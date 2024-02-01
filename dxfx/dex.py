import lief
import logging
import zlib
from Crypto.Cipher import ARC4
from enum import IntEnum
from functools import lru_cache

from dxfx.apk import APK
from dxfx.dgc import CodePool


log = logging.getLogger("dxfx::dex")


class PseudoOpCode(IntEnum):
    """Dalvik pseudo opcodes"""

    PACKED_SWITCH = 0x0100
    SPARSE_SWITCH = 0x0200
    FILL_ARRAY = 0x0300

    @classmethod
    def has(cls, value: int) -> bool:
        return value in cls._value2member_map_


class MethodCipher:
    """
    Cipher used to decrypt code from the code pool
    """

    # fmt: off
    _INSN_SIZE = [  # INSN_SIZE[OPCODE] = SIZE_IN_WORDS
        1, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 2, 3, 2, 2, 3, 5, 2, 2, 3, 2, 1, 1, 2,
        2, 1, 2, 2, 3, 3, 3, 1, 1, 2, 3, 3, 3, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0,
        0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3,
        3, 3, 3, 0, 3, 3, 3, 3, 3, 0, 0, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]
    """Dalvik instruction sizes (in words) indexed by opcode value"""

    def __init__(self, s_table: bytes):
        self._s_table = s_table

    @staticmethod
    def _fill_array_sz(data: bytes, offset: int) -> int:
        """
        Gets the fill-array-payload struct size

        Parameters
        ----------
        data: bytes
            The method code
        offset: int
            The offset of the opcode

        Returns
        -------
        int
            The size of the fill-array-payload struct (in bytes)
        """

        element_with = int.from_bytes(data[offset + 2 : offset + 4], "little")
        size = int.from_bytes(data[offset + 4 : offset + 8], "little")

        return element_with * size + 8

    @staticmethod
    def _packed_switch_sz(data: bytes, offset: int) -> int:
        """
        Gets the packed-switch-payload struct size

        Parameters
        ----------
        data: bytes
            The method code
        offset: int
            The offset of the opcode

        Returns
        -------
        int
            The size of the packed-switch-payload struct (in bytes)
        """

        size = int.from_bytes(data[offset + 2 : offset + 4], "little")

        return 4 * size + 8

    @staticmethod
    def _sparse_switch_sz(data: bytes, offset: int) -> int:
        """
        Gets the sparse-switch-payload struct size

        Parameters
        ----------
        data: bytes
            The method code
        offset: int
            The offset of the opcode

        Returns
        -------
        int
            The size of the sparse-switch-payload struct (in bytes)
        """

        size = int.from_bytes(data[offset + 2 : offset + 4], "little")

        return 8 * size + 4

    def decrypt(self, method_id: int, method_code: bytes) -> bytes:
        """
        Decrypt method code fetched from the code pool

        Parameters
        ----------
        method_id: int
            The ID used to bind method code from the code pool and method from a DEX
            file. The `debug_info_off` field of DEX `code_item` is used to store this
            ID. The least significant byte of the method ID is used as a XOR key to
            decrypt dalvik opcodes
        method_code: bytes
            The method encrypted code (fetched from the code pool)

        Returns
        -------
        bytes
            The decrypted code

        Raises
        ------
        RuntimeError
            On decryption error
        """

        key = method_id & 0xFF
        code = bytearray(method_code)
        size = len(method_code)
        cursor = 0

        while cursor < size:
            s_byte = self._s_table[code[cursor] ^ key]
            insn_size = self._INSN_SIZE[s_byte] * 2

            if insn_size == 0:
                raise RuntimeError(
                    f"Unknown instruction found in method 0x{method_id:08x}"
                )

            code[cursor] = s_byte

            # Handles special opcodes
            if s_byte == 0:
                dw_opcode = int.from_bytes(code[cursor : cursor + 2], "little")

                if PseudoOpCode.has(dw_opcode):
                    if dw_opcode == PseudoOpCode.PACKED_SWITCH:
                        insn_size = self._packed_switch_sz(method_code, cursor)
                    elif dw_opcode == PseudoOpCode.SPARSE_SWITCH:
                        insn_size = self._sparse_switch_sz(method_code, cursor)
                    else:  # 0x0300: fill-array-payload
                        insn_size = self._fill_array_sz(method_code, cursor)

            cursor += insn_size

        return bytes(code)


class Dex:
    """Wraps DEX file bytes extracted from a DexPool"""

    def __init__(self, name: str, data: bytes):
        self._data = data
        self._name = name

    @staticmethod
    def _fix_checksum(data: bytes) -> bytes:
        chksum = zlib.adler32(data[12:]).to_bytes(4, "little")
        return data[:8] + chksum + data[12:]

    @property
    def name(self) -> str:
        return self._name

    def fix(self, code_pool: CodePool, cipher: MethodCipher) -> bytes:
        """
        Repairs the DEX file

        Parameters
        ----------
        code_pool: CodePool
            The code pool which contains missing method bodies
        cipher: MethodCipher
            A cipher used to decrypt encrypted code from the code pool

        Returns
        -------
        bytes
            The fixed DEX bytes
        """

        log.info(f"Fixing {self}")

        parser = lief.DEX.parse(list(self._data))
        fixed = bytearray(self._data)

        for method in filter(lambda m: m.code_offset > 0, parser.methods):
            dx_mth_of = method.code_offset  # obfuscated method code offset
            dx_mth_dbg_of = dx_mth_of - 8  # obfuscated method dbg info offset
            mth_id = int.from_bytes(  # method id (debug info)
                self._data[dx_mth_dbg_of : dx_mth_dbg_of + 4], "little"
            )

            enc_code = code_pool.get_method_code(mth_id, len(method.bytecode))

            if enc_code is None:
                continue

            try:
                dec_code = cipher.decrypt(mth_id, enc_code)
            except RuntimeError as err:
                log.error(str(err))
                continue

            # Overwrite debug info to prevent decompilation errors
            fixed[dx_mth_dbg_of : dx_mth_dbg_of + 4] = 0, 0, 0, 0
            fixed[dx_mth_of : dx_mth_of + len(dec_code)] = dec_code

        return self._fix_checksum(fixed)

    def __str__(self) -> str:
        return self._name


class DexPool:
    """
    DexPool is used to decrypt and extract DEX files from the `classes.dex` file

    `classes.dex` basically contains:
    - A legitimate DEX used to bootstrap the packer
    - A set of DEX files which first 128KB chunk is RC4 encrypted
    """

    _FILEPATH_IN_APK = "./classes.dex"
    """The file name of the DEX pool in the APK"""

    _HC_PRE_DEX_KEY = bytes.fromhex("66976ce86d4638b0095aa5d70fcb9aa0")
    """Hardcoded const used to generate DEX_KEY"""

    _DEX_SIG = bytes.fromhex("cdf236dd")
    """DEX encrypted chunk signature"""

    _CHUNK_SIZE = 0x20000  # 128K
    """DEX encrypted chunk size"""

    def __init__(self, apk: APK):
        self._apk = apk
        self._data = apk.read_file(self._FILEPATH_IN_APK)

    @property
    def dexfiles(self):
        """Provides a generator over decrypted DEX files contained in the pool"""

        offset = self._data.find(self._DEX_SIG)
        dexnum = 2

        while offset != -1:
            chunk = ARC4.new(self.key).decrypt(
                self._data[offset : offset + self._CHUNK_SIZE]
            )
            size = int.from_bytes(chunk[0x20:0x24], "little")  # file_size header field
            name = f"classes{dexnum}.dex"

            log.info(f"Extracting {name} from DexPool@0x{offset:08x}")

            yield Dex(
                name=name,
                data=chunk + self._data[offset + self._CHUNK_SIZE : offset + size],
            )

            offset = self._data.find(self._DEX_SIG, offset + 1)
            dexnum += 1

    @property
    @lru_cache(maxsize=1)
    def key(self):
        """
        The RC4 key to decrypt first chunk of DEX files

        This key is obtained from a XOR between:
        - `_HC_PRE_DEX_KEY`: 16 bytes value generated in the `libDexHelper.so` code
        - the app package string
        """

        return bytes(
            ord(self._apk.package[i]) ^ self._HC_PRE_DEX_KEY[i]
            for i in range(len(self._HC_PRE_DEX_KEY))
        )  # 05f801c6092c519e6034c1a27cbfe8d9
