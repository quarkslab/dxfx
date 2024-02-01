import hashlib
from functools import lru_cache

from dxfx.apk import APK


def fibonacci(n: int):
    """Fibonacci generator"""

    a = 0
    b = 1
    for _ in range(n):
        yield a
        a, b = b, a + b


class BinHelper:
    """
    `libDexHelper.so` parser
    """

    _FILEPATH_IN_APK = "./lib/arm64-v8a/libDexHelper.so"
    _S_TABLE_SIG = bytes.fromhex("dfc9df83c2c9ced9c0cdf3cddcdc82c8")
    _S_TABLE_SIG_OFFSET = 26
    _S_TABLE_SIZE = 256
    _S_TABLE_KEY = 0xAC
    _MTH_FILEKEY_SIG = bytes.fromhex("6d746866696c656b657905fefa2f0ab9")
    _MTH_FILEKEY_SIG_OFFSET = 16
    _MTH_FILEKEY_SIZE = 0x1000

    def __init__(self, apk: APK):
        self._apk = apk
        self._data = apk.read_file(self._FILEPATH_IN_APK)
        s_table_offset = self._data.find(self._S_TABLE_SIG)
        cde_pl_key_offset = self._data.find(self._MTH_FILEKEY_SIG)

        if s_table_offset == -1 or cde_pl_key_offset == -1:
            raise RuntimeError("Unable to parse libDexHelper.so")

        self._s_table_offset = s_table_offset + self._S_TABLE_SIG_OFFSET
        self._cde_pl_key_offset = cde_pl_key_offset + self._MTH_FILEKEY_SIG_OFFSET

    @property
    @lru_cache(maxsize=1)
    def s_table(self) -> bytes:
        """The substitution table used to decrypt opcodes from code pool"""

        return bytes(
            b ^ self._S_TABLE_KEY
            for b in self._data[
                self._s_table_offset : self._s_table_offset + self._S_TABLE_SIZE
            ]
        )

    @property
    @lru_cache(maxsize=1)
    def code_pool_key(self) -> bytes:
        """
        The key used to decrypt the `classes.dgc` (code pool) first chunk

        Generated from a fibonacci based XOR walk between:
        - The MD5 of a chunk stored in `libDexHelper.so`
        - The chunk bytes
        """

        chunk = self._data[
            self._cde_pl_key_offset : self._cde_pl_key_offset + self._MTH_FILEKEY_SIZE
        ]
        md5 = hashlib.md5(chunk).digest()
        return bytes(md5[i] ^ chunk[f] for i, f in enumerate(fibonacci(16)))
