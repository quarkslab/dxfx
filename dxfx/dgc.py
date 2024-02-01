import logging
from Crypto.Cipher import ARC4
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, Optional

from dxfx.apk import APK


log = logging.getLogger("dxfx::dgc")


@dataclass
class _MethodInfo:
    """Contains method various information from the code pool"""

    id: int
    offset: int
    size: int

    @property
    def code_offset(self) -> int:
        return self.offset + 16


class CodePool:
    """
    CodePool is used to extract missing method code from the `classes.dgc` file
    """

    _FILEPATH_IN_APK = "./assets/classes.dgc"

    _CHUNK_SIZE = 0x20000  # 128K
    """Size of the encrypted chunk of `classes.dgc`"""

    def __init__(self, apk: APK, key: bytes):
        self._apk = apk
        self._data = bytearray(apk.read_file(self._FILEPATH_IN_APK))
        self._key = key
        self._decrypt_chunk()

    def _decrypt_chunk(self):
        """Decrypt the first 128KB chunk of the `classes.dgc` file"""

        chunk = ARC4.new(self._key).decrypt(self._data[: self._CHUNK_SIZE])
        self._data[: self._CHUNK_SIZE] = chunk

    @property
    @lru_cache(maxsize=1)
    def _base_offset(self) -> int:
        """The code pool offset in `classes.dgc`"""

        return int.from_bytes(self._data[16:20], "big")

    @property
    @lru_cache(maxsize=1)
    def _methods(self) -> Dict[int, _MethodInfo]:
        """
        Returns a dictionary which contains methods information from the `classes.dgc`
        methods index. Indexed by method ID
        """

        result = dict()
        cursor = 24

        while cursor < self._base_offset:
            m_offset = int.from_bytes(self._data[cursor : cursor + 4], "big")
            m_size = int.from_bytes(self._data[cursor + 4 : cursor + 8], "big")
            m_id = int.from_bytes(self._data[cursor + 12 : cursor + 16], "big")

            result[m_id] = _MethodInfo(m_id, m_offset, m_size)

            cursor += 20

        return result

    def get_method_code(self, method_id: int, method_sz: int) -> Optional[bytes]:
        """
        Gets the code of a method from the code pool

        Parameters
        ----------
        method_id: int
            The method ID (packer ID, contained in the `debug_info_off` field)
        method_sz: int
            The method code size (in bytes)

        Returns
        -------
        Optional[bytes]
            The method code or None if not found
        """

        info = self._methods.get(method_id)

        if info is None:
            return None

        code_offset = info.code_offset + self._base_offset

        return self._data[code_offset : code_offset + method_sz]
