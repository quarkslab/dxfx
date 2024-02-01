import logging
import pyaxmlparser
import shutil
import tempfile
from functools import wraps
from pathlib import Path
from typing import Union


log = logging.getLogger("dxfx::apk")


def _closed_(method):
    @wraps(method)
    def _impl(self, *method_args, **method_kwargs):
        if self._tmpdir is not None:
            raise RuntimeError("APK is already opened")
        return method(self, *method_args, **method_kwargs)

    return _impl


def _opened_(method):
    @wraps(method)
    def _impl(self, *method_args, **method_kwargs):
        if self._tmpdir is None:
            raise RuntimeError("APK is not opened")
        return method(self, *method_args, **method_kwargs)

    return _impl


class APK:
    """
    Helper to pack/unpack an APK archive
    """

    def __init__(self, path: Union[Path, str]):
        self._path = Path(path)
        self._axml = pyaxmlparser.APK(self._path)
        self._tmpdir = None

    @property
    def package(self) -> str:
        return self._axml.package

    @property
    def version(self) -> int:
        return self._axml.version_name

    @_closed_
    def open(self):
        log.info(f"Unpacking {self._path.name} ...")

        self._tmpdir = tempfile.TemporaryDirectory()
        shutil.unpack_archive(self._path.as_posix(), self._tmpdir.name, "zip")

    @_opened_
    def close(self):
        self._tmpdir.cleanup()
        self._tmpdir = None

    @_opened_
    def read_file(self, path: str) -> bytes:
        with open(Path(self._tmpdir.name) / path, "rb") as fd:
            return fd.read()

    @_opened_
    def write_file(self, path: str, data: bytes):
        with open(Path(self._tmpdir.name) / path, "wb") as fd:
            fd.write(data)

    @_opened_
    def save(self, path: Union[Path, str]):
        log.info(f"Saving APK to {path} ...")

        out_path = Path(
            shutil.make_archive(
                Path(path).as_posix(), "zip", root_dir=self._tmpdir.name
            )
        )

        # remove the zip extension
        out_path.rename(out_path.parent / out_path.stem)
