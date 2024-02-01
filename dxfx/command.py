import argparse
import logging
from pathlib import Path

from dxfx.apk import APK
from dxfx.bin import BinHelper
from dxfx.dgc import CodePool
from dxfx.dex import DexPool, MethodCipher


log = logging.getLogger("dxfx::command")


def fix_apk(options: argparse.Namespace):
    apk = APK(options.apk)

    if options.output is not None:
        output = options.output
    else:
        output = f"{Path(options.apk).stem}_fixed.apk"

    if apk.package != "com.dji.industry.pilot":
        raise RuntimeError("DJI Pilot app not recognized. Aborting.")

    log.info(f"Detected: DJI Pilot {apk.version}")

    apk.open()

    dex_pool = DexPool(apk)
    bin_help = BinHelper(apk)
    cde_pool = CodePool(apk, bin_help.code_pool_key)
    cipher = MethodCipher(bin_help.s_table)

    for dex in dex_pool.dexfiles:
        apk.write_file(dex.name, dex.fix(cde_pool, cipher))

    apk.save(output)
    apk.close()
