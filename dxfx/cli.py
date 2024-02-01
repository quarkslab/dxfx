import argparse
import logging

from dxfx import __version__
from dxfx.command import fix_apk

DESCRIPTION = f"DxFx - DJI Pilot bytecode unpacker v. {__version__}"
log = logging.getLogger("dxfx::cli")


def setup_logger(args: argparse.Namespace):
    if args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(level=level, format="[%(levelname)s] - %(name)s : %(message)s")


def get_options() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="show debug level messages"
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        metavar="fixed_apk",
        help="the path of the output APK",
    )
    parser.add_argument("apk", type=str, help="the APK to fix")

    return parser.parse_args()


def main():
    args = get_options()
    setup_logger(args)

    log.info(DESCRIPTION)
    fix_apk(args)
    log.info("Done.")


if __name__ == "__main__":
    main()
