#!/usr/bin/env python3
"""Retired (PR-6).

nexus_driver.c and standard_wdm.c are now written against the official WDK headers and
linked against the official ntoskrnl.lib, so the hand-written ntoskrnl.def import library
this script generated no longer applies to them. Rebuild / verify the committed .sys with:

    python3 scripts/wdk-abi.py --cc clang-cl --wdk-root <WDK pkg> --sdk-root <SDK pkg> --update-fixtures
    python3 scripts/wdk-abi.py --cc clang-cl --wdk-root <WDK pkg> --sdk-root <SDK pkg> --check-fixtures --enforce

(ntoskrnl.def is still used by scripts/build-reloc-driver.py for reloc_driver.sys.)
"""
import sys

if __name__ == '__main__':
    print(__doc__, file=sys.stderr)
    sys.exit(2)
