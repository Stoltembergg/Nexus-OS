#!/usr/bin/env python3
"""
Nexus OS — Independent Windows NT Kernel Driver Builder
Compiles tests/fixtures/nt_driver/nexus_driver.c into a valid PE32+ .sys native driver
using MSVC cl.exe and link.exe.
"""

import os
import subprocess
import sys
from pathlib import Path

def find_msvc_tools():
    base_vc = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC")
    if not base_vc.exists():
        # Try finding standard Visual Studio Enterprise/Professional/Community
        for vs_edition in ["BuildTools", "Community", "Professional", "Enterprise"]:
            candidate = Path(rf"C:\Program Files\Microsoft Visual Studio\2022\{vs_edition}\VC\Tools\MSVC")
            if candidate.exists():
                base_vc = candidate
                break

    if not base_vc.exists():
        raise RuntimeError("MSVC tools directory not found")

    # Pick the latest version directory
    versions = sorted([d for d in base_vc.iterdir() if d.is_dir()])
    if not versions:
        raise RuntimeError("No MSVC toolchain version found")
    
    latest_vc = versions[-1]
    bin_x64 = latest_vc / "bin" / "HostX64" / "x64"
    cl = bin_x64 / "cl.exe"
    link = bin_x64 / "link.exe"
    lib = bin_x64 / "lib.exe"

    if not cl.exists() or not link.exists() or not lib.exists():
        raise RuntimeError(f"MSVC toolchain executables missing in {bin_x64}")

    return cl, link, lib

def build_driver():
    repo_root = Path(__file__).resolve().parent.parent
    driver_dir = repo_root / "tests" / "fixtures" / "nt_driver"
    c_source = driver_dir / "nexus_driver.c"
    def_source = driver_dir / "ntoskrnl.def"
    out_sys = driver_dir / "nexus_driver.sys"
    out_obj = driver_dir / "nexus_driver.obj"
    out_lib = driver_dir / "ntoskrnl.lib"

    print(f"[*] Building independent NT driver: {c_source}")

    cl, link, lib = find_msvc_tools()
    print(f"[+] Using MSVC toolchain: {cl.parent}")

    # 1. Generate ntoskrnl.lib from ntoskrnl.def
    print("[*] Generating ntoskrnl.lib from ntoskrnl.def...")
    cmd_lib = [
        str(lib),
        "/NOLOGO",
        f"/DEF:{def_source}",
        "/MACHINE:X64",
        f"/OUT:{out_lib}",
    ]
    res_lib = subprocess.run(cmd_lib, cwd=driver_dir, capture_output=True, text=True)
    if res_lib.returncode != 0:
        print(f"[-] lib.exe failed:\n{res_lib.stderr}\n{res_lib.stdout}", file=sys.stderr)
        return 1

    # 2. Compile nexus_driver.c to object
    print("[*] Compiling nexus_driver.c with cl.exe /kernel...")
    cmd_cl = [
        str(cl),
        "/NOLOGO",
        "/c",
        "/GS-",
        "/kernel",
        "/O2",
        "/W4",
        "/Fo:" + str(out_obj),
        str(c_source),
    ]
    res_cl = subprocess.run(cmd_cl, cwd=driver_dir, capture_output=True, text=True)
    if res_cl.returncode != 0:
        print(f"[-] cl.exe failed:\n{res_cl.stderr}\n{res_cl.stdout}", file=sys.stderr)
        return 1

    # 3. Link nexus_driver.sys
    print("[*] Linking nexus_driver.sys with link.exe /SUBSYSTEM:NATIVE /DRIVER...")
    cmd_link = [
        str(link),
        "/NOLOGO",
        "/SUBSYSTEM:NATIVE",
        "/DRIVER",
        "/ENTRY:DriverEntry",
        "/NODEFAULTLIB",
        "/OPT:REF,NOICF",
        f"/OUT:{out_sys}",
        str(out_obj),
        str(out_lib),
    ]
    res_link = subprocess.run(cmd_link, cwd=driver_dir, capture_output=True, text=True)
    if res_link.returncode != 0:
        print(f"[-] link.exe failed:\n{res_link.stderr}\n{res_link.stdout}", file=sys.stderr)
        return 1

    if not out_sys.exists() or out_sys.stat().st_size == 0:
        print("[-] Driver binary not generated or empty!", file=sys.stderr)
        return 1

    print(f"[+] Successfully built native driver: {out_sys} ({out_sys.stat().st_size} bytes)")
    return 0

if __name__ == "__main__":
    sys.exit(build_driver())
