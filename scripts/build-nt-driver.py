#!/usr/bin/env python3
"""
Nexus OS — Independent Windows NT Kernel Driver Builder
Compiles tests/fixtures/nt_driver/*.c into valid PE32+ .sys native drivers
using MSVC cl.exe and link.exe.
"""

import os
import subprocess
import sys
from pathlib import Path

def find_msvc_tools():
    base_vc = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC")
    if not base_vc.exists():
        for vs_edition in ["BuildTools", "Community", "Professional", "Enterprise"]:
            candidate = Path(rf"C:\Program Files\Microsoft Visual Studio\2022\{vs_edition}\VC\Tools\MSVC")
            if candidate.exists():
                base_vc = candidate
                break

    if not base_vc.exists():
        raise RuntimeError("MSVC tools directory not found")

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

def compile_driver(cl, link, lib_path, driver_dir, source_c, out_sys):
    stem = source_c.stem
    out_obj = driver_dir / f"{stem}.obj"

    print(f"[*] Compiling {source_c.name} with cl.exe /kernel...")
    cmd_cl = [
        str(cl),
        "/NOLOGO",
        "/c",
        "/GS-",
        "/kernel",
        "/O2",
        "/W4",
        "/Fo:" + str(out_obj),
        str(source_c),
    ]
    res_cl = subprocess.run(cmd_cl, cwd=driver_dir, capture_output=True, text=True)
    if res_cl.returncode != 0:
        print(f"[-] cl.exe failed for {source_c.name}:\n{res_cl.stderr}\n{res_cl.stdout}", file=sys.stderr)
        return False

    print(f"[*] Linking {out_sys.name} with link.exe /SUBSYSTEM:NATIVE /DRIVER...")
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
        str(lib_path),
    ]
    res_link = subprocess.run(cmd_link, cwd=driver_dir, capture_output=True, text=True)
    if res_link.returncode != 0:
        print(f"[-] link.exe failed for {out_sys.name}:\n{res_link.stderr}\n{res_link.stdout}", file=sys.stderr)
        return False

    if not out_sys.exists() or out_sys.stat().st_size == 0:
        print(f"[-] Driver binary {out_sys.name} not generated or empty!", file=sys.stderr)
        return False

    print(f"[+] Successfully built: {out_sys} ({out_sys.stat().st_size} bytes)")
    return True

def build_drivers():
    repo_root = Path(__file__).resolve().parent.parent
    driver_dir = repo_root / "tests" / "fixtures" / "nt_driver"
    def_source = driver_dir / "ntoskrnl.def"
    out_lib = driver_dir / "ntoskrnl.lib"

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

    # 2. Build nexus_driver.c
    c_nexus = driver_dir / "nexus_driver.c"
    sys_nexus = driver_dir / "nexus_driver.sys"
    if not compile_driver(cl, link, out_lib, driver_dir, c_nexus, sys_nexus):
        return 1

    # 3. Build standard_wdm.c
    c_wdm = driver_dir / "standard_wdm.c"
    sys_wdm = driver_dir / "standard_wdm.sys"
    if not compile_driver(cl, link, out_lib, driver_dir, c_wdm, sys_wdm):
        return 1

    # Clean intermediate files
    for tmp in driver_dir.glob("*.obj"):
        tmp.unlink(missing_ok=True)
    out_lib.unlink(missing_ok=True)
    (driver_dir / "ntoskrnl.exp").unlink(missing_ok=True)

    print("[+] All NT drivers built and intermediate artifacts cleaned successfully!")
    return 0

if __name__ == "__main__":
    sys.exit(build_drivers())
