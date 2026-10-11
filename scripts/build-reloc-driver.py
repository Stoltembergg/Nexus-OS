#!/usr/bin/env python3
"""Nexus OS — compila a fixture de relocações (tests/fixtures/nt_driver/reloc).

Usa só LLVM (clang + lld-link + llvm-dlltool), disponível em Linux e Windows,
para gerar um driver PE32+ IMAGE_SUBSYSTEM_NATIVE com uma tabela de ponteiros
absolutos (entradas IMAGE_REL_BASED_DIR64 em .reloc). O .sys gerado é
versionado; `--check` recompila num diretório temporário e falha se o
resultado não for byte a byte idêntico ao versionado (verificação de
proveniência, reprodutível porque /Brepro zera o timestamp).
"""

import argparse
import filecmp
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "nt_driver" / "reloc"
SOURCE = FIXTURE_DIR / "reloc_driver.c"
OUTPUT = FIXTURE_DIR / "reloc_driver.sys"
DEF = ROOT / "tests" / "fixtures" / "nt_driver" / "ntoskrnl.def"


def tool(*names: str) -> str:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    raise SystemExit(f"ferramenta ausente: {' ou '.join(names)}")


def run(cmd: list[str]) -> None:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(f"falhou: {' '.join(cmd)}\n{result.stdout}{result.stderr}")
        raise SystemExit(1)


def build(out_dir: Path) -> Path:
    clang = tool("clang", "clang-18", "clang-17")
    lld_link = tool("lld-link", "lld-link-18", "lld-link-17")
    dlltool = tool("llvm-dlltool", "llvm-dlltool-18", "llvm-dlltool-17")
    obj = out_dir / "reloc_driver.obj"
    lib = out_dir / "ntoskrnl.lib"
    sys_out = out_dir / "reloc_driver.sys"
    run([dlltool, "-m", "i386:x86-64", "-d", str(DEF), "-l", str(lib)])
    run([
        clang, "--target=x86_64-pc-windows-msvc", "-c", "-O2", "-ffreestanding",
        "-fno-stack-protector", "-mno-red-zone", "-Wall", "-Werror",
        "-o", str(obj), str(SOURCE),
    ])
    run([
        lld_link, "/NOLOGO", "/DRIVER", "/SUBSYSTEM:NATIVE", "/ENTRY:DriverEntry",
        "/NODEFAULTLIB", "/DYNAMICBASE", "/BASE:0x140000000", "/Brepro",
        f"/OUT:{sys_out}", str(obj), str(lib),
    ])
    return sys_out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="recompila e compara com o .sys versionado")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        built = build(Path(tmp))
        if args.check:
            if not filecmp.cmp(built, OUTPUT, shallow=False):
                print(f"[-] {OUTPUT.relative_to(ROOT)} difere do binário recompilado")
                return 1
            print(f"[+] {OUTPUT.relative_to(ROOT)} confere com o fonte")
            return 0
        shutil.copyfile(built, OUTPUT)
        print(f"[+] gerado {OUTPUT.relative_to(ROOT)} ({OUTPUT.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
