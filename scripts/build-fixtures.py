"""Compile genuine PE32+/ELF64 freestanding fixtures, using Clang or Zig's Clang."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def linker_command(nt):
    available = shutil.which('lld-link' if nt else 'ld.lld')
    if available:
        return [available]
    sysroot = Path(subprocess.check_output(['rustc', '--print', 'sysroot'], text=True).strip())
    host = subprocess.check_output(['rustc', '-vV'], text=True).split('host: ')[1].splitlines()[0]
    binary = 'rust-lld.exe' if os.name == 'nt' else 'rust-lld'
    return [str(sysroot / 'lib' / 'rustlib' / host / 'bin' / binary), '-flavor', 'link' if nt else 'gnu']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--zig', help='Optional Zig executable (0.13.0 tested)')
    args = parser.parse_args()
    compiler = [str(Path(args.zig).resolve()), 'cc'] if args.zig else [shutil.which('clang') or 'clang']
    output = ROOT / 'build' / 'fixtures'
    output.mkdir(parents=True, exist_ok=True)
    sources = ROOT / 'tests' / 'fixtures'
    manifest = {'compiler': subprocess.check_output(compiler + ['--version'], text=True).splitlines()[0],
                'compiler_command': compiler, 'linker_commands': {'pe': linker_command(True), 'elf': linker_command(False)},
                'sources': {name: hashlib.sha256((sources / name).read_bytes()).hexdigest()
                            for name in ['entry.S', 'probe.c', 'elf.ld']}, 'files': {}}
    for nt in (False, True):
        target = 'x86_64-windows-msvc' if nt else 'x86_64-linux-musl'
        flags = ['-target', target] if args.zig else ['--target=' + ('x86_64-windows-msvc' if nt else 'x86_64-linux-gnu')]
        for mode in range(16):
            name = ('pe' if nt else 'elf') + '-' + str(mode) + ('.exe' if nt else '.elf')
            cmd = compiler + flags + ['-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-mno-red-zone', '-fno-asynchronous-unwind-tables', '-O1', '-nostdlib', '-DMODE=' + str(mode)]
            if nt:
                objs = []
                for source in ['entry.S', 'probe.c']:
                    obj = output / (name + '-' + source + '.obj')
                    subprocess.run([x for x in cmd if x != '-nostdlib'] + ['-DNT', '-c', str(sources / source), '-o', str(obj)], check=True)
                    objs.append(str(obj))
                link_cmd = linker_command(True)
                subprocess.run(link_cmd + ['/nodefaultlib', '/entry:entry', '/subsystem:console', '/base:0x140000000', '/out:' + str(output / name)] + objs, check=True)
            else:
                objs = []
                for source in ['entry.S', 'probe.c']:
                    obj = output / (name + '-' + source + '.o')
                    subprocess.run([x for x in cmd if x != '-nostdlib'] + ['-fno-pie', '-mcmodel=large', '-c', str(sources / source), '-o', str(obj)], check=True)
                    objs.append(str(obj))
                subprocess.run(linker_command(False) + ['-static', '-T', str(sources / 'elf.ld'), '-z', 'noexecstack', '-o', str(output / name)] + objs, check=True)
            data = (output / name).read_bytes()
            assert data.startswith(b'MZ' if nt else b'\x7fELF')
            manifest['files'][name] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Compiled and hashed {len(manifest["files"])} external images into {output}')


if __name__ == '__main__':
    main()
