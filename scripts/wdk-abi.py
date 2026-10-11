#!/usr/bin/env python3
"""PR-5: compare Nexus NT structs with the official WDK and rebuild the test drivers.

What it does (all outputs go to --out, default build/wdk-abi/):

1. ABI table. The struct/field list comes from `cargo run -p nexus-types --example
   abi_layout` (single source of truth). For every entry this script generates a C file
   that includes the official WDK <ntddk.h> and stores `sizeof(T)` / `FIELD_OFFSET(T, f)`
   in a dedicated COFF section, compiles it (no link, nothing runs) and reads the values
   back from the object file. Result: wdk-abi.json and abi-table.md (WDK vs Nexus).
2. Driver rebuild. Compiles tests/fixtures/nt_driver/{nexus_driver,standard_wdm}.c and
   tests/fixtures/nt_driver/wdk/wdk_min.c and links them against the WDK's official
   ntoskrnl.lib (not the hand-written ntoskrnl.def). Link failures are recorded with the
   unresolved imports.
3. Nexus load probe. Every driver that linked is loaded (map + relocate + resolve
   imports, never executed) by `cargo run -p nexus-loader --example probe_load`.

Exit status:
- infrastructure problems (WDK headers/lib not found, ABI probe does not compile, table
  empty or inconsistent, cargo examples failing) always fail (exit 1);
- ABI mismatches, link failures and load failures are REPORTED but do not fail unless
  --enforce is given. PR-5 runs report-only, because those mismatches are the known
  audit finding C4/A4; PR-6 (struct alignment) switches CI to --enforce.

Compilers: `--cc cl` (MSVC, used in CI on windows-latest) or `--cc clang-cl` (+ lld-link),
which lets the ABI table be reproduced on Linux with the same WDK NuGet packages.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / 'tests' / 'fixtures' / 'nt_driver'
SECTION = b'.nxabi'
DRIVERS = [
    ('nexus_driver', FIXTURES / 'nexus_driver.c', False),
    ('standard_wdm', FIXTURES / 'standard_wdm.c', False),
    ('wdk_min', FIXTURES / 'wdk' / 'wdk_min.c', True),  # uses <ntddk.h>
]


class Infra(RuntimeError):
    """A failure of the tooling itself (always fatal, even in report-only mode)."""


def find_one(root: Path, pattern: str) -> Path:
    hits = sorted(root.rglob(pattern))
    if not hits:
        raise Infra(f'{pattern} not found under {root}')
    return hits[-1]


def wdk_paths(wdk_root: Path, sdk_root: Path | None):
    ntddk = find_one(wdk_root, 'km/ntddk.h')
    km = ntddk.parent
    inc = km.parent
    lib = find_one(wdk_root, 'km/x64/ntoskrnl.lib')
    includes = [km, km / 'crt', inc / 'shared']
    if sdk_root is not None:
        includes.append(find_one(sdk_root, 'shared/ntdef.h').parent)
    missing = [p for p in includes if not p.is_dir()]
    if missing:
        raise Infra(f'WDK include directories missing: {missing}')
    return includes, lib


def run(cmd, **kw):
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)


NOT_FOUND = re.compile(r"fatal error: '([^']+)' file not found")


def compile_with_case_shim(cc, includes, source: Path, obj: Path, uses_wdk_headers: bool, cwd: Path):
    """Compile; on a case-sensitive host (Linux + clang-cl), resolve header names that the
    WDK/SDK include with a different case by symlinking them into a shim directory.
    On Windows (MSVC, the CI path) the first attempt is the only one."""
    shim = cwd / 'case-shim'
    extra = [shim] if shim.is_dir() else []
    for _ in range(64):
        res = run(compiler_cmd(cc, includes + extra, source, obj, uses_wdk_headers), cwd=cwd)
        missing = NOT_FOUND.search(res.stdout + res.stderr)
        if res.returncode == 0 or os.name == 'nt' or not missing or not uses_wdk_headers:
            return res
        wanted = missing.group(1)
        target = None
        for inc in includes:
            for candidate in inc.iterdir():
                if candidate.name.lower() == Path(wanted).name.lower():
                    target = candidate
                    break
            if target:
                break
        if target is None:
            return res
        shim.mkdir(exist_ok=True)
        link = shim / wanted
        link.parent.mkdir(parents=True, exist_ok=True)
        if not link.exists():
            link.symlink_to(target)
        extra = [shim]
    return res


def compiler_cmd(cc: str, includes, source: Path, obj: Path, uses_wdk_headers: bool):
    if cc == 'cl':
        cmd = ['cl', '/nologo', '/c', '/kernel', '/GS-', '/O2', '/W4', '/Zl']
    elif cc == 'clang-cl':
        cmd = [shutil.which('clang-cl') or shutil.which('clang-cl-19') or 'clang-cl',
               '/nologo', '/c', '/kernel', '/GS-', '/O2', '/Zl', '/X',
               '--target=x86_64-pc-windows-msvc', '-Wno-everything']
    else:
        raise Infra(f'unknown compiler {cc}')
    cmd += ['/D_AMD64_', '/DAMD64', '/D_WIN64', '/D_KERNEL_MODE']
    if uses_wdk_headers:
        cmd += [f'/I{p}' for p in includes]
    # clang-cl on Linux would parse an absolute path such as /workspace/x.c as an option.
    return cmd + [f'/Fo{obj}'] + (['--'] if cc == 'clang-cl' else []) + [str(source)]


def linker_cmd(cc: str, obj: Path, lib: Path, out: Path):
    linker = 'link' if cc == 'cl' else (shutil.which('lld-link') or 'lld-link')
    return [linker, '/nologo', '/DRIVER', '/SUBSYSTEM:NATIVE', '/ENTRY:DriverEntry',
            '/NODEFAULTLIB', '/OPT:REF,NOICF', '/MACHINE:X64', f'/OUT:{out}', str(obj), str(lib)]


def coff_section(obj_bytes: bytes, name: bytes) -> bytes:
    """Raw data of the section `name` in a COFF object (x64)."""
    machine, nsec = struct.unpack_from('<HH', obj_bytes, 0)
    if machine != 0x8664:
        raise Infra(f'unexpected COFF machine {machine:#x}')
    opt_size = struct.unpack_from('<H', obj_bytes, 16)[0]
    base = 20 + opt_size
    for i in range(nsec):
        off = base + i * 40
        sec_name = obj_bytes[off:off + 8].rstrip(b'\0')
        size, ptr = struct.unpack_from('<II', obj_bytes, off + 16)
        if sec_name == name:
            return obj_bytes[ptr:ptr + size]
    raise Infra(f'section {name!r} not found in ABI probe object')


def wdk_expr(entry):
    ty, field = entry['type'], entry['field']
    return f'sizeof({ty})' if field == 'sizeof' else f'FIELD_OFFSET({ty}, {field})'


def build_abi_table(cc, includes, layout, work: Path):
    probe = work / 'abi_probe.c'
    lines = [
        '/* Generated by scripts/wdk-abi.py. Compiled only (never linked or run). */',
        '#include <ntddk.h>',
        '#pragma section(".nxabi", read)',
        '__declspec(allocate(".nxabi")) const unsigned __int64 nexus_wdk_abi_table[] = {',
    ]
    lines += [f'    (unsigned __int64)({wdk_expr(e)}), /* {e["type"]}.{e["field"]} */' for e in layout]
    lines += ['};', '']
    probe.write_text('\n'.join(lines))
    obj = work / 'abi_probe.obj'
    res = compile_with_case_shim(cc, includes, probe, obj, True, work)
    if res.returncode != 0 or not obj.exists():
        raise Infra(f'ABI probe did not compile with the WDK headers:\n{res.stdout}\n{res.stderr}')
    data = coff_section(obj.read_bytes(), SECTION)
    if len(data) < 8 * len(layout):
        raise Infra(f'ABI section has {len(data)} bytes, expected {8 * len(layout)}')
    values = struct.unpack_from(f'<{len(layout)}Q', data, 0)
    rows = []
    for entry, wdk in zip(layout, values):
        rows.append({'type': entry['type'], 'field': entry['field'], 'wdk': wdk,
                     'nexus': entry['value'], 'match': wdk == entry['value']})
    return rows


# MSVC: "LNK2019: unresolved external symbol __imp_KeRaiseIrql referenced in ..."
# lld:  "undefined symbol: __declspec(dllimport) KeRaiseIrql"
UNRESOLVED = re.compile(
    r'(?:unresolved external symbol|undefined symbol:)\s+(?:__declspec\(dllimport\)\s+)?(?:__imp_)?([A-Za-z_][A-Za-z0-9_]*)')


def rebuild_drivers(cc, includes, lib, work: Path):
    results = []
    for name, source, uses_headers in DRIVERS:
        obj = work / f'{name}.obj'
        sys_path = work / f'{name}.sys'
        sys_path.unlink(missing_ok=True)
        entry = {'driver': name, 'source': str(source.relative_to(REPO)),
                 'wdk_headers': uses_headers, 'compiled': False, 'linked': False,
                 'unresolved_imports': []}
        res = compile_with_case_shim(cc, includes, source, obj, uses_headers, work)
        if res.returncode != 0:
            entry['compile_log'] = (res.stdout + res.stderr)[-4000:]
            if uses_headers:
                raise Infra(f'{source.name} does not compile with the WDK headers:\n{entry["compile_log"]}')
            results.append(entry)
            continue
        entry['compiled'] = True
        res = run(linker_cmd(cc, obj, lib, sys_path), cwd=work)
        if res.returncode == 0 and sys_path.exists():
            entry['linked'] = True
            entry['sha256'] = hashlib.sha256(sys_path.read_bytes()).hexdigest()
            entry['path'] = str(sys_path)
        else:
            log = res.stdout + res.stderr
            entry['unresolved_imports'] = sorted(set(UNRESOLVED.findall(log)))
            entry['link_log'] = log[-4000:]
        results.append(entry)
    return results


def cargo_json_lines(args):
    res = run(['cargo', 'run', '-q', '--locked', *args], cwd=REPO)
    if res.returncode != 0:
        raise Infra(f'cargo {" ".join(args)} failed:\n{res.stderr}')
    return res.stdout


def probe_loads(drivers):
    linked = [d for d in drivers if d['linked']]
    if not linked:
        return
    out = cargo_json_lines(['-p', 'nexus-loader', '--example', 'probe_load', '--',
                            *[d['path'] for d in linked]])
    by_path = {}
    for line in out.splitlines():
        if line.strip():
            obj = json.loads(line)
            by_path[obj['file']] = obj
    for d in linked:
        probe = by_path.get(d['path'])
        if probe is None:
            raise Infra(f'probe_load printed nothing for {d["path"]}')
        d['nexus_load'] = probe['load']
        d['nexus_load_error'] = probe.get('error')
        d['imports'] = probe.get('imports', [])


def markdown(rows, drivers, wdk_desc):
    mism = [r for r in rows if not r['match']]
    out = ['# Nexus NT structs vs official WDK (x64)', '',
           f'WDK: {wdk_desc}. Values in bytes. Generated by `scripts/wdk-abi.py`.', '',
           f'**{len(rows) - len(mism)} of {len(rows)} entries match; {len(mism)} differ.**', '',
           '| Struct | Field | WDK | Nexus | |', '| :--- | :--- | ---: | ---: | :---: |']
    for r in rows:
        out.append(f"| `{r['type']}` | `{r['field']}` | {r['wdk']:#x} | {r['nexus']:#x} | {'✔' if r['match'] else '✘'} |")
    out += ['', '## Drivers rebuilt against the official `ntoskrnl.lib`', '',
            '| Driver | WDK headers | Compiled | Linked | Unresolved imports | Nexus load (not executed) |',
            '| :--- | :---: | :---: | :---: | :--- | :--- |']
    for d in drivers:
        load = d.get('nexus_load', '—')
        if d.get('nexus_load_error'):
            load = f"{load}: `{d['nexus_load_error']}`"
        out.append(f"| `{d['driver']}` | {'yes' if d['wdk_headers'] else 'no (hand-written structs)'} | "
                   f"{'yes' if d['compiled'] else 'no'} | {'yes' if d['linked'] else 'no'} | "
                   f"{', '.join(d['unresolved_imports']) or '—'} | {load} |")
    out.append('')
    return '\n'.join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--wdk-root', type=Path, required=True, help='extracted Microsoft.Windows.WDK.x64 package (or WDK install root)')
    ap.add_argument('--sdk-root', type=Path, help='extracted Microsoft.Windows.SDK.CPP package (for shared/ headers)')
    ap.add_argument('--cc', choices=['cl', 'clang-cl'], default='cl')
    ap.add_argument('--out', type=Path, default=REPO / 'build' / 'wdk-abi')
    ap.add_argument('--enforce', action='store_true', help='fail on any ABI mismatch, link failure or load failure (PR-6)')
    ap.add_argument('--summary', type=Path, help='append the markdown report to this file (e.g. $GITHUB_STEP_SUMMARY)')
    args = ap.parse_args()

    try:
        args.out.mkdir(parents=True, exist_ok=True)
        includes, lib = wdk_paths(args.wdk_root, args.sdk_root)
        layout = json.loads(cargo_json_lines(['-p', 'nexus-types', '--example', 'abi_layout']))['layout']
        if not layout:
            raise Infra('nexus-types abi_layout returned no entries')
        keys = [(e['type'], e['field']) for e in layout]
        if len(keys) != len(set(keys)):
            raise Infra('duplicate entries in nexus-types abi_layout')
        rows = build_abi_table(args.cc, includes, layout, args.out)
        drivers = rebuild_drivers(args.cc, includes, lib, args.out)
        probe_loads(drivers)
    except Infra as e:
        print(f'[wdk-abi] INFRASTRUCTURE FAILURE: {e}', file=sys.stderr)
        return 1

    wdk_desc = f'`{lib.relative_to(args.wdk_root) if lib.is_relative_to(args.wdk_root) else lib}`'
    report = {'wdk_lib': str(lib), 'compiler': args.cc, 'abi': rows, 'drivers': drivers,
              'enforced': args.enforce}
    (args.out / 'wdk-abi.json').write_text(json.dumps(report, indent=2))
    md = markdown(rows, drivers, wdk_desc)
    (args.out / 'abi-table.md').write_text(md, encoding='utf-8')
    if args.summary:
        with open(args.summary, 'a', encoding='utf-8') as f:
            f.write(md + '\n')
    print(md)

    problems = [f"ABI {r['type']}.{r['field']}: WDK {r['wdk']:#x} != Nexus {r['nexus']:#x}" for r in rows if not r['match']]
    problems += [f"{d['driver']}: link failed ({', '.join(d['unresolved_imports']) or 'see link_log'})" for d in drivers if not d['linked']]
    problems += [f"{d['driver']}: Nexus load failed ({d.get('nexus_load_error')})" for d in drivers if d['linked'] and d.get('nexus_load') != 'ok']
    mode = 'ENFORCED' if args.enforce else 'report-only (PR-5; --enforce lands with PR-6)'
    print(f'[wdk-abi] {len(problems)} known incompatibilities, mode: {mode}')
    for p in problems:
        print(f'[wdk-abi]   {p}')
    return 1 if (args.enforce and problems) else 0


if __name__ == '__main__':
    sys.exit(main())
