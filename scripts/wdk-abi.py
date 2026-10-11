#!/usr/bin/env python3
"""PR-5/PR-6: compare Nexus NT structs with the official WDK, rebuild and run the test drivers.

What it does (all outputs go to --out, default build/wdk-abi/):

1. ABI table. The struct/field list comes from `cargo run -p nexus-types --example
   abi_layout` (single source of truth). For every entry this script generates a C file
   that includes the official WDK <ntddk.h> and stores `sizeof(T)` / `FIELD_OFFSET(T, f)`
   in a dedicated COFF section, compiles it (no link, nothing runs) and reads the values
   back from the object file. Result: wdk-abi.json and abi-table.md (WDK vs Nexus).
2. Driver rebuild. Compiles tests/fixtures/nt_driver/{nexus_driver,standard_wdm}.c and
   tests/fixtures/nt_driver/wdk/wdk_min.c (all three use only the official <ntddk.h>)
   and links them against the WDK's official ntoskrnl.lib. Link failures are recorded
   with the unresolved imports.
3. Nexus load + run probe. Every driver that linked is loaded (map + relocate + resolve
   imports) AND run (W^X, DriverEntry, IRP_MJ_CREATE/CLOSE, DriverUnload, no bugcheck,
   devices deleted, pool balanced) by `cargo run -p nexus-loader --example probe_load
   -- --run`.
4. Export check. Every NTOSKRNL.EXE export Nexus provides must be a real export of the
   official ntoskrnl.lib (read from the archive symbol table), so Nexus cannot offer a
   name such as KeRaiseIrql that no x64 driver can import.
5. No Microsoft code. Each link writes a map; any public symbol that comes from a
   non-import member of ntoskrnl.lib (e.g. its static memcpy) is a problem, so the
   drivers (and the committed fixtures, which are byte-identical rebuilds) contain only
   import thunks from ntoskrnl.lib. --check-fixtures also scans the committed .sys bytes for
   any 32-byte window of the code sections of ntoskrnl.lib's static members.
6. Fixtures. `--update-fixtures` copies the rebuilt .sys over the committed fixtures that
   the host tests and the QEMU guest embed; `--check-fixtures` requires them to be byte
   identical. Both only with `--cc clang-cl` (deterministic, /Brepro), because the
   committed fixtures are produced by clang-cl + lld-link; MSVC output is
   checked independently for link/load/run. --check-reproducible compares two builds
   made with the selected compiler, without comparing MSVC bytes to clang-cl bytes.

Exit status:
- infrastructure problems (WDK headers/lib not found, ABI probe does not compile, table
  empty or inconsistent, cargo examples failing) always fail (exit 1);
- ABI mismatches, link/load/run failures, exports missing from ntoskrnl.lib and fixture
  drift are REPORTED, and fail with --enforce (PR-6 turns --enforce on).

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
# (name, source, uses the WDK headers, committed fixture embedded by the tests)
DRIVERS = [
    ('nexus_driver', FIXTURES / 'nexus_driver.c', True, FIXTURES / 'nexus_driver.sys'),
    ('standard_wdm', FIXTURES / 'standard_wdm.c', True, FIXTURES / 'standard_wdm.sys'),
    ('wdk_min', FIXTURES / 'wdk' / 'wdk_min.c', True, FIXTURES / 'wdk' / 'wdk_min.sys'),
]


class Infra(RuntimeError):
    """A failure of the tooling itself (always fatal, even in report-only mode)."""


def find_one(root: Path, pattern: str) -> Path:
    hits = sorted(root.rglob(pattern))
    if not hits:
        raise Infra(f'{pattern} not found under {root}')
    return hits[-1]


def wdk_paths(wdk_root: Path, sdk_root: Path | None):
    wdk_root = wdk_root.resolve()
    sdk_root = sdk_root.resolve() if sdk_root is not None else None
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
        cmd = ['cl', '/nologo', '/c', '/kernel', '/GS-', '/O2', '/W4', '/Zl', '/we4013']
    elif cc == 'clang-cl':
        cmd = [shutil.which('clang-cl') or shutil.which('clang-cl-19') or 'clang-cl',
               '/nologo', '/c', '/kernel', '/GS-', '/O2', '/Zl', '/X',
               '--target=x86_64-pc-windows-msvc', '-Wno-everything',
               # an undeclared intrinsic must not silently become an import
               '-Werror=implicit-function-declaration']
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
            '/NODEFAULTLIB', '/OPT:REF,NOICF', '/MACHINE:X64', '/Brepro', f'/MAP:{out.with_suffix(".map")}',
            f'/OUT:{out}', str(obj), str(lib)]


# " 0001:000009c0       memcpy     00000001400019c0     ntoskrnl:...\memcpy.obj"  (lld-link)
# " 0001:00000540       memcpy     0000000140001540 f   ntoskrnl:memcpy.obj"       (MSVC link)
MAP_SYMBOL = re.compile(r'^\s*[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+[0-9a-fA-F]{8,16}\b.*?(\S+)\s*$')


def static_lib_symbols(map_text: str, own_obj: str) -> list[str]:
    """Symbols the linker took from library *code* rather than from the driver's own
    object. Import members of ntoskrnl.lib show up as `ntoskrnl:ntoskrnl.exe` (the
    __imp_ pointers and jmp thunks); linker-synthesised symbols as `<...>`. Anything
    else (e.g. `ntoskrnl:...\\memcpy.obj`) is Microsoft code statically linked into the
    driver, which the committed fixtures must not contain."""
    found = []
    for line in map_text.splitlines():
        m = MAP_SYMBOL.match(line)
        if not m:
            continue
        sym, origin = m.group(1), m.group(2)
        if origin.startswith('<') or origin.lower() == own_obj.lower():
            continue
        if origin.lower().endswith(':ntoskrnl.exe'):
            continue
        found.append((origin, sym))
    by_origin = {}
    for origin, sym in found:
        by_origin.setdefault(origin, set()).add(sym)
    return [f"{origin} ({len(syms)} symbols, e.g. {', '.join(sorted(syms)[:3])})" for origin, syms in sorted(by_origin.items())]


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
    (work / 'abi-compile.log').write_text(res.stdout + res.stderr, encoding='utf-8')
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
    for name, source, uses_headers, fixture in DRIVERS:
        obj = work / f'{name}.obj'
        sys_path = work / f'{name}.sys'
        sys_path.unlink(missing_ok=True)
        entry = {'driver': name, 'source': str(source.relative_to(REPO)),
                 'fixture': str(fixture.relative_to(REPO)),
                 'wdk_headers': uses_headers, 'compiled': False, 'linked': False,
                 'unresolved_imports': []}
        res = compile_with_case_shim(cc, includes, source, obj, uses_headers, work)
        (work / f'{name}-compile.log').write_text(res.stdout + res.stderr, encoding='utf-8')
        if res.returncode != 0:
            entry['compile_log'] = (res.stdout + res.stderr)[-4000:]
            if uses_headers:
                raise Infra(f'{source.name} does not compile with the WDK headers:\n{entry["compile_log"]}')
            results.append(entry)
            continue
        entry['compiled'] = True
        res = run(linker_cmd(cc, obj, lib, sys_path), cwd=work)
        (work / f'{name}-link.log').write_text(res.stdout + res.stderr, encoding='utf-8')
        if res.returncode == 0 and sys_path.exists():
            entry['linked'] = True
            map_path = sys_path.with_suffix('.map')
            if not map_path.exists():
                raise Infra(f'linker map {map_path} missing')
            entry['static_lib_code'] = static_lib_symbols(map_path.read_text(errors='replace'), obj.name)
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
    out = cargo_json_lines(['-p', 'nexus-loader', '--example', 'probe_load', '--', '--run',
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
        d['nexus_run'] = probe.get('run', '—')
        d['nexus_run_error'] = probe.get('run_error')
        d['imports'] = probe.get('imports', [])


def lib_symbols(lib: Path) -> set[str]:
    """Public symbols of a COFF import library, from the archive's first linker member
    (big-endian count, offsets, then NUL-terminated names). No external tools needed."""
    data = lib.read_bytes()
    if not data.startswith(b'!<arch>\n'):
        raise Infra(f'{lib} is not an ar archive')
    header = data[8:68]
    if header[:16].rstrip() != b'/':
        raise Infra(f'{lib}: first archive member is not the linker member')
    size = int(header[48:58].decode().strip())
    body = data[68:68 + size]
    count = struct.unpack('>I', body[:4])[0]
    names = body[4 + 4 * count:].split(b'\0')[:count]
    if len(names) != count:
        raise Infra(f'{lib}: truncated linker member')
    return {n.decode('ascii', 'replace') for n in names}


def archive_members(data: bytes):
    off = 8
    while off + 60 <= len(data):
        header = data[off:off + 60]
        size = int(header[48:58].decode().strip())
        yield data[off + 60:off + 60 + size]
        off += 60 + size + (size & 1)


def lib_static_code_windows(lib: Path, width: int = 32) -> set[bytes]:
    """32-byte windows of every code section of the *static* (non-import) COFF members of
    the import library (memcpy, memset, CFG/GS helpers...). Import members start with
    0x0000 0xFFFF and are skipped. Windows that are mostly one byte value are dropped."""
    data = lib.read_bytes()
    if not data.startswith(b'!<arch>\n'):
        raise Infra(f'{lib} is not an ar archive')
    windows = set()
    for obj in archive_members(data):
        if len(obj) < 20 or struct.unpack_from('<H', obj, 0)[0] != 0x8664:
            continue
        nsec, opt = struct.unpack_from('<H', obj, 2)[0], struct.unpack_from('<H', obj, 16)[0]
        for i in range(nsec):
            sec = 20 + opt + 40 * i
            size, ptr = struct.unpack_from('<II', obj, sec + 16)
            if struct.unpack_from('<I', obj, sec + 36)[0] & 0x20 and ptr and size >= width:
                code = obj[ptr:ptr + size]
                for j in range(0, size - width + 1, 16):
                    w = code[j:j + width]
                    if len(set(w)) > 4:
                        windows.add(w)
    return windows


def ntoskrnl_exports(lib: Path) -> set[str]:
    return {s[len('__imp_'):] for s in lib_symbols(lib) if s.startswith('__imp_')}


def check_exports(lib: Path):
    nexus = json.loads(cargo_json_lines(['-p', 'nexus-loader', '--example', 'probe_load', '--', '--exports']))['exports']
    if not nexus:
        raise Infra('probe_load --exports returned no exports')
    real = ntoskrnl_exports(lib)
    if not real:
        raise Infra(f'no __imp_ symbols found in {lib}')
    return {'nexus_exports': sorted(nexus), 'not_in_ntoskrnl_lib': sorted(n for n in nexus if n not in real)}


MANIFEST = FIXTURES / 'wdk-fixtures.json'


def clang_version() -> str:
    exe = shutil.which('clang-cl') or shutil.which('clang-cl-19') or 'clang-cl'
    res = run([exe, '--version'])
    m = re.search(r'clang version (\d+\.\d+\.\d+)', res.stdout)
    if not m:
        raise Infra(f'cannot read the clang-cl version: {res.stdout}{res.stderr}')
    return m.group(1)


def compare_fixtures(drivers, update: bool, lib: Path):
    """Byte comparison only makes sense with the clang version that produced the
    committed fixtures (recorded in wdk-fixtures.json); any other version is refused
    instead of being reported as drift."""
    version = clang_version()
    if update:
        manifest = {'producer': 'scripts/wdk-abi.py --cc clang-cl --update-fixtures',
                    'clang_cl': version, 'link': 'lld-link /Brepro',
                    'ntoskrnl_lib': lib.name, 'wdk_package': next((p.name for p in lib.parents if p.name.lower().startswith('microsoft.windows.wdk')), str(lib.parent)),
                    'drivers': {}}
    else:
        if not MANIFEST.exists():
            raise Infra(f'{MANIFEST.relative_to(REPO)} missing; run --update-fixtures')
        manifest = json.loads(MANIFEST.read_text())
        if manifest.get('clang_cl') != version:
            raise Infra(f"committed fixtures were produced by clang-cl {manifest.get('clang_cl')}, this is {version}; "
                        'byte comparison is not meaningful across compiler versions')
    lib_code = lib_static_code_windows(lib)
    if not lib_code:
        raise Infra(f'no static code found in {lib}; the Microsoft-code check would be vacuous')
    for d in drivers:
        fixture = REPO / d['fixture']
        if fixture.exists():
            committed = fixture.read_bytes()
            d['fixture_lib_code_windows'] = sum(1 for w in lib_code if w in committed)
        if not d['linked']:
            d['fixture_match'] = False
            continue
        built = Path(d['path']).read_bytes()
        if update:
            fixture.parent.mkdir(parents=True, exist_ok=True)
            fixture.write_bytes(built)
        d['fixture_match'] = fixture.exists() and fixture.read_bytes() == built
        if update:
            manifest['drivers'][d['fixture']] = hashlib.sha256(built).hexdigest()
        elif manifest['drivers'].get(d['fixture']) != hashlib.sha256(fixture.read_bytes()).hexdigest():
            d['fixture_match'] = False
    if update:
        MANIFEST.write_text(json.dumps(manifest, indent=2) + '\n')


def markdown(rows, drivers, wdk_desc, exports=None):
    mism = [r for r in rows if not r['match']]
    out = ['# Nexus NT structs vs official WDK (x64)', '',
           f'WDK: {wdk_desc}. Values in bytes. Generated by `scripts/wdk-abi.py`.', '',
           f'**{len(rows) - len(mism)} of {len(rows)} entries match; {len(mism)} differ.**', '',
           '| Struct | Field | WDK | Nexus | |', '| :--- | :--- | ---: | ---: | :---: |']
    for r in rows:
        out.append(f"| `{r['type']}` | `{r['field']}` | {r['wdk']:#x} | {r['nexus']:#x} | {'✔' if r['match'] else '✘'} |")
    out += ['', '## Drivers rebuilt against the official `ntoskrnl.lib`', '',
            '| Driver | WDK headers | Compiled | Linked | Unresolved imports | Static code from ntoskrnl.lib | Nexus load | Nexus run | Committed fixture |',
            '| :--- | :---: | :---: | :---: | :--- | :--- | :--- | :--- | :---: |']
    for d in drivers:
        load = d.get('nexus_load', '—')
        if d.get('nexus_load_error'):
            load = f"{load}: `{d['nexus_load_error']}`"
        run_ = d.get('nexus_run', '—')
        if d.get('nexus_run_error'):
            run_ = f"{run_}: `{d['nexus_run_error']}`"
        fix = {True: 'identical', False: 'DIFFERS'}.get(d.get('fixture_match'), 'not checked')
        if 'fixture_lib_code_windows' in d:
            fix += f"; ntoskrnl.lib code windows: {d['fixture_lib_code_windows']}"
        out.append(f"| `{d['driver']}` | {'yes' if d['wdk_headers'] else 'no (hand-written structs)'} | "
                   f"{'yes' if d['compiled'] else 'no'} | {'yes' if d['linked'] else 'no'} | "
                   f"{', '.join(d['unresolved_imports']) or '—'} | "
                   f"{', '.join(d.get('static_lib_code', [])) or 'none (imports only)'} | {load} | {run_} | {fix} |")
    if exports is not None:
        bad = exports['not_in_ntoskrnl_lib']
        out += ['', f"Nexus `NTOSKRNL.EXE` exports: {len(exports['nexus_exports'])}; "
                f"not exported by the official `ntoskrnl.lib`: {', '.join(bad) if bad else 'none'}."]
    out.append('')
    return '\n'.join(out)


def collect_problems(rows, drivers, exports):
    """Everything --enforce fails on."""
    problems = [f"ABI {r['type']}.{r['field']}: WDK {r['wdk']:#x} != Nexus {r['nexus']:#x}" for r in rows if not r['match']]
    problems += [f"{d['driver']}: link failed ({', '.join(d['unresolved_imports']) or 'see link_log'})" for d in drivers if not d['linked']]
    problems += [f"{d['driver']}: Nexus load failed ({d.get('nexus_load_error')})" for d in drivers if d['linked'] and d.get('nexus_load') != 'ok']
    problems += [f"{d['driver']}: Nexus run failed ({d.get('nexus_run_error')})" for d in drivers if d.get('nexus_load') == 'ok' and d.get('nexus_run') != 'ok']
    problems += [f"Nexus exports {name}, which the official ntoskrnl.lib does not export" for name in exports['not_in_ntoskrnl_lib']]
    problems += [f"{d['fixture']}: committed fixture differs from the rebuild" for d in drivers if d.get('fixture_match') is False]
    problems += [f"{d['driver']}: statically links library code from ntoskrnl.lib: {', '.join(d['static_lib_code'])}"
                 for d in drivers if d.get('static_lib_code')]
    problems += [f"{d['fixture']}: contains {d['fixture_lib_code_windows']} code windows of ntoskrnl.lib static members"
                 for d in drivers if d.get('fixture_lib_code_windows')]
    problems += [f"{d['driver']}: same-compiler rebuild differs or failed"
                 for d in drivers if d.get('reproducible') is False]
    return problems


def compare_rebuilds(drivers, repeated):
    """Compare two builds by the same compiler; never MSVC against clang-cl."""
    by_name = {d['driver']: d for d in repeated}
    if len(by_name) != len(repeated) or set(by_name) != {d['driver'] for d in drivers}:
        raise Infra('same-compiler rebuild has missing/duplicate/unexpected drivers')
    for d in drivers:
        other = by_name[d['driver']]
        d['rebuild_sha256'] = other.get('sha256')
        d['reproducible'] = bool(d['linked'] and other['linked'] and d.get('sha256')
                                 and d['sha256'] == other.get('sha256'))


def inject_import_error(drivers):
    """Corrupt only a built output's import name, preserving the PE layout."""
    original, missing = b'IofCompleteRequest\0', b'NexusMissingExport\0'
    for d in drivers:
        if not d['linked']:
            continue
        path = Path(d['path'])
        data = path.read_bytes()
        if original in data:
            data = data.replace(original, missing, 1)
            path.write_bytes(data)
            d['injected_import'] = missing[:-1].decode()
            d['sha256'] = hashlib.sha256(data).hexdigest()
            return
    raise Infra('--inject-import-error: no built IofCompleteRequest import found')


def inject_layout_error(layout, key: str):
    """Negative control: shift one Nexus value by 8 bytes (e.g. KEVENT.Header.WaitListHead.Flink
    becomes 0x10, the pre-PR-6 order). The run must then fail under --enforce."""
    typ, _, field = key.partition('.')
    for e in layout:
        if e['type'] == typ and e['field'] == field:
            e['value'] += 8
            return
    raise Infra(f'--inject-layout-error: no entry {key}')


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--wdk-root', type=Path, required=True, help='extracted Microsoft.Windows.WDK.x64 package (or WDK install root)')
    ap.add_argument('--sdk-root', type=Path, help='extracted Microsoft.Windows.SDK.CPP package (for shared/ headers)')
    ap.add_argument('--cc', choices=['cl', 'clang-cl'], default='cl')
    ap.add_argument('--out', type=Path, default=REPO / 'build' / 'wdk-abi')
    ap.add_argument('--enforce', action='store_true', help='fail on any ABI mismatch, link/load/run failure, non-ntoskrnl export or fixture drift')
    ap.add_argument('--inject-layout-error', metavar='TYPE.FIELD', help='negative control: shift that Nexus entry by 8 bytes; the run must fail with --enforce')
    ap.add_argument('--inject-import-error', action='store_true', help='negative control: replace a built import with NexusMissingExport')
    ap.add_argument('--check-reproducible', action='store_true', help='require two builds with this compiler to have identical driver hashes')
    fx = ap.add_mutually_exclusive_group()
    fx.add_argument('--check-fixtures', action='store_true', help='require the committed .sys fixtures to be byte-identical to the rebuild (clang-cl only)')
    fx.add_argument('--update-fixtures', action='store_true', help='overwrite the committed .sys fixtures with the rebuild (clang-cl only)')
    ap.add_argument('--summary', type=Path, help='append the markdown report to this file (e.g. $GITHUB_STEP_SUMMARY)')
    args = ap.parse_args()
    args.out = args.out.resolve()

    if (args.check_fixtures or args.update_fixtures) and args.cc != 'clang-cl':
        print('[wdk-abi] --check-fixtures/--update-fixtures need --cc clang-cl (the committed fixtures are clang-cl builds)', file=sys.stderr)
        return 2
    try:
        args.out.mkdir(parents=True, exist_ok=True)
        includes, lib = wdk_paths(args.wdk_root, args.sdk_root)
        layout = json.loads(cargo_json_lines(['-p', 'nexus-types', '--example', 'abi_layout']))['layout']
        if not layout:
            raise Infra('nexus-types abi_layout returned no entries')
        keys = [(e['type'], e['field']) for e in layout]
        if len(keys) != len(set(keys)):
            raise Infra('duplicate entries in nexus-types abi_layout')
        if args.inject_layout_error:
            inject_layout_error(layout, args.inject_layout_error)
        rows = build_abi_table(args.cc, includes, layout, args.out)
        drivers = rebuild_drivers(args.cc, includes, lib, args.out)
        if args.check_reproducible:
            repeated_out = args.out / 'repro'
            repeated_out.mkdir(exist_ok=True)
            compare_rebuilds(drivers, rebuild_drivers(args.cc, includes, lib, repeated_out))
        if args.inject_import_error:
            inject_import_error(drivers)
        probe_loads(drivers)
        exports = check_exports(lib)
        if args.check_fixtures or args.update_fixtures:
            compare_fixtures(drivers, args.update_fixtures, lib)
    except Infra as e:
        print(f'[wdk-abi] INFRASTRUCTURE FAILURE: {e}', file=sys.stderr)
        return 1

    wdk_desc = f'`{lib.relative_to(args.wdk_root) if lib.is_relative_to(args.wdk_root) else lib}`'
    problems = collect_problems(rows, drivers, exports)
    report = {'wdk_lib': str(lib), 'compiler': args.cc, 'abi': rows, 'drivers': drivers,
              'exports': exports, 'enforced': args.enforce, 'problems': problems}
    (args.out / 'wdk-abi.json').write_text(json.dumps(report, indent=2))
    md = markdown(rows, drivers, wdk_desc, exports)
    (args.out / 'abi-table.md').write_text(md, encoding='utf-8')
    if args.summary:
        with open(args.summary, 'a', encoding='utf-8') as f:
            f.write(md + '\n')
    print(md)

    mode = 'ENFORCED' if args.enforce else 'report-only'
    print(f'[wdk-abi] {len(problems)} incompatibilities, mode: {mode}')
    for p in problems:
        print(f'[wdk-abi]   {p}')
    return 1 if (args.enforce and problems) else 0


if __name__ == '__main__':
    sys.exit(main())
