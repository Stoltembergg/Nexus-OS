#!/usr/bin/env python3
"""Unit tests for scripts/wdk-abi.py that run anywhere (no WDK, no compiler)."""

import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('wdk_abi', Path(__file__).with_name('wdk-abi.py'))
wdk_abi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wdk_abi)


def coff(sections):
    """Minimal x64 COFF object with the given (name, data) sections."""
    header = struct.pack('<HHIIIHH', 0x8664, len(sections), 0, 0, 0, 0, 0)
    table, raw = b'', b''
    data_start = 20 + 40 * len(sections)
    for name, data in sections:
        ptr = data_start + len(raw)
        table += name.ljust(8, b'\0') + struct.pack('<IIIIIIHHI', 0, 0, len(data), ptr, 0, 0, 0, 0, 0)
        raw += data
    return header + table + raw


class WdkAbiTests(unittest.TestCase):
    def test_package_paths_are_absolute_for_compiler_working_directory(self):
        with tempfile.TemporaryDirectory(dir=wdk_abi.REPO) as tmp:
            root = Path(tmp)
            for directory in ['Include/km/crt', 'Include/shared', 'Lib/km/x64']:
                (root / directory).mkdir(parents=True)
            (root / 'Include/km/ntddk.h').touch()
            (root / 'Lib/km/x64/ntoskrnl.lib').touch()
            includes, lib = wdk_abi.wdk_paths(root.relative_to(wdk_abi.REPO), None)
            self.assertTrue(all(p.is_absolute() for p in [*includes, lib]))

    def test_missing_import_control_changes_only_the_built_driver(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'built.sys'
            original = b'PE-data\0IofCompleteRequest\0tail'
            path.write_bytes(original)
            drivers = [{'driver': 'test', 'linked': True, 'path': str(path)}]
            wdk_abi.inject_import_error(drivers)
            self.assertEqual(path.read_bytes(), b'PE-data\0NexusMissingExport\0tail')
            self.assertEqual(len(path.read_bytes()), len(original))
            self.assertEqual(drivers[0]['injected_import'], 'NexusMissingExport')
            with self.assertRaises(wdk_abi.Infra):
                wdk_abi.inject_import_error(drivers)

    def test_rebuild_drift_and_failed_rebuild_are_enforced(self):
        first = [{'driver': 'a', 'fixture': 'a.sys', 'linked': True, 'sha256': 'first',
                  'unresolved_imports': [], 'nexus_load': 'ok', 'nexus_run': 'ok'}]
        for second in [[{'driver': 'a', 'linked': True, 'sha256': 'different'}],
                       [{'driver': 'a', 'linked': False}]]:
            wdk_abi.compare_rebuilds(first, second)
            self.assertFalse(first[0]['reproducible'])
            self.assertTrue(any('same-compiler rebuild' in p for p in
                                wdk_abi.collect_problems([], first, {'not_in_ntoskrnl_lib': []})))
        wdk_abi.compare_rebuilds(first, [{'driver': 'a', 'linked': True, 'sha256': 'first'}])
        self.assertTrue(first[0]['reproducible'])
        self.assertEqual(wdk_abi.collect_problems([], first, {'not_in_ntoskrnl_lib': []}), [])
        with self.assertRaises(wdk_abi.Infra):
            wdk_abi.compare_rebuilds(first, [])

    def test_reads_named_section(self):
        values = struct.pack('<3Q', 0x150, 0x30, 0x40)
        obj = coff([(b'.text', b'\xc3'), (b'.nxabi', values)])
        self.assertEqual(wdk_abi.coff_section(obj, b'.nxabi'), values)

    def test_missing_section_is_infrastructure_failure(self):
        with self.assertRaises(wdk_abi.Infra):
            wdk_abi.coff_section(coff([(b'.text', b'\xc3')]), b'.nxabi')

    def test_wrong_machine_is_infrastructure_failure(self):
        obj = bytearray(coff([(b'.nxabi', b'\0' * 8)]))
        obj[0:2] = struct.pack('<H', 0x14C)
        with self.assertRaises(wdk_abi.Infra):
            wdk_abi.coff_section(bytes(obj), b'.nxabi')

    def test_unresolved_symbols_from_msvc_and_lld(self):
        msvc = 'standard_wdm.obj : error LNK2019: unresolved external symbol __imp_KeAcquireSpinLock referenced in function X'
        lld = 'lld-link: error: undefined symbol: __declspec(dllimport) KeRaiseIrql'
        self.assertEqual(wdk_abi.UNRESOLVED.findall(msvc), ['KeAcquireSpinLock'])
        self.assertEqual(wdk_abi.UNRESOLVED.findall(lld), ['KeRaiseIrql'])

    def test_expressions(self):
        self.assertEqual(wdk_abi.wdk_expr({'type': 'IRP', 'field': 'sizeof'}), 'sizeof(IRP)')
        self.assertEqual(wdk_abi.wdk_expr({'type': 'IRP', 'field': 'Tail.Overlay.CurrentStackLocation'}),
                         'FIELD_OFFSET(IRP, Tail.Overlay.CurrentStackLocation)')

    def test_report_marks_mismatches(self):
        rows = [{'type': 'DEVICE_OBJECT', 'field': 'Flags', 'wdk': 0x30, 'nexus': 0x28, 'match': False},
                {'type': 'KEVENT', 'field': 'sizeof', 'wdk': 0x18, 'nexus': 0x18, 'match': True}]
        md = wdk_abi.markdown(rows, [], 'test')
        self.assertIn('1 of 2 entries match; 1 differ', md)
        self.assertIn('| `DEVICE_OBJECT` | `Flags` | 0x30 | 0x28 | ✘ |', md)

    def test_wrong_offset_is_an_enforced_problem(self):
        # Negative control: the pre-PR-6 KEVENT order (Blink before Flink) must fail --enforce.
        layout = [{'type': 'KEVENT', 'field': 'Header.WaitListHead.Flink', 'value': 0x8}]
        wdk_abi.inject_layout_error(layout, 'KEVENT.Header.WaitListHead.Flink')
        self.assertEqual(layout[0]['value'], 0x10)
        rows = [{'type': 'KEVENT', 'field': 'Header.WaitListHead.Flink', 'wdk': 0x8, 'nexus': 0x10, 'match': False}]
        problems = wdk_abi.collect_problems(rows, [], {'not_in_ntoskrnl_lib': []})
        self.assertEqual(problems, ['ABI KEVENT.Header.WaitListHead.Flink: WDK 0x8 != Nexus 0x10'])
        with self.assertRaises(wdk_abi.Infra):
            wdk_abi.inject_layout_error(layout, 'IRP.NoSuchField')

    def test_clean_run_has_no_problems(self):
        rows = [{'type': 'IRP', 'field': 'sizeof', 'wdk': 0xd0, 'nexus': 0xd0, 'match': True}]
        drivers = [{'driver': 'wdk_min', 'fixture': 'f.sys', 'linked': True, 'unresolved_imports': [],
                    'nexus_load': 'ok', 'nexus_run': 'ok', 'fixture_match': True}]
        self.assertEqual(wdk_abi.collect_problems(rows, drivers, {'not_in_ntoskrnl_lib': []}), [])

    def test_run_failure_export_and_fixture_drift_are_problems(self):
        drivers = [{'driver': 'a', 'fixture': 'a.sys', 'linked': True, 'unresolved_imports': [],
                    'nexus_load': 'ok', 'nexus_run': 'error', 'nexus_run_error': 'DriverEntry returned 0xc0000001',
                    'fixture_match': False},
                   {'driver': 'b', 'fixture': 'b.sys', 'linked': False, 'unresolved_imports': ['KeRaiseIrql']}]
        problems = wdk_abi.collect_problems([], drivers, {'not_in_ntoskrnl_lib': ['KeAcquireSpinLock']})
        self.assertEqual(len(problems), 4)
        self.assertTrue(any('run failed' in p for p in problems))
        self.assertTrue(any('KeAcquireSpinLock' in p for p in problems))
        self.assertTrue(any('a.sys' in p for p in problems))
        self.assertTrue(any('KeRaiseIrql' in p for p in problems))

    def test_import_library_symbol_table(self):
        names = [b'__imp_KfRaiseIrql', b'KfRaiseIrql', b'__imp_IofCompleteRequest', b'memcpy']
        body = struct.pack('>I', len(names)) + b'\0\0\0\0' * len(names) + b'\0'.join(names) + b'\0'
        member = b'/'.ljust(16) + b'0'.ljust(12) + b'0'.ljust(6) + b'0'.ljust(6) + b'0'.ljust(8) + str(len(body)).encode().ljust(10) + b'`\n'
        with tempfile.TemporaryDirectory() as tmp:
            lib = Path(tmp) / 'ntoskrnl.lib'
            lib.write_bytes(b'!<arch>\n' + member + body)
            self.assertEqual(wdk_abi.ntoskrnl_exports(lib), {'KfRaiseIrql', 'IofCompleteRequest'})
            lib.write_bytes(b'not an archive')
            with self.assertRaises(wdk_abi.Infra):
                wdk_abi.ntoskrnl_exports(lib)

    def test_linker_map_static_library_code(self):
        lld = """ 0001:00000000       DriverEntry                0000000140001000     nexus_driver.obj
 0001:000009c0       memcpy                     00000001400019c0     ntoskrnl:d:\\os\\amd64\\memcpy.obj
 0001:00000c70       DbgPrint                   0000000140001c70     ntoskrnl:ntoskrnl.exe
 0002:000001e8       __imp_DbgPrint             00000001400021e8     ntoskrnl:ntoskrnl.exe
 0000:00000000       __ImageBase                0000000140000000     <linker-defined>
 0001:00000000 00000981H .text                   CODE"""
        self.assertEqual(wdk_abi.static_lib_symbols(lld, 'nexus_driver.obj'),
                         ['ntoskrnl:d:\\os\\amd64\\memcpy.obj (1 symbols, e.g. memcpy)'])
        msvc = """ 0001:00000000       DriverEntry                0000000140001000 f   standard_wdm.obj
 0001:00000540       memset                     0000000140001540 f   ntoskrnl:memset.obj
 0002:00000010       __imp_IofCompleteRequest   0000000140002010     ntoskrnl:ntoskrnl.exe"""
        self.assertEqual(wdk_abi.static_lib_symbols(msvc, 'standard_wdm.obj'), ['ntoskrnl:memset.obj (1 symbols, e.g. memset)'])
        clean = lld.replace(' 0001:000009c0       memcpy                     00000001400019c0     ntoskrnl:d:\\os\\amd64\\memcpy.obj\n', '')
        self.assertEqual(wdk_abi.static_lib_symbols(clean, 'nexus_driver.obj'), [])
        drivers = [{'driver': 'x', 'fixture': 'x.sys', 'linked': True, 'unresolved_imports': [], 'nexus_load': 'ok',
                    'nexus_run': 'ok', 'static_lib_code': ['memcpy (ntoskrnl:memcpy.obj)']}]
        self.assertEqual(len(wdk_abi.collect_problems([], drivers, {'not_in_ntoskrnl_lib': []})), 1)

    def test_static_library_code_windows(self):
        code = bytes(range(64))
        obj = struct.pack('<HHIIIHH', 0x8664, 1, 0, 0, 0, 0, 0) + \
            b'.text\0\0\0' + struct.pack('<IIIIIIHHI', 0, 0, len(code), 60, 0, 0, 0, 0, 0x60000020) + code
        imp = struct.pack('<HH', 0, 0xFFFF) + b'\0' * 40
        def member(body):
            hdr = b'x'.ljust(16) + b'0'.ljust(12) + b'0'.ljust(6) + b'0'.ljust(6) + b'0'.ljust(8) + str(len(body)).encode().ljust(10) + b'`\n'
            return hdr + body + (b'\n' if len(body) & 1 else b'')
        with tempfile.TemporaryDirectory() as tmp:
            lib = Path(tmp) / 'ntoskrnl.lib'
            lib.write_bytes(b'!<arch>\n' + member(imp) + member(obj))
            windows = wdk_abi.lib_static_code_windows(lib)
            self.assertEqual(len(windows), 3)  # offsets 0, 16, 32
            self.assertTrue(any(w in b'driver' + code[10:50] + b'tail' for w in windows))
            self.assertFalse(any(w in b'\x90' * 200 for w in windows))


if __name__ == '__main__':
    unittest.main()
