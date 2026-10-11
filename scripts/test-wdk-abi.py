#!/usr/bin/env python3
"""Unit tests for scripts/wdk-abi.py that run anywhere (no WDK, no compiler)."""

import importlib.util
import struct
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


if __name__ == '__main__':
    unittest.main()
