"""Negative regressions: success logs, stale logs, and QEMU failures never suffice."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('runner', Path(__file__).with_name('test-hardening.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RunnerTests(unittest.TestCase):
    def serial(self):
        return '\n'.join(f'NEXUS_CHECK:{name}:PASS' for name in sorted(runner.CHECKS | runner.DRIVER_CHECKS)) + '\nNEXUS_DRIVER_WX:pages_verified=20\nNEXUS_DRIVER_LIFECYCLE:drivers=3:heap_balanced=true:pool_balanced=true:devices_deleted=true' + '\nNEXUS_STRESS:cycles=64:processes=128:yields=1024:frames=1:heap=0\nNEXUS_HARDENING_PASS:checks=8\nNEXUS_PHASE3_SUCCESS: Unified PE32+/ELF64 Execution Verified\nNEXUS_PHASE3_6_SUCCESS: Native NT Driver Execution Verified in Ring 0\nNEXUS_PHASE3_7_SUCCESS: NT Driver Runtime Hardening & W^X Verified in Ring 0\nNEXUS_DRIVER_RELOC:applied=3:rebased=true:entry_status=0x0\nNEXUS_DRIVER_FAIL_CLOSED:imports=rejected:relocs=rejected\n'

    def test_complete_protocol_requires_success_exit(self):
        runner.validate(33, self.serial())
        for code in [0, 1, 35, -9, 124]:
            with self.assertRaises(RuntimeError):
                runner.validate(code, self.serial())

    def test_marker_only_missing_duplicate_and_failed_checks_are_rejected(self):
        for serial in ['NEXUS_HARDENING_PASS:checks=8', self.serial().replace('NEXUS_CHECK:msrs:PASS', ''), self.serial() + 'NEXUS_CHECK:context:PASS\n', self.serial().replace('context:PASS', 'context:FAIL'), self.serial().replace('NEXUS_PHASE3_SUCCESS:', 'INCOMPLETE:')]:
            with self.assertRaises(RuntimeError):
                runner.validate(33, serial)

    def test_driver_relocation_and_fail_closed_markers_are_required(self):
        for old, new in [
            ('NEXUS_DRIVER_RELOC:applied=3', 'NEXUS_DRIVER_RELOC:applied=0'),
            ('entry_status=0x0', 'entry_status=0xc0de0001'),
            ('NEXUS_DRIVER_FAIL_CLOSED:imports=rejected:relocs=rejected\n', ''),
        ]:
            with self.assertRaises(RuntimeError):
                runner.validate(33, self.serial().replace(old, new))

    def test_driver_evidence_is_required(self):
        for old, new in [
            ('NEXUS_CHECK:driver-wx:PASS\n', ''),
            ('NEXUS_CHECK:driver-lifecycle:PASS\n', ''),
            ('pages_verified=20', 'pages_verified=0'),
            ('drivers=3:heap_balanced=true', 'drivers=2:heap_balanced=true'),
        ]:
            with self.assertRaises(RuntimeError):
                runner.validate(33, self.serial().replace(old, new))

    def test_guest_failure_exit_codes_are_named(self):
        for code in (35, 37):
            with self.assertRaisesRegex(RuntimeError, 'Guest reported failure'):
                runner.validate(code, self.serial())


if __name__ == '__main__':
    unittest.main()
