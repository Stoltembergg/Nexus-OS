"""Negative regressions: success logs, stale logs, and QEMU failures never suffice."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('runner', Path(__file__).with_name('test-hardening.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RunnerTests(unittest.TestCase):
    def serial(self):
        return '\n'.join(f'NEXUS_CHECK:{name}:PASS' for name in runner.CHECKS) + '\nNEXUS_STRESS:cycles=64:processes=128:yields=1024:frames=1:heap=0\nNEXUS_HARDENING_PASS:checks=8\nNEXUS_PHASE3_SUCCESS: Unified PE32+/ELF64 Execution Verified\nNEXUS_PHASE3_6_SUCCESS: Native NT Driver Execution Verified in Ring 0\nNEXUS_PHASE3_7_SUCCESS: NT Driver Runtime Hardening & W^X Verified in Ring 0\n'

    def test_complete_protocol_requires_success_exit(self):
        runner.validate(33, self.serial())
        for code in [0, 1, 35, -9, 124]:
            with self.assertRaises(RuntimeError):
                runner.validate(code, self.serial())

    def test_marker_only_missing_duplicate_and_failed_checks_are_rejected(self):
        for serial in ['NEXUS_HARDENING_PASS:checks=8', self.serial().replace('NEXUS_CHECK:msrs:PASS', ''), self.serial() + 'NEXUS_CHECK:context:PASS\n', self.serial().replace('context:PASS', 'context:FAIL'), self.serial().replace('NEXUS_PHASE3_SUCCESS:', 'INCOMPLETE:')]:
            with self.assertRaises(RuntimeError):
                runner.validate(33, serial)


if __name__ == '__main__':
    unittest.main()
