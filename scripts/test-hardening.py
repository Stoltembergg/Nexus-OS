"""Build and validate a real QEMU/OVMF guest. Serial markers alone cannot pass."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import re
import platform
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
CHECKS = {'msrs', 'permissions', 'context', 'faults', 'exit-and-boundary', 'rollback-oom', 'loader-bytes', 'stress'}


def validate(returncode, serial):
    if returncode != 33:
        raise RuntimeError(f'Guest did not signal isa-debug-exit success (expected 33, got {returncode})')
    checks = [line.strip() for line in serial.splitlines() if line.startswith('NEXUS_CHECK:')]
    expected = {f'NEXUS_CHECK:{name}:PASS' for name in CHECKS}
    if set(checks) != expected or len(checks) != len(expected):
        raise RuntimeError(f'Missing/duplicate/unexpected guest checks: {checks}')
    if serial.count('NEXUS_HARDENING_PASS:checks=8') != 1:
        raise RuntimeError('Missing unique suite completion result')
    if serial.count('NEXUS_PHASE3_SUCCESS: Unified PE32+/ELF64 Execution Verified') != 1:
        raise RuntimeError('Original Phase 3 execution did not finish its outcome assertions')
    if serial.count('NEXUS_PHASE3_6_SUCCESS: Native NT Driver Execution Verified in Ring 0') != 1:
        raise RuntimeError('Phase 3.6 NT driver execution did not complete in guest Ring 0')
    if serial.count('NEXUS_PHASE3_7_SUCCESS: NT Driver Runtime Hardening & W^X Verified in Ring 0') != 1:
        raise RuntimeError('Phase 3.7 NT driver hardening did not complete in guest Ring 0')
    if serial.count('NEXUS_DRIVER_RELOC:applied=3:rebased=true:entry_status=0x0') != 1:
        raise RuntimeError('Relocation-bearing NT driver was not rebased and verified in guest Ring 0')
    if serial.count('NEXUS_DRIVER_FAIL_CLOSED:imports=rejected:relocs=rejected') != 1:
        raise RuntimeError('NT driver loader did not reject corrupted import/relocation tables in guest')
    if 'NEXUS_STRESS:cycles=64:processes=128:yields=1024:' not in serial:
        raise RuntimeError('Missing measured stress results')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--qemu', default=os.environ.get('QEMU_BIN') or shutil.which('qemu-system-x86_64') or r'C:\Program Files\qemu\qemu-system-x86_64.exe')
    parser.add_argument('--ovmf', default=os.environ.get('OVMF_PATH'))
    parser.add_argument('--ram', type=int, default=128)
    parser.add_argument('--cpu', default='qemu64')
    parser.add_argument('--timeout', type=int, default=60)
    parser.add_argument('--release', action='store_true')
    args = parser.parse_args()
    firmware = args.ovmf or next((p for p in [r'C:\Program Files\qemu\share\edk2-x86_64-code.fd', '/usr/share/ovmf/OVMF.fd', '/usr/share/OVMF/OVMF_CODE.fd', '/usr/share/OVMF/OVMF_CODE_4M.fd'] if Path(p).is_file()), None)
    if not firmware:
        parser.error('OVMF unavailable; provide --ovmf. No validation can be claimed.')
    fixture_dir = ROOT / 'build' / 'fixtures'
    if not (fixture_dir / 'manifest.json').exists():
        parser.error('Compile external fixtures with scripts/build-fixtures.py first')
    manifest_bytes = (fixture_dir / 'manifest.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    expected_files = {f'{kind}-{mode}.{suffix}' for kind, suffix in [('pe', 'exe'), ('elf', 'elf')] for mode in range(16)}
    if set(manifest['files']) != expected_files:
        parser.error('Fixture manifest must contain the 32 expected external images')
    for name, expected in manifest['files'].items():
        data = (fixture_dir / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected['sha256'] or len(data) != expected['bytes']:
            parser.error(f'Fixture bytes differ from compiler manifest: {name}')
    env = dict(os.environ, NEXUS_FIXTURES_DIR=str(fixture_dir))
    cmd = ['cargo', 'build', '--locked', '-p', 'nexus-boot', '--target', 'x86_64-unknown-uefi', '--features', 'hardening-tests']
    if args.release:
        cmd.append('--release')
    subprocess.run(cmd, check=True, cwd=ROOT, env=env)
    image = ROOT / 'target' / 'x86_64-unknown-uefi' / ('release' if args.release else 'debug') / 'bootx64.efi'
    out = ROOT / 'build' / f'hardening-{args.ram}-{args.cpu}-{"release" if args.release else "debug"}'
    out.mkdir(parents=True, exist_ok=True)
    boot = out / 'esp' / 'EFI' / 'BOOT'
    boot.mkdir(parents=True, exist_ok=True)
    shutil.copy2(image, boot / 'BOOTX64.EFI')
    serial_path = out / 'serial.log'
    qemu_log = out / 'qemu.log'
    if serial_path.exists():
        serial_path.unlink()
    cmd = [args.qemu, '-accel', 'tcg', '-cpu', args.cpu, '-m', str(args.ram), '-smp', '1', '-drive', f'if=pflash,format=raw,readonly=on,file={firmware}', '-drive', f'file=fat:rw:{boot.parents[1]},format=raw', '-kernel', str(image), '-display', 'none', '-serial', f'file:{serial_path}', '-monitor', 'none', '-net', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    source_hash = hashlib.sha256()
    paths = sorted([p for parent in ['crates', 'scripts', 'tests', '.github']
                    for p in (ROOT / parent).rglob('*') if p.is_file() and '__pycache__' not in str(p)]
                   + [ROOT / 'Cargo.toml', ROOT / 'Cargo.lock'])
    for path in paths:
        source_hash.update(str(path.relative_to(ROOT)).replace('\\', '/').encode())
        source_hash.update(path.read_bytes())
    result = {'started_at_utc': datetime.now(timezone.utc).isoformat(), 'host': platform.platform(),
              'rustc': subprocess.check_output(['rustc', '--version'], text=True).strip(),
              'ram_mb': args.ram, 'cpu': args.cpu, 'release': args.release, 'passed': False, 'command': cmd,
              'compiler': manifest['compiler'], 'fixture_manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(),
              'efi_sha256': hashlib.sha256(image.read_bytes()).hexdigest(),
              'firmware_sha256': hashlib.sha256(Path(firmware).read_bytes()).hexdigest(),
              'source_sha256': source_hash.hexdigest(),
              'qemu_version': subprocess.check_output([args.qemu, '--version'], text=True).splitlines()[0]}
    try:
        with qemu_log.open('wb') as log:
            completed = subprocess.run(cmd, stdout=log, stderr=log, timeout=args.timeout, cwd=ROOT)
        result['returncode'] = completed.returncode
        serial = serial_path.read_bytes().decode('utf-8', errors='replace') if serial_path.exists() else ''
        validate(completed.returncode, serial)
        if serial_path.read_bytes().count(b'\xff\x00\x7f') != 130:
            raise RuntimeError('Binary syscall output differs from 130 verified fixture writes')
        result['serial_sha256'] = hashlib.sha256(serial_path.read_bytes()).hexdigest()
        result['checks'] = sorted(CHECKS)
        result['phase3_outcomes_verified'] = True
        result['phase3_6_nt_driver_verified'] = True
        result['binary_writes_verified'] = 130
        stress = re.search(r'NEXUS_STRESS:cycles=(\d+):processes=(\d+):yields=(\d+):frames=(\d+):heap=(\d+)', serial)
        result['stress'] = dict(zip(['cycles', 'processes', 'yields', 'free_frames', 'heap_used_bytes'], map(int, stress.groups())))
        result['passed'] = True
        print(f'QEMU/OVMF assertions and exit status verified: RAM={args.ram} MiB CPU={args.cpu} release={args.release}')
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        result['error'] = str(error)
        print(f'FAIL: {error}. Inspect {serial_path} and {qemu_log}', file=sys.stderr)
        raise
    finally:
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
