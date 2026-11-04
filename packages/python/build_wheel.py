#!/usr/bin/env python3
"""Builds a platform wheel holding the standalone fortis binary, so `pip install fortis-watchdog`
gives Python teams the CLI with no Node. A wheel is a zip file, so this needs only the standard
library. The binary goes in the wheel's scripts folder, which pip installs onto the venv's PATH.

    python build_wheel.py --binary dist-sea/fortis --platform manylinux_2_28_x86_64 --version 0.1.0-beta.9 --out out/
"""
import argparse
import base64
import hashlib
import re
import zipfile
from pathlib import Path

NAME = 'fortis-watchdog'
DIST = 'fortis_watchdog'
HERE = Path(__file__).resolve().parent


def pep440(version: str) -> str:
    """npm's 0.1.0-beta.9 is Python's 0.1.0b9."""
    match = re.fullmatch(r'(\d+\.\d+\.\d+)(?:-(alpha|beta|rc)\.(\d+))?', version)
    if not match:
        raise SystemExit(f'not a version this script understands: {version}')
    base, stage, number = match.groups()
    return base if not stage else f"{base}{ {'alpha': 'a', 'beta': 'b', 'rc': 'rc'}[stage] }{number}"


def record_line(path: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
    return f'{path},sha256={digest},{len(data)}'


def build(binary: Path, platform: str, version: str, out: Path) -> Path:
    py_version = pep440(version)
    dist_info = f'{DIST}-{py_version}.dist-info'
    script = f'{DIST}-{py_version}.data/scripts/{binary.name}'
    readme = (HERE / 'README.md').read_text(encoding='utf8')
    metadata = '\n'.join([
        'Metadata-Version: 2.1',
        f'Name: {NAME}',
        f'Version: {py_version}',
        'Summary: Fortis: fintech security checks on every push, for African fintech teams.',
        'Home-page: https://fortis.dev',
        'License: MIT',
        'Project-URL: Source, https://github.com/Divine-mercyx/fortis',
        'Requires-Python: >=3.8',
        'Description-Content-Type: text/markdown',
        '',
        readme,
    ])
    wheel = '\n'.join(['Wheel-Version: 1.0', 'Generator: fortis build_wheel.py', 'Root-Is-Purelib: false', f'Tag: py3-none-{platform}', ''])

    out.mkdir(parents=True, exist_ok=True)
    path = out / f'{DIST}-{py_version}-py3-none-{platform}.whl'
    binary_data = binary.read_bytes()
    entries = [
        (script, binary_data, 0o755),
        (f'{dist_info}/METADATA', metadata.encode(), 0o644),
        (f'{dist_info}/WHEEL', wheel.encode(), 0o644),
        (f'{dist_info}/licenses/LICENSE', (HERE.parent / 'cli' / 'LICENSE').read_bytes(), 0o644),
    ]
    record = [record_line(name, data) for name, data, _ in entries] + [f'{dist_info}/RECORD,,']
    entries.append((f'{dist_info}/RECORD', ('\n'.join(record) + '\n').encode(), 0o644))

    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100000 | mode) << 16
            zf.writestr(info, data)
    return path


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--platform', required=True, help='wheel platform tag, such as manylinux_2_28_x86_64')
    parser.add_argument('--version', required=True, help="the CLI's version, as in package.json")
    parser.add_argument('--out', type=Path, default=Path('out'))
    args = parser.parse_args()
    built = build(args.binary, args.platform, args.version, args.out)
    print(f'built {built} ({built.stat().st_size // 1024 // 1024} MB)')
