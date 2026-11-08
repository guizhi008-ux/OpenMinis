#!/usr/bin/env python3
"""Apply the guest-only adapter to the exact audited iSH source revision."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
PIN = '0fd17a135e78b7a0cf08a4f5831217bbb76ed22f'

def apply(root, verify_git=True):
    root = Path(root).resolve()
    if verify_git:
        revision = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
        if revision != PIN:
            raise SystemExit('Guest proxy requires iSH commit ' + PIN)
    # Both dry runs avoid partially editing an incompatible source tree.
    patch = (HERE / 'guest.patch').read_bytes()
    check = subprocess.run(['patch', '-p1', '--dry-run', '--silent', '--forward'], cwd=root, input=patch, capture_output=True)
    if check.returncode:
        reverse = subprocess.run(['patch', '-p1', '--dry-run', '--silent', '--reverse'], cwd=root, input=patch, capture_output=True)
        if reverse.returncode:
            raise SystemExit('iSH guest proxy patch does not match source; refusing partial application')
    else:
        for name, expected in json.loads((HERE / 'pinned-files.json').read_text()).items():
            if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
                raise SystemExit('Pinned iSH source fingerprint differs: ' + name)
        subprocess.run(['patch', '-p1', '--batch', '--forward'], cwd=root, input=patch, check=True)
    for name in ('ish_proxy.c', 'ish_proxy.h'):
        shutil.copyfile(HERE / name, root / 'fs' / name)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: apply.py ISH_SOURCE')
    apply(sys.argv[1])
