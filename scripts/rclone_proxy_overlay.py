#!/usr/bin/env python3
"""Generate a hash-locked Go overlay for the single pinned rclone dialer.

Run from deps/rclone-mobile, then pass both -modfile=<output>/go.mod and
-overlay=<output>/overlay.json to Go.
The module cache remains untouched. An rclone upgrade requires explicit review.
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import shutil

VERSION = 'v1.75.0'
SHA256 = '994b3ff14a3db6d9f3dba5172b111d84be367bfc4405964472df69fb7a8e7cb6'
IMPORT = '\t"github.com/OpenMinis/minis-rclone/routepolicy"\n'
ORIGINAL = '\tc, err := d.Dialer.DialContext(ctx, network, address)'
REPLACEMENT = '''\tc, handled, err := routepolicy.DialContext(ctx, network, address)
\tif !handled {
\t\tc, err = d.Dialer.DialContext(ctx, network, address)
\t}'''


def generate(source, output):
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHA256:
        raise ValueError('rclone dialer hash mismatch: review pinned upstream before building')
    text = raw.decode()
    if text.count(ORIGINAL) != 1 or text.count('import (\n') != 1:
        raise ValueError('rclone dialer injection point changed')
    output.mkdir(parents=True, exist_ok=True)
    replacement = (output / 'dialer.go').resolve()
    text = text.replace('import (\n', 'import (\n' + IMPORT, 1).replace(ORIGINAL, REPLACEMENT, 1)
    text = text.replace('type Dialer struct {', 'func init() { routepolicy.MarkInstalled() }\n\ntype Dialer struct {', 1)
    replacement.write_text(text)
    manifest = (output / 'overlay.json').resolve()
    manifest.write_text(json.dumps({'Replace': {str(source.absolute()): str(replacement)}}, indent=2) + '\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    # go list checks the module selected by go.mod rather than guessing a cache path.
    module = json.loads(subprocess.check_output(['go', 'list', '-m', '-json', 'github.com/rclone/rclone']))
    if module.get('Version') != VERSION or module.get('Replace'):
        raise ValueError('rclone version/replacement mismatch: expected unmodified ' + VERSION)
    source = pathlib.Path(module['Dir']).resolve()
    output = args.output.resolve()
    # Go forbids overlays beneath GOMODCACHE. Stage a disposable source copy;
    # only the hash-verified dialer is replaced by the overlay below.
    view = output / 'rclone'
    if hashlib.sha256((source / 'fs/fshttp/dialer.go').read_bytes()).hexdigest() != SHA256:
        raise ValueError('rclone dialer hash mismatch: review pinned upstream before building')
    if view.exists():
        shutil.rmtree(view)
    shutil.copytree(source, view)
    modfile = pathlib.Path('go.mod').read_text()
    (output / 'go.mod').write_text(modfile + '\nreplace github.com/rclone/rclone => ' + json.dumps(str(view)) + '\n')
    shutil.copyfile('go.sum', output / 'go.sum')
    print(generate(view / 'fs/fshttp/dialer.go', output))


if __name__ == '__main__':
    main()
