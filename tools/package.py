"""Build a source-only ZIP using an allowlist; never zip the workspace recursively."""
import argparse
import hashlib
from pathlib import Path
import zipfile
from validate import ROOT, public_files, validate


def package(output, root=ROOT):
    validate(root)
    if output.exists(): raise ValueError('Refuse to overwrite an existing release archive')
    files = public_files(root)
    entries = [(p.relative_to(root).as_posix(), p.read_bytes()) for p in files]
    manifest = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n' for name, data in entries)
    entries.append(('MANIFEST.sha256', manifest.encode('utf-8')))
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in entries:
            info = zipfile.ZipInfo('bms46-q28g-research/' + name, date_time=(2026,11,18,0,0,0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None: raise ValueError('Archive integrity failure')
        for name, data in entries:
            if archive.read('bms46-q28g-research/' + name) != data: raise ValueError('Archive content mismatch')
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + '.sha256').write_text(digest + '  ' + output.name + '\n')
    print(f'PASS: {len(entries)} source files, {output.stat().st_size} bytes, SHA256 {digest}')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    package(args.output.resolve())
