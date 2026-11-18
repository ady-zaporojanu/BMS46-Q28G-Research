"""Offline validation: no ROM, Ghidra, network or third-party Python packages needed."""
import argparse
import json
import re
from pathlib import Path
from snapshot import FIELDS, LANGUAGE, SHA256, read_rows
from validate_materials import validate_materials

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_DIRS = {'.github', 'annotations', 'docs', 'extension', 'ghidra_scripts', 'licenses', 'research', 'tests', 'tools'}
PUBLIC_FILES = {'README.md', 'README.ro.md', 'LICENSE', 'NOTICE.md', 'CONTRIBUTING.md', 'CHANGELOG.md', '.gitignore', '.gitattributes', '.editorconfig', 'requirements-native.txt'}
LOCAL_DIRS = {'.git', '.local', 'local-work', '.venv', '__pycache__'}
TEXT_SUFFIXES = {'.md', '.txt', '.json', '.jsonl', '.csv', '.py', '.java', '.sinc', '.slaspec', '.cspec', '.pspec', '.ldefs', '.properties', '.manifest', '.yml'}


def public_files(root=ROOT):
    """Fail closed on unexpected files; ignore only explicit local directories."""
    result = []
    for p in root.rglob('*'):
        rel = p.relative_to(root)
        if rel.as_posix() == 'MANIFEST.sha256':
            continue  # Generated source-archive checksum list, not a source input.
        if rel.parts[0] in LOCAL_DIRS or '__pycache__' in rel.parts:
            continue
        if rel.parts[0] == 'materials':
            continue  # Separate manifest-verified dataset, never part of source-only packaging.
        if p.is_symlink():
            raise ValueError(f'Symlink cannot enter source package: {rel}')
        if not p.is_file():
            continue
        if rel.parts[0] not in PUBLIC_DIRS and str(rel) not in PUBLIC_FILES:
            raise ValueError(f'Unexpected public file: {rel}')
        if rel.parts[0] in PUBLIC_DIRS and p.suffix not in TEXT_SUFFIXES:
            raise ValueError(f'Non-source extension: {rel}')
        p.read_text(encoding='utf-8-sig')  # Refuse undecodable binary files.
        if b'\0' in p.read_bytes():
            raise ValueError(f'Binary NUL bytes: {rel}')
        result.append(p)
    return sorted(result)


def validate_snapshot(directory):
    errors = []
    manifest = json.loads((directory / 'manifest.json').read_text())
    if manifest.get('rom_sha256') != SHA256 or manifest.get('rom_size') != 262144 or manifest.get('language') != LANGUAGE or manifest.get('image_base') != '00000000':
        errors.append('Canonical identity/language/base mismatch')
    all_rows = {}
    for name, fields in FIELDS.items():
        rows = read_rows(directory / (name + '.jsonl'))
        all_rows[name] = rows
        if len(rows) != manifest['counts'].get(name):
            errors.append(f'{name}: manifest count mismatch')
        for row in rows:
            if set(row) - set(fields.split()):
                errors.append(f'{name}: unexpected fields')
            if 'address' in row and not re.fullmatch('[0-9a-f]{8}', row['address']):
                errors.append(f'{name}: invalid address')
        keys = []
        for r in rows:
            if name == 'comments': key = (r['address'], r['type'])
            elif name == 'symbols': key = (r['address'], r['name'], r['namespace'])
            elif name == 'bookmarks': key = (r['address'], r['type'], r['category'])
            else: key = r.get('address', r.get('start', r.get('path')))
            keys.append(key)
        if len(keys) != len(set(keys)):
            errors.append(f'{name}: duplicate record identity')
    memory = all_rows['memory']
    def mapped(address):
        return any(int(m['start'],16) <= address <= int(m['end'],16) for m in memory)
    for name in ('comments', 'symbols', 'defined_data', 'functions', 'bookmarks'):
        for row in all_rows[name]:
            if not mapped(int(row['address'],16)):
                errors.append(f'{name}: unmapped address {row["address"]}')
    previous_end = -1
    starts = set()
    for row in sorted(all_rows['all_instructions'], key=lambda r: r['address']):
        address, length = int(row['address'],16), row['length']
        starts.add(row['address'])
        if not (address % 2 == 0 and length > 0 and length % 2 == 0 and address > previous_end and address + length <= 262144):
            errors.append(f'Overlapping/out-of-range instruction {row["address"]}')
        previous_end = address + length - 1
    for row in all_rows['functions']:
        if row['address'] not in starts:
            errors.append(f'Function does not start at instruction: {row["address"]}')
        if not re.fullmatch(r'\[\[[0-9a-f]{8}, [0-9a-f]{8}\](?:\s+\[[0-9a-f]{8}, [0-9a-f]{8}\])*\]', row['body_ranges']):
            errors.append(f'Malformed function body: {row["address"]}')
    for row in all_rows['comments']:
        if row['type'] not in {'EOL','PRE','POST','PLATE','REPEATABLE'}:
            errors.append('Unknown comment kind')
    overrides = read_rows(directory / 'flow_overrides.jsonl')
    if len(overrides) != manifest['flow_overrides']:
        errors.append('Flow override count mismatch')
    for row in overrides:
        if row['address'] not in starts or row['override'] not in {'CALL','CALL_RETURN','BRANCH','RETURN'}:
            errors.append('Invalid flow override')
    return errors


def validate(root=ROOT):
    validate_materials(root)
    files = public_files(root)
    errors = validate_snapshot(root / 'annotations/q28g')
    for p in files:
        text = p.read_text(encoding='utf-8-sig')
        if re.search(r'(?i)\bWB[AS][A-Z0-9]{14}\b|[a-z]:[\\/]+Users[\\/]+[^\\/\s]+|/home/[a-z0-9_-]+/|-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----', text):
            errors.append(f'Possible private identity/path/credential: {p.relative_to(root)}')
        if p.suffix == '.md':
            for link in re.findall(r'\]\(([^)]+)\)', text):
                if '://' in link or link.startswith('#'):
                    continue
                target = (p.parent / link.split('#')[0]).resolve()
                if not target.exists():
                    material_root = (root / 'materials').resolve()
                    if not material_root.exists() and material_root in target.parents:
                        continue  # Source-only archive references the companion dataset.
                    errors.append(f'Broken local Markdown link in {p.relative_to(root)}: {link}')
    if errors:
        raise ValueError('\n'.join(errors[:30]))
    return len(files)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    print(f'PASS: {validate(args.root)} public source files and {validate_materials(args.root)} material files; identity, structure, links and integrity checks')
