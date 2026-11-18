"""Validate the explicitly published dataset without broadening source packaging."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

MATERIAL_SUFFIXES = {'.bin', '.xdf', '.xml', '.css', '.xsd', '.kp', '.ols',
                     '.gzf', '.json', '.csv', '.md', '.txt'}


def validate_materials(root):
    root = Path(root)
    manifest_path = root / 'research/materials-manifest.json'
    directory = root / 'materials'
    if not manifest_path.exists():
        if directory.exists():
            raise ValueError('Materials exist without an integrity manifest')
        return 0  # The source-only distribution intentionally omits the dataset.
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if manifest.get('schema') != 1 or not isinstance(manifest.get('files'), list):
        raise ValueError('Unsupported materials manifest')
    expected = {}
    for row in manifest['files']:
        name = row['file']
        path = PurePosixPath(name)
        if (path.is_absolute() or '..' in path.parts or '\\' in name
                or ':' in name or len(path.parts) < 2 or path.parts[0] != 'materials'
                or path.as_posix() != name
                or (path.suffix.lower() not in MATERIAL_SUFFIXES
                    and not (path.suffix == '' and path.parts[:3] == ('materials', 'library', 'firmware')))):
            raise ValueError('Invalid material path: ' + name)
        if name in expected:
            raise ValueError('Duplicate material: ' + name)
        if not re.fullmatch('[0-9a-f]{64}', row['sha256']) or not isinstance(row['bytes'], int) or row['bytes'] < 0:
            raise ValueError('Invalid material hash or size: ' + name)
        expected[name] = row
    if not directory.exists():
        return 0  # Source archive includes provenance but not the separate material files.
    if directory.is_symlink():
        raise ValueError('Material directory must not be a symlink')
    actual = {}
    for path in directory.rglob('*'):
        if path.is_symlink():
            raise ValueError('Material symlink: ' + str(path))
        if path.is_file():
            actual[path.relative_to(root).as_posix()] = path
    if set(actual) != set(expected):
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        raise ValueError(f'Material inventory mismatch: missing={missing[:5]}, unexpected={extra[:5]}')
    for name, path in actual.items():
        data = path.read_bytes()
        row = expected[name]
        if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('Material integrity mismatch: ' + name)
        if len(data) >= 100 * 1024 * 1024:
            raise ValueError('Material exceeds normal Git file limit: ' + name)
        if path.suffix.lower() == '.md':
            for link in re.findall(r'\]\(([^)]+)\)', data.decode('utf-8-sig')):
                if '://' not in link and not link.startswith('#'):
                    if not (path.parent / link.split('#')[0]).resolve().exists():
                        raise ValueError('Broken material Markdown link: ' + name + ': ' + link)
    return len(actual)
