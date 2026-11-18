"""Report annotation differences by stable record identity, without firmware."""
import argparse
import json
from pathlib import Path
from snapshot import read_rows


def key(row):
    if 'text' in row and 'type' in row: return (row['address'], row['type'])
    if 'namespace' in row and 'name' in row: return (row['address'], row['name'], row['namespace'])
    if 'category' in row: return (row['address'], row['type'], row['category'])
    return (row.get('address', row.get('start', row.get('path'))),)


def compare(before, after):
    changes = []
    names = sorted({p.name for d in (before, after) for p in d.glob('*.jsonl')})
    for name in names:
        def index(directory):
            path = directory / name
            rows = read_rows(path) if path.exists() else []
            result = {key(row): row for row in rows}
            if len(result) != len(rows): raise ValueError('Duplicate identities in ' + str(path))
            return result
        left, right = index(before), index(after)
        for identity in sorted(left.keys() | right.keys()):
            if left.get(identity) == right.get(identity): continue
            changes.append({'file': name, 'key': identity, 'before': left.get(identity), 'after': right.get(identity)})
    return changes


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('before', type=Path); p.add_argument('after', type=Path)
    args = p.parse_args()
    print(json.dumps(compare(args.before, args.after), indent=2, ensure_ascii=False))
