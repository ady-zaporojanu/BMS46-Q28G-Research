"""Create a deterministic, byte-free collaboration snapshot from a PRIVATE Ghidra export.

The private exporter contains firmware: keep its output outside Git. This converter
uses field allowlists rather than copying entire export records.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

SHA256 = 'd3c3abb5236240906a9d8851b31802e0751c233ebe0bba58d2c51f66e137679d'
LANGUAGE = '68000:BE:32:CPU32_STATUS_V2'
FIELDS = {
    'memory': 'name start end size initialized read write execute volatile',
    'comments': 'address type text',
    'symbols': 'address name type source namespace primary',
    'functions': 'address end body_ranges size current_name namespace source prototype signature_source is_thunk no_return comment repeatable_comment variables',
    'datatypes': 'path kind length description components definition',
    'defined_data': 'address end length datatype components',
    'bookmarks': 'address type category comment',
    'all_instructions': 'address length',
}


def read_rows(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8-sig').splitlines() if line.strip()]


def write_rows(path, rows):
    rows = sorted(rows, key=lambda row: (row.get('address', row.get('start', row.get('path', ''))), json.dumps(row, sort_keys=True)))
    path.write_bytes(''.join(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n' for row in rows).encode('utf-8'))


def reject_private(text):
    if re.search(r'(?i)[a-z]:[\\/]|/home/|/Users/|\bWBA[A-Z0-9]{14}\b|\bWBS[A-Z0-9]{14}\b', text):
        raise ValueError('Local path or VIN found: review/redact the source record before export')


def convert(source, output, overrides):
    # Verify the private export belongs to the exact image; do not infer identity
    # from a user-supplied filename or an earlier project's metadata.
    rom = (source / 'rom_readback.bin').read_bytes()
    if len(rom) != 262144 or hashlib.sha256(rom).hexdigest() != SHA256:
        raise ValueError('Canonical firmware SHA-256/size mismatch')
    program = read_rows(source / 'program.jsonl')[0]
    if LANGUAGE not in json.dumps(program):
        raise ValueError('Wrong processor language in private export')
    if output.exists() and any(output.iterdir()):
        raise ValueError('Output must be empty: export changes to a new directory, then review the diff')
    prepared = {}
    for name, fields in FIELDS.items():
        rows = [{key: row[key] for key in fields.split() if key in row} for row in read_rows(source / (name + '.jsonl'))]
        if name == 'symbols':
            rows = [r for r in rows if r['type'] == 'Label' and r['namespace'] == 'Global' and r['source'] != 'DEFAULT' and re.fullmatch('[0-9a-fA-F]+', r['address'])]
        reject_private(json.dumps(rows))
        prepared[name] = rows
    flow = json.loads(overrides.read_text(encoding='utf-8-sig'))
    reject_private(json.dumps(flow))
    output.mkdir(parents=True, exist_ok=True)
    for name, rows in prepared.items():
        write_rows(output / (name + '.jsonl'), rows)
    write_rows(output / 'flow_overrides.jsonl', flow)
    metadata = {'schema': 1, 'firmware_id': '01119700F000Q28G', 'rom_size': 262144, 'rom_sha256': SHA256, 'image_base': '00000000', 'language': LANGUAGE, 'ghidra_version': '12.1.2', 'counts': {name: len(rows) for name, rows in prepared.items()}, 'flow_overrides': len(flow)}
    (output / 'manifest.json').write_bytes((json.dumps(metadata, indent=2) + '\n').encode('utf-8'))
    print(json.dumps(metadata, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-export', type=Path, required=True)
    parser.add_argument('--overrides', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    convert(args.private_export, args.output, args.overrides)
