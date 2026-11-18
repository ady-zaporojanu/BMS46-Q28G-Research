"""Guard the public material inventory, byte integrity and source-only boundary."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from validate_materials import validate_materials
from validate import public_files


class PublishedMaterialsTests(unittest.TestCase):
    def seed(self, root):
        name = 'materials/library/firmware/example.bin'
        path = root / name
        path.parent.mkdir(parents=True)
        path.write_bytes(b'\x00ROM\xff')
        (root/'research').mkdir()
        rows = [{'file': name, 'bytes': 5, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}]
        self.save(root, rows)
        return path, rows

    def save(self, root, rows):
        (root/'research/materials-manifest.json').write_text(json.dumps({'schema': 1, 'files': rows}))

    def test_dataset_validated_but_excluded_from_source_package(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); self.seed(root)
            self.assertEqual(validate_materials(root), 1)
            self.assertEqual([p.name for p in public_files(root)], ['materials-manifest.json'])

    def test_changed_binary_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); path, _ = self.seed(root)
            path.write_bytes(b'\x00BAD\xff')
            with self.assertRaisesRegex(ValueError, 'integrity mismatch'): validate_materials(root)

    def test_undeclared_file_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); path, _ = self.seed(root)
            path.with_name('unexpected.bin').write_bytes(b'other')
            with self.assertRaisesRegex(ValueError, 'inventory mismatch'): validate_materials(root)

    def test_partial_dataset_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); path, _ = self.seed(root); path.unlink()
            with self.assertRaisesRegex(ValueError, 'inventory mismatch'): validate_materials(root)

    def test_manifest_cannot_whitelist_outside_dataset(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); _, rows = self.seed(root)
            for name in ['materials/../private.bin', '/materials/a.bin', 'materials/C:/a.bin', 'materials\\a.bin', 'materials/a.exe']:
                rows[0]['file'] = name; self.save(root, rows)
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'Invalid material path'):
                    validate_materials(root)

    def test_missing_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); self.seed(root); (root/'research/materials-manifest.json').unlink()
            with self.assertRaisesRegex(ValueError, 'without an integrity manifest'): validate_materials(root)


if __name__ == '__main__': unittest.main()
