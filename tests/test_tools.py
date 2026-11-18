"""Regression tests for wrong-image refusal, privacy boundaries and merge handling."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from ghidra_project import check_rom
from snapshot import reject_private, write_rows
from diff_snapshot import compare
from validate import public_files, validate_snapshot, ROOT


class ToolsTests(unittest.TestCase):
    def test_wrong_rom_refused_even_at_correct_size(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'input.bin'; p.write_bytes(bytes(262144))
            with self.assertRaisesRegex(ValueError, 'Wrong firmware'): check_rom(p)

    def test_private_fields_refused(self):
        for value in ('C:' + chr(92) + 'private' + chr(92) + 'file', 'WBA' + '12345678901234'):
            with self.assertRaises(ValueError): reject_private(value)
        reject_private('Fan request at 0xFF8804; ID 0x0615; units unresolved')

    def test_diff_distinguishes_comment_types_and_changes(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d)/'a', Path(d)/'b'; a.mkdir(); b.mkdir()
            rows = [{'address':'00000400','type':'PRE','text':'old'}, {'address':'00000400','type':'EOL','text':'same'}]
            write_rows(a/'comments.jsonl', rows)
            rows[0]['text'] = 'new'; write_rows(b/'comments.jsonl', rows)
            changes = compare(a,b)
            self.assertEqual(len(changes),1); self.assertEqual(changes[0]['key'],('00000400','PRE'))

    def test_conflicting_comment_identity_is_not_silently_merged(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d)/'a', Path(d)/'b'; a.mkdir(); b.mkdir()
            write_rows(a/'comments.jsonl',[{'address':'00000400','type':'PRE','text':x} for x in ('first','second')])
            with self.assertRaisesRegex(ValueError,'Duplicate'): compare(a,b)

    def test_package_file_selection_rejects_firmware(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'research').mkdir(); (root/'research/firmware.bin').write_bytes(b'ROM')
            with self.assertRaisesRegex(ValueError,'Non-source'): public_files(root)

    def test_private_build_artifacts_are_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'local-work').mkdir(); (root/'local-work/rom.bin').write_bytes(b'ROM')
            (root/'README.md').write_text('research')
            self.assertEqual([p.name for p in public_files(root)],['README.md'])

    def test_current_snapshot_consistent(self):
        self.assertEqual(validate_snapshot(ROOT/'annotations/q28g'),[])


if __name__ == '__main__': unittest.main()
