import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from collect_materials import collect, clean_name


class MaterialsTests(unittest.TestCase):
    def test_vin_in_underscored_filename_is_removed(self):
        identifier='WBA'+'12345678901234'
        self.assertNotIn(identifier,clean_name('read_'+identifier+'_partial.bin'))

    def test_dedup_private_binary_and_xml_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);src=root/'src';src.mkdir()
            (src/'a.bin').write_bytes(bytes(range(256))*128)
            (src/'b.bin').write_bytes((src/'a.bin').read_bytes())
            (src/'private.bin').write_bytes(b'WBA'+b'12345678901234'+bytes(40))
            (src/'map.xdf').write_text('<XDFFORMAT><XDFHEADER><deftitle>Test</deftitle></XDFHEADER><XDFTABLE/></XDFFORMAT>')
            out=root/'out';hold=root/'hold'
            collect({'output':str(out),'private_output':str(hold),'sources':[{'path':str(src),'alias':'test','category':'tests'}]})
            rows=json.loads((out/'catalog/objects.json').read_text())
            self.assertEqual(len(rows),3)
            held=[r for r in rows if r['disposition']=='PRIVATE_HOLD'];self.assertEqual(len(held),1)
            self.assertEqual(held[0]['file'],'');self.assertTrue((hold/held[0]['private_object']).exists())
            self.assertFalse(any((b'WBA'+b'12345678901234') in p.read_bytes() for p in out.rglob('*') if p.is_file()))
            xdf=next(r for r in rows if r['category']=='tunerpro')
            self.assertTrue(xdf['xml_well_formed']);self.assertEqual(xdf['tables'],1)

    def test_private_hold_cannot_be_nested_in_public_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError,'separate'):
                collect({'output':tmp,'private_output':str(Path(tmp)/'private'),'sources':[]})
