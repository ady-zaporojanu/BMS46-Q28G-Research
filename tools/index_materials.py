"""Build firmware slice relationships and a readable XDF index for a local bundle.

Exact byte matching proves file correspondence only, not hardware compatibility.
XDF address checks cover embedded numeric ranges, not conversion correctness.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def write(path,obj):path.write_bytes((json.dumps(obj,ensure_ascii=False,indent=2)+'\n').encode())
def number(value):
    if value is None:return None
    try:return int(value,0)
    except ValueError:
        try:return int(value,10)
        except ValueError:return None


def main(root):
    catalog=root/'catalog';bins=json.loads((catalog/'firmware.json').read_text());xdfs=json.loads((catalog/'tunerpro.json').read_text())
    available=[r for r in bins if r['file']]
    fulls=[r for r in available if r['bytes']==262144]
    full_data={r['sha256']:(root/r['file']).read_bytes() for r in fulls}
    slices=[]
    for partial in available:
        if not 8192<=partial['bytes']<262144:continue
        data=(root/partial['file']).read_bytes()
        if len(set(data))<8:continue
        for full in fulls:
            address=full_data[full['sha256']].find(data)
            if address>=0:
                slices.append({'partial':partial['file'],'partial_sha256':partial['sha256'],'full':full['file'],'full_sha256':full['sha256'],'base_address':hex(address),'length':len(data),'evidence':'Exact contiguous byte equality; not inferred from filenames'})
    write(catalog/'full-partial-relationships.json',slices)
    audits=[]
    for row in xdfs:
        if not row['file'] or not row.get('xml_well_formed'):continue
        tree=ET.parse(root/row['file']);data=[]
        for node in tree.findall('.//EMBEDDEDDATA'):
            address=number(node.get('mmedaddress'));bits=number(node.get('mmedelementsizebits'))
            rows=number(node.get('mmedrowcount')) or 1;cols=number(node.get('mmedcolcount')) or 1
            if address is not None and bits:
                data.append((address,(bits*rows*cols+7)//8))
        base=tree.find('./XDFHEADER/BASEOFFSET');offset=number(base.get('offset')) if base is not None else 0
        subtract=number(base.get('subtract')) if base is not None else 0
        audit={'file':row['file'],'sha256':row['sha256'],'embedded_numeric_regions':len(data),'baseoffset':offset,'subtract':subtract,'max_raw_address_end':hex(max((a+n for a,n in data),default=0)),'note':'Syntactic address audit only. External links, strides, equations, axes and physical units require separate validation.'}
        audits.append(audit)
    write(catalog/'xdf-address-audit.json',audits)
    with (catalog/'tunerpro.csv').open('w',encoding='utf-8',newline='') as f:
        fields=['name','title','file_version','tables','constants','flags','xml_well_formed','file','sha256']
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(xdfs)
    lines=['# Firmware library','', 'Files are research inputs, not approved flash images. A 256 KiB size alone does not prove a complete physical read.','', '| File | Bytes | Shape | Identity strings | Status |','| --- | ---: | --- | --- | --- |']
    for r in bins:
        label=('['+r['name'].replace('|','/')+'](../'+r['file']+')') if r['file'] else r['name']+' (private hold)'
        lines.append(f"| {label} | {r['bytes']} | {r['shape']} | {', '.join(r['firmware_ids'])} | {r['disposition']} |")
    (catalog/'FIRMWARE.md').write_bytes(('\n'.join(lines)+'\n').encode())
    lines=['# TunerPro definitions (XDF / XML)','', 'All versions are indexed, including historical and experimental definitions. XML parsing is not a calibration validation.','', '| Definition | Version | Tables | Constants | XML |','| --- | --- | ---: | ---: | --- |']
    for r in xdfs:
        lines.append(f"| [{r.get('title') or r['name']}](../{r['file']}) | {r.get('file_version','')} | {r.get('tables','')} | {r.get('constants','')} | {r.get('xml_well_formed',False)} |")
    (catalog/'TUNERPRO.md').write_bytes(('\n'.join(lines)+'\n').encode())
    print('Indexed',len(bins),'firmware objects;',len(xdfs),'XDFs;',len(slices),'exact full/partial relationships')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);main(p.parse_args().root)
