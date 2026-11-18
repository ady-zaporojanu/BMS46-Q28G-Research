"""Collect a configured local research library into a deduplicated REVIEW bundle.

Never publishes. Sources remain untouched. A private source-path manifest stays
outside the bundle. Firmware with recognizable VIN text is held separately,
without byte modification. XML/XDF are inventoried, not declared calibrated.
"""
import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

TEXT = {'.md','.txt','.py','.java','.ps1','.c','.h','.asm','.csv','.tsv','.json','.jsonl','.xml','.xdf','.xsd','.css','.html','.sinc','.slaspec','.ldefs','.cspec','.pspec','.ini','.cfg','.bat','.sh','.dot'}
BINARY = {'.bin','.ori','.kp','.a2l','.ols','.dam','.hex','.pdf','.png','.jpg','.jpeg','.svg','.gzf'}
SKIP_DIRS = {'.git','.venv','__pycache__','node_modules','deps','database','ghidra_home','ghidra_settings','baseline','previous_catalogs'}
VIN = re.compile(r'(?<![A-Z0-9])WB[AS][A-HJ-NPR-Z0-9]{14}(?![A-Z0-9])',re.I)
BIN_VIN = re.compile(rb'WB[AS][A-HJ-NPR-Z0-9]{14}',re.I)
ROM_SHA = 'd3c3abb5236240906a9d8851b31802e0751c233ebe0bba58d2c51f66e137679d'


def sha(data): return hashlib.sha256(data).hexdigest()
def write_json(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes((json.dumps(obj,ensure_ascii=False,indent=2)+'\n').encode())
def clean_name(name):
    name=VIN.sub('VEHICLE',name)
    return re.sub(r'[^A-Za-z0-9._-]+','_',name)[:120]
def csv_file(path,rows,fields):
    with path.open('w',newline='',encoding='utf-8') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields,extrasaction='ignore');writer.writeheader();writer.writerows(rows)


def collect(config):
    out=Path(config['output']).resolve();private=Path(config['private_output']).resolve()
    if out.is_relative_to(private) or private.is_relative_to(out):raise ValueError('Private hold and review bundle must be separate directory trees')
    for source in config['sources']:
        root=Path(source['path']).resolve()
        if root.is_dir() and (out.is_relative_to(root) or private.is_relative_to(root)):
            raise ValueError('Collection destinations cannot be inside a scanned source tree')
    if (out/'catalog/summary.json').exists():raise ValueError('Refusing to overwrite a completed collection')
    out.mkdir(parents=True,exist_ok=True);private.mkdir(parents=True,exist_ok=True)
    source_rows=[];objects={};excluded=[];original_paths=[]
    replacements=[]
    for source in config['sources']:
        raw=str(Path(source['path']).resolve())
        replacements.extend([(raw.replace('\\','\\\\'),source['alias']), (raw,source['alias']), (raw.replace('\\','/'),source['alias'])])
    replacements.sort(key=lambda x:len(x[0]),reverse=True)
    for old,new in config.get('redact_roots',{}).items():
        replacements.extend([(old.replace('\\','\\\\'),new),(old,new),(old.replace('\\','/'),new)])
    def sanitize(text):
        text=VIN.sub('[VEHICLE_ID_REDACTED]',text)
        for old,new in replacements:text=text.replace(old,new)
        return text
    for source in config['sources']:
        root=Path(source['path']).resolve()
        candidates=sorted(root.rglob('*')) if root.is_dir() else [root]
        for p in candidates:
            if not p.is_file():continue
            rel=p.relative_to(root).as_posix() if root.is_dir() else p.name
            alias=sanitize(source['alias']+'/'+rel)
            parts=p.relative_to(root).parts if root.is_dir() else (p.name,)
            if any(x in SKIP_DIRS or x.endswith('.rep') for x in parts):continue
            if source.get('include_tokens') and not any(t in p.name.lower() for t in source['include_tokens']):continue
            if source.get('exclude_parts') and any(x in source['exclude_parts'] for x in parts):continue
            ext=p.suffix.lower()
            if source.get('extensions') and ext not in source['extensions']:continue
            if ext not in TEXT|BINARY and p.name not in {'LICENSE','NOTICE','ecuBMW46'}:continue
            size=p.stat().st_size
            if size>64*1024*1024:
                excluded.append({'source':alias,'bytes':size,'reason':'Large generated artifact; indexed, not copied. Recreate with historical scripts.'});continue
            data=p.read_bytes();digest=sha(data)
            original_paths.append({'source':str(p),'source_sha256':digest})
            if digest not in objects:
                is_bin=ext in {'.bin','.ori'} or p.name=='ecuBMW46'
                sensitive=is_bin and (BIN_VIN.search(data) or VIN.search(data.decode('utf-16le',errors='ignore')))
                distributed=data;sanitized=False
                if ext in TEXT or p.name in {'LICENSE','NOTICE'}:
                    try:
                        text=data.decode('utf-8-sig');new=sanitize(text)
                        if new!=text:distributed=new.encode('utf-8');sanitized=True
                    except UnicodeDecodeError:
                        pass
                category=('firmware' if is_bin else 'tunerpro' if ext=='.xdf' else 'firmware-metadata' if source['category']=='firmware' else source['category'])
                filename=digest[:12]+'_'+clean_name(p.name)
                target=Path('library')/category/filename
                disposition='PRIVATE_HOLD' if sensitive else 'REVIEW_CANDIDATE'
                dest=(private if sensitive else out)/target
                dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(distributed)
                row={'source_sha256':digest,'sha256':sha(distributed),'bytes':size,'distributed_bytes':len(distributed),'name':sanitize(p.name),'category':category,'file':target.as_posix() if not sensitive else '', 'private_object':target.as_posix() if sensitive else '', 'disposition':disposition,'text_redacted':sanitized,'origin':source['alias'],'license_status':source.get('license_status','NOT_ESTABLISHED_FOR_REDISTRIBUTION')}
                if is_bin:
                    row['shape']='full_256KiB' if size==262144 else 'partial_32KiB' if size==32768 else 'other_size_do_not_assume_full'
                    row['canonical_q28g']=digest==ROM_SHA
                    row['firmware_ids']=sorted(set(m.decode() for m in re.findall(rb'01119700[A-Z0-9]{8}',data)))
                    row['modified_name_hint']=bool(re.search('patch|pops|flame|hardcut|limiter|stage|live_v|modif',p.name,re.I))
                    row['flash_approval']='NONE_RESEARCH_ONLY'
                if ext=='.xdf':
                    try:
                        xml=ET.fromstring(data)
                        row['xml_root']=xml.tag;row['xml_well_formed']=True
                        row['title']=sanitize(xml.findtext('./XDFHEADER/deftitle',''))
                        row['file_version']=xml.findtext('./XDFHEADER/fileversion','')
                        row['baseoffset']=[x.attrib for x in xml.findall('./XDFHEADER/BASEOFFSET')]
                        row['regions']=[x.attrib for x in xml.findall('./XDFHEADER/REGION')]
                        row['tables']=len(xml.findall('XDFTABLE'));row['constants']=len(xml.findall('XDFCONSTANT'));row['flags']=len(xml.findall('XDFFLAG'))
                        row['validation']='XML_PARSE_ONLY_NOT_A_MAP_SEMANTICS_OR_TUNERPRO_TEST'
                    except ET.ParseError as exc:row['xml_well_formed']=False;row['parse_error']=str(exc)
                objects[digest]=row
            source_rows.append({'source':alias,'source_sha256':digest,'file':objects[digest]['file'],'disposition':objects[digest]['disposition']})
    rows=list(objects.values())
    write_json(private/'original-paths.json',original_paths)
    finalize_catalog(out,rows,source_rows,excluded)


def finalize_catalog(out,rows,source_rows,excluded):
    catalog=out/'catalog';catalog.mkdir(exist_ok=True)
    write_json(catalog/'objects.json',rows)
    write_json(catalog/'sources.json',source_rows)
    write_json(catalog/'excluded.json',excluded)
    csv_file(catalog/'files.csv',rows,['category','name','file','bytes','source_sha256','sha256','disposition','text_redacted','license_status'])
    bins=[x for x in rows if x['category']=='firmware']
    xdfs=[x for x in rows if x['category']=='tunerpro']
    write_json(catalog/'firmware.json',bins);write_json(catalog/'tunerpro.json',xdfs)
    summary={'source_occurrences':len(source_rows),'unique_objects':len(rows),'review_candidate_objects':sum(r['disposition']=='REVIEW_CANDIDATE' for r in rows),'private_hold_objects':sum(r['disposition']=='PRIVATE_HOLD' for r in rows),'candidate_bytes':sum(r['distributed_bytes'] for r in rows if r['file']),'categories':dict(collections.Counter(r['category'] for r in rows)),'firmware_shapes':dict(collections.Counter(r['shape'] for r in bins)),'xdf_xml_ok':sum(r.get('xml_well_formed',False) for r in xdfs),'excluded_large_generated':len(excluded)}
    write_json(catalog/'summary.json',summary)
    print(json.dumps(summary,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',type=Path,required=True)
    args=parser.parse_args();collect(json.loads(args.config.read_text(encoding='utf-8-sig')))
