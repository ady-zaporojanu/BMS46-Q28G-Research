"""Package a reviewed local companion collection, never the private hold folder.

This creates an offline review asset; it does not assert redistribution rights
or publish anything. Verify each catalogued object's distributed SHA first.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile


def file_hash(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def package(root,output,ready_only=False):
    root=root.resolve();output=output.resolve()
    if output.is_relative_to(root):raise ValueError('Archive must be outside the collection')
    if output.exists():raise ValueError('Refusing to overwrite archive')
    if not ready_only:
        for row in json.loads((root/'catalog/objects.json').read_text()):
            if not row['file']:continue
            p=(root/row['file']).resolve()
            if not p.is_relative_to(root) or file_hash(p)!=row['sha256']:
                raise ValueError('Object path/hash failure: '+row['file'])
    allowed={'ghidra','toolkit','catalog','library','README.md','START_HERE_RO.md','PUBLICATION_REVIEW.md'}
    files=[]
    for p in root.rglob('*'):
        rel=p.relative_to(root)
        if p.is_symlink():raise ValueError('Symlink refused')
        if not p.is_file():continue
        if rel.parts[0] not in allowed:raise ValueError('Unexpected bundle file: '+str(rel))
        if 'original-paths.json' in rel.parts or 'private-hold' in rel.parts:raise ValueError('Private material refused')
        if ready_only and rel.parts[0] not in {'ghidra','toolkit','README.md','START_HERE_RO.md','PUBLICATION_REVIEW.md'}:continue
        files.append(p)
    manifest=[]
    output.parent.mkdir(parents=True,exist_ok=True)
    prefix='bms46-ghidra-ready' if ready_only else 'bms46-community-materials'
    with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6,allowZip64=True) as archive:
        for p in sorted(files):
            name=p.relative_to(root).as_posix()
            manifest.append(file_hash(p)+'  '+name)
            archive.write(p,prefix+'/'+name)
        archive.writestr(prefix+'/MANIFEST.sha256','\n'.join(manifest)+'\n')
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:raise ValueError('ZIP integrity failure')
    digest=file_hash(output)
    output.with_suffix(output.suffix+'.sha256').write_text(digest+'  '+output.name+'\n')
    print(json.dumps({'archive':output.name,'files':len(files)+1,'bytes':output.stat().st_size,'sha256':digest,'status':'VERIFIED_REVIEW_ASSET_NOT_PUBLISHED'},indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('--output',type=Path,required=True);p.add_argument('--ready-only',action='store_true')
    a=p.parse_args();package(a.root,a.output,a.ready_only)
