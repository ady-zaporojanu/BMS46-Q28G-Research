"""Build a NEW Ghidra research project. Never opens a vehicle interface.

Runs the pinned Ghidra distribution with argument arrays, never a shell command.
An existing project is refused. Failure artifacts remain in local-work for inspection.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from snapshot import SHA256, convert


def check_rom(path):
    data = path.read_bytes()
    if len(data) != 262144 or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('Wrong firmware: expected canonical 262144-byte Q28G image and SHA-256 in README')


def java_prefix(ghidra, java_home):
    props = (ghidra / 'Ghidra/application.properties').read_text()
    if 'application.version=12.1.2\n' not in props:
        raise ValueError('Use Ghidra 12.1.2 for this reproducible baseline')
    binary = 'java.exe' if os.name == 'nt' else 'java'
    java = str(Path(java_home) / 'bin' / binary) if java_home else shutil.which('java')
    if not java:
        raise ValueError('Set JAVA_HOME or pass --java-home to a supported JDK')
    return [java, '-Djava.system.class.loader=ghidra.GhidraClassLoader', '-Dfile.encoding=UTF8', '--enable-native-access=ALL-UNNAMED', '-Xmx2G', '-cp', str(ghidra / 'Ghidra/Framework/Utility/lib/Utility.jar'), 'ghidra.Ghidra']


def run_logged(command, log, marker=None):
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open('w', encoding='utf-8') as stream:
        result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=900, check=False)
    text = log.read_text(encoding='utf-8', errors='replace')
    if result.returncode or (marker and marker not in text):
        print(text[-7000:], file=sys.stderr)
        raise RuntimeError(f'Ghidra failed; inspect private log: {log}')


def install(ghidra, java_home):
    source = ROOT / 'extension/BMS46_CPU32_Status_V2'
    target = ghidra / 'Ghidra/Extensions/BMS46_CPU32_Status_V2'
    # Preflight every existing source file before creating anything. Never replace
    # a different custom language or overwrite a built-in processor definition.
    files = [p for p in source.rglob('*') if p.is_file()]
    for p in files:
        dest = target / p.relative_to(source)
        if dest.exists() and dest.read_bytes() != p.read_bytes():
            raise ValueError(f'Conflicting extension file; use a separate Ghidra installation: {dest}')
    for p in files:
        dest = target / p.relative_to(source)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists():
            shutil.copyfile(p, dest)
    language = target / 'data/languages'
    run_logged(java_prefix(ghidra, java_home) + ['ghidra.pcodeCPort.slgh_compile.SleighCompileLauncher', str(language / 'CPU32.slaspec'), str(language / 'CPU32.sla')], ROOT / 'local-work/sleigh.log')
    if not (language / 'CPU32.sla').is_file():
        raise RuntimeError('Language compilation produced no SLA')
    print('Installed isolated CPU32_STATUS_V2 language; restart Ghidra if it was open.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check-rom', 'install-language', 'build', 'export'])
    parser.add_argument('--ghidra-home', type=Path, default=os.environ.get('GHIDRA_HOME'))
    parser.add_argument('--java-home', default=os.environ.get('JAVA_HOME'))
    parser.add_argument('--rom', type=Path)
    parser.add_argument('--project-dir', type=Path, default=ROOT / 'local-work/projects')
    parser.add_argument('--project-name', default='Q28G_Research')
    parser.add_argument('--program', help='Exact imported program name (export only)')
    parser.add_argument('--output', type=Path, help='New public snapshot directory (export only)')
    args = parser.parse_args()
    if args.action in ('check-rom', 'build'):
        if not args.rom: parser.error('--rom is required')
        check_rom(args.rom)
    if args.action == 'check-rom':
        print('PASS: canonical firmware identity and size'); return
    if not args.ghidra_home: parser.error('--ghidra-home or GHIDRA_HOME is required')
    ghidra = args.ghidra_home.resolve()
    if args.action == 'install-language':
        install(ghidra, args.java_home); return
    if not args.project_name.replace('_', '').replace('-', '').isalnum():
        parser.error('Use letters, digits, underscores or hyphens for the project name')
    directory = args.project_dir.resolve()
    if args.action == 'export':
        if not args.program or args.program.startswith('-') or not args.output:
            parser.error('export requires --program and --output')
        if not (directory / (args.project_name + '.gpr')).is_file():
            raise ValueError('Existing source project not found')
        if args.output.exists() and any(args.output.iterdir()):
            raise ValueError('Export output must be a new/empty directory')
        private_parent = ROOT / 'local-work/private-exports'
        private_parent.mkdir(parents=True, exist_ok=True)
        private = Path(tempfile.mkdtemp(prefix='export-', dir=private_parent))
        command = java_prefix(ghidra, args.java_home) + [
            'ghidra.app.util.headless.AnalyzeHeadless', str(directory), args.project_name,
            '-process', args.program, '-readOnly', '-noanalysis',
            '-scriptPath', str(ROOT / 'ghidra_scripts'),
            '-postScript', 'ExportPrivateEvidence.java', str(private / 'raw'),
            '-postScript', 'ExportFlowOverrides.java', str(private / 'flow.json'),
        ]
        run_logged(command, private / 'export.log', 'BMS46_READ_ONLY_SNAPSHOT_COMPLETE')
        programs = list((private / 'raw').rglob('program.jsonl'))
        if len(programs) != 1 or not (private / 'flow.json').exists():
            raise RuntimeError('Expected exactly one complete private export')
        convert(programs[0].parent, args.output.resolve(), private / 'flow.json')
        print('Public metadata exported. Raw firmware-bearing intermediates remain PRIVATE in', private)
        return
    if any((directory / (args.project_name + ext)).exists() for ext in ('.gpr', '.rep')):
        raise ValueError('Existing project refused; choose a fresh --project-name')
    directory.mkdir(parents=True, exist_ok=True)
    report = directory / (args.project_name + '-verification.json')
    if report.exists(): raise ValueError('Existing verification report refused')
    command = java_prefix(ghidra, args.java_home) + [
        'ghidra.app.util.headless.AnalyzeHeadless', str(directory), args.project_name,
        '-import', str(args.rom.resolve()), '-loader', 'BinaryLoader',
        '-processor', '68000:BE:32:CPU32_STATUS_V2', '-cspec', 'default', '-noanalysis',
        '-scriptPath', str(ROOT / 'ghidra_scripts'),
        '-postScript', 'ImportResearch.java', str(ROOT / 'annotations/q28g'),
        '-postScript', 'VerifyResearch.java', str(ROOT / 'annotations/q28g'), str(report),
    ]
    run_logged(command, directory / (args.project_name + '-build.log'), 'BMS46_VERIFICATION_PASS')
    if not report.is_file() or json.loads(report.read_text())['status'] != 'PASS':
        raise RuntimeError('No successful verification report')
    print('PASS: rebuilt and verified', directory / (args.project_name + '.gpr'))
    print(report.read_text())


if __name__ == '__main__':
    main()
