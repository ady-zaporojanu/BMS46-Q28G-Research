# Quick start

## Requirements

- Python 3.10+; Git for collaboration.
- [Ghidra 12.1.2](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.2_build), extracted in a writable location.
- A JDK supported by that release; this package was exercised with Eclipse Temurin JDK 25.
- Your own unmodified 262144-byte canonical Q28G image matching the README hash.

Use the pinned version and custom language for this baseline. A newer built-in
CPU32 language is not a drop-in replacement without a separate decode/p-code audit.
No ECU, cable or live vehicle connection is required.

## Windows / PowerShell

Run from the repository directory. Replace the example paths with yours:

```powershell
$env:GHIDRA_HOME = 'C:\Tools\ghidra_12.1.2_PUBLIC'
$env:JAVA_HOME = 'C:\Tools\jdk-25'
python tools/validate.py
python tools/ghidra_project.py check-rom --rom 'C:\Private\Q28G.bin'
python tools/ghidra_project.py install-language
python tools/ghidra_project.py build --rom 'C:\Private\Q28G.bin'
```

The extension installer only writes `Ghidra/Extensions/BMS46_CPU32_Status_V2`.
It refuses conflicting source files. Close Ghidra first, and restart after installation.
It never overwrites the built-in 68000 language. Use a separate Ghidra installation
if you have a different extension with the same ID.

The result is `local-work/projects/Q28G_Research.gpr`. Open it in Ghidra and open
the imported program. If asked about automatic analysis, decline for baseline
reproduction. Analysis can be explored later in a separate project/branch.

The verifier prints `PASS` and saves `Q28G_Research-verification.json` alongside
the project. Treat a build as failed if that report is absent or not PASS, even if
Ghidra says “Import succeeded”. Ghidra can save a project after a script error.

An existing project is refused. Use `--project-name Q28G_MyFinding` for another
fresh rebuild. Keep project paths free of components beginning with a dot:
Ghidra rejects them. `local-work/` is ignored by Git.

## Linux / macOS

The Python driver uses the same Java entry points and has no Windows-only paths:

```sh
export GHIDRA_HOME=/opt/ghidra_12.1.2_PUBLIC
export JAVA_HOME=/path/to/jdk
python3 tools/ghidra_project.py install-language
python3 tools/ghidra_project.py build --rom /private/Q28G.bin
```

The native Ghidra build was tested on Windows; other operating systems still
need contributor validation. Do not report them as verified simply because the
commands are portable.

## Optional native fan-demand tests

Use a virtual environment, then install the pinned optional dependency:

```sh
python -m venv .venv
# Activate .venv using your shell's normal activation command.
python -m pip install -r requirements-native.txt
python tests/native_fan_demand.py --rom /path/to/Q28G.bin
```

Do not use `python -O`: assertions are part of the tests. Reports are written to
ignored `local-work/native/`. Some reports contain small extracted ROM regions;
review and sanitize them before sharing. The expected total is 74,049 cases.

## Editing and exporting

Close the project in the Ghidra GUI before headless export. The easiest route is:

```sh
python tools/ghidra_project.py export --project-name Q28G_Research --program Q28G.bin --output local-work/proposed-snapshot
```

Use the actual imported program name, which is normally your input ROM filename.
This opens the project read-only, writes private intermediates under ignored
`local-work/private-exports/`, and creates only allowlisted metadata in the output
directory. It never replaces the tracked snapshot. Continue with review at step 5
below. For manual Script Manager/headless use, the same stages are:

1. Add `ghidra_scripts/` to Ghidra's Script Manager paths.
2. On your project, run `ExportPrivateEvidence.java` with an absolute output directory
   under `local-work/private-export/`. **Its output includes firmware bytes.**
3. Run `ExportFlowOverrides.java` with an absolute output file, such as
   `local-work/flow.json`.
4. Find the program subdirectory created by the private exporter, then run:

```sh
python tools/snapshot.py --private-export local-work/private-export/PROGRAM_FOLDER --overrides local-work/flow.json --output local-work/proposed-snapshot
```

5. Review the proposed snapshot against `annotations/q28g/`. Copy the intended
   metadata changes into the tracked snapshot. Do not copy the raw export.
6. A rebuilt project has default signatures/locals: preserve reference-only
   metadata in `functions.jsonl` unless you deliberately improve it with evidence.
7. Run validation and rebuild a fresh project before submitting your PR.

The converter validates the ROM hash/language, uses explicit field allowlists,
rejects obvious local paths/VINs, and refuses a non-empty output directory.
Manual privacy/licensing review is still necessary for arbitrary new comments.
