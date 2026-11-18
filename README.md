# BMS46 Q28G — collaborative Ghidra research

Reproducible, **offline** reverse-engineering workspace for the BMW/Siemens BMS46
firmware revision **01119700F000Q28G**. Share and review annotations in Git, then
rebuild a local Ghidra project from a firmware image you are entitled to use.

**Complete companion bundle:** the original ready-to-open Ghidra project, packed
program, full/partial BIN collection, TunerPro XDF/XML definitions, map packs and
historical research are now prepared separately as release/review materials.
See [MATERIALS.md](docs/MATERIALS.md). The packed project preserves the original
signatures and variables; the text-only reconstruction below has a narrower scope.

[Română](README.ro.md) · [Quick start](docs/QUICKSTART.md) ·
[Findings](docs/FINDINGS.md) · [Contributing](CONTRIBUTING.md) ·
[Attribution](NOTICE.md) · [Reconstruction limits](docs/RECONSTRUCTION.md)

This is an extension of existing community research, including
[Bartek0x00/BMS46-Wiki](https://github.com/Bartek0x00/BMS46-Wiki), not a claim of
sole authorship. The isolated CPU32 language derives from Ghidra and the
[CPU32 patch by Brad Ackerman](https://github.com/NationalSecurityAgency/ghidra/commit/fafd1bb00aaca30ee546de0485896ba4de1bacab).
See [NOTICE.md](NOTICE.md) for licensing and the scope of our additions.

## What is included

| Item | Current snapshot |
| --- | ---: |
| Functions and body ranges | 756 |
| Address/type comment records | 4,523 |
| Non-default global labels | 3,259 |
| Instruction boundaries, without firmware bytes | 45,151 |
| Data definitions | 3,211 |
| Data-type records / structures | 37 / 10 |
| Memory blocks / flow overrides / bookmarks | 4 / 2 / 47 |

- Text snapshots suitable for diffs and pull requests.
- CPU32_STATUS_V2 language sources, importer, private exporter and verifier.
- Firmware identity checks; no automatic analysis or hardware communication.
- Portable native fan-demand tests: **74,049 bounded cases** on Unicorn's M68020
  common instruction subset. This does **not** validate CPU32 peripherals or a real fan.
- Research notes, confidence rules, open tasks, issue/PR templates and offline CI.

The inherited function-role catalog has 14 CONFIRMED, 116 HIGH and 626 LOW/UNKNOWN
entries. These are historical claim-specific classifications, **not a percentage
of firmware understood**. Later comments contain additional bounded findings;
descriptive names alone are not proof. The project remains research in progress.

## Firmware identity

```text
Revision:  01119700F000Q28G
Size:      262144 bytes (0x40000)
Base:      0x00000000
SHA-256:   d3c3abb5236240906a9d8851b31802e0751c233ebe0bba58d2c51f66e137679d
Language:  68000:BE:32:CPU32_STATUS_V2
Ghidra:    12.1.2 (pinned reconstruction baseline)
```

Firmware and Ghidra databases are not stored in this text-source repository;
they are organized in the separate companion collection with provenance and
publication-review status. Private identity data and proprietary software installers
are not intended for public redistribution. Do not substitute another BMS46
revision. The public annotations alone do not reconstruct the ROM bytes.

## Start here

Python 3.10 or later is sufficient for checks and annotation review:

```sh
python tools/validate.py
python -m unittest discover -s tests -p "test_*.py"
```

To open the research in Ghidra, follow [QUICKSTART](docs/QUICKSTART.md): install the
isolated processor language, supply your canonical ROM, and run the guarded build.
The build creates a new project and verifies it; it refuses existing projects.

## Working together

Use a branch per finding. Discuss an address/routine in an issue, include bounded
evidence and confidence, submit a small annotation diff, then rebuild and verify.
The shared artifact is `annotations/q28g/`, **not** a `.rep` folder that Git cannot
merge. Read [CONTRIBUTING.md](CONTRIBUTING.md) before exporting changes.

Useful next tasks: physical fan/TPU timing, receive error paths, injector/dwell
units, uncertain function roles, and explicit comparison with other firmware
revisions. See [ROADMAP](docs/ROADMAP.md).

## Scope

This repository does not flash, patch or code an ECU, and does not connect to
EDIABAS. Disassembly, decompilation and emulator behavior are analysis evidence,
not a guarantee of hardware behavior. The reconstruction preserves the documented
annotation contract, not every internal Ghidra database object.

Original tooling/documentation and inherited MIT material: [MIT](LICENSE).
Processor extension: [Apache-2.0](licenses/Apache-2.0.txt), with provenance in
[NOTICE](NOTICE.md). Firmware rights are not granted by these licenses.
