# Research materials

## Start with the matching BIN and XDF

[Q28G_START_HERE.md](catalog/Q28G_START_HERE.md) links the canonical full 256 KiB
image and both 32 KiB partial layouts to their matching TunerPro definitions.
The partial layouts start at `0x8000` and `0x8010`; do not interchange their XDFs.

- [Firmware collection](library/firmware): 185 research inputs, including 41 images
  of 256 KiB, 62 images of 32 KiB, and fragments/comparison material of other sizes.
- [TunerPro XDF definitions](library/tunerpro): 131 historical definitions. 108 parse
  as XML; 23 historical parsing failures are retained and documented in the catalog.
- [Diagnostic XML and support files](library/diagnostic-xml): 8 files.
- [Map packs](library/map-packs): 3 research files.
- [Firmware index](catalog/FIRMWARE.md) and [XDF index](catalog/TUNERPRO.md).

These counts do not mean 185 compatible BMS46 versions. Modified files, fragments
and comparison ECU material are retained with provenance, not recommended for flashing.

## Open the actual annotated Ghidra program

1. Install Ghidra **12.1.2** and the **CPU32_STATUS_V2** language using the
   [quick-start instructions](../docs/QUICKSTART.md).
2. Create a new Ghidra project and use **File -> Import File** to import
   [Q28G_CPU32_STATUS_V2_annotated.gzf](ghidra/Q28G_CPU32_STATUS_V2_annotated.gzf).
3. Do not rerun auto-analysis when reproducing this baseline.

This is the original packed program, including firmware, function names, comments,
signatures and local-variable metadata. The [round-trip report](ghidra/full-state-verification.json)
records 756 functions, 4,523 comments, 9,928 symbols, 37 types, 45,151 instructions,
27,145 references and all 23 user-defined signatures preserved.

The ready-to-open `.gpr` plus its `.rep` database and the complete historical
collection are in the [v0.2.0 release](https://github.com/ady-zaporojanu/BMS46-Q28G-Research/releases/tag/v0.2.0).
Use the specifically named research ZIP asset; GitHub's automatic source ZIP only
contains the repository. Keep the `.gpr` and adjacent `.rep` together after extraction.

## Collaboration, integrity and provenance

Commit annotation changes under `annotations/q28g/` so contributors can review
text diffs. Do not merge a live `.rep` database. Packed snapshots are versioned
research artifacts. See [CONTRIBUTING](../CONTRIBUTING.md).

Every included material is enumerated with a SHA-256 and size in
[materials-manifest.json](../research/materials-manifest.json). `python tools/validate.py`
checks that manifest and rejects unexpected or modified material files.

Research materials remain subject to their original rights. The MIT/Apache licenses
of the toolkit do not license manufacturer firmware, diagnostic data or third-party
map packs. The existing per-object `license_status` is retained, including unresolved
redistribution status; publication does not establish a new license or technical validity.
Preserve upstream attribution. No ECU writing is performed by these instructions.
