# Complete research materials — companion release

The companion `bms46-community-materials` bundle extends the small source repository
with actual research inputs and the original annotated Ghidra program. It is
available as [repository materials](../materials/README.md) and the
[complete v0.2.0 release](https://github.com/ady-zaporojanu/BMS46-Q28G-Research/releases/tag/v0.2.0). The release ZIP contains the full collection;
the repository exposes the BIN/XDF/XML inputs and packed Ghidra program.

## Open the complete Ghidra analysis

Use Ghidra 12.1.2 and install the supplied CPU32_STATUS_V2 extension first. Then:

- Open `ghidra/project/Q28G_Complete.gpr`, keeping its `.rep` directory beside it; or
- Create a new local Ghidra project and import
  `ghidra/Q28G_CPU32_STATUS_V2_annotated.gzf` using **File → Import File**.

The `.gzf` is a packed copy of the **actual original annotated program**, including
its firmware, names, comments, signatures, local-variable metadata, symbols,
references, structures and data placements. It is not rebuilt by the approximate
annotation importer. Do not re-run auto-analysis to reproduce the recorded state.

The packed program was imported into a new project and re-exported. Full records
matched for 756 functions, 4,523 comments, 9,928 symbols, 37 types, 3,211 data
definitions, 45,151 instructions and 27,145 references. The 23 manually defined
function signatures are preserved. See the companion `ghidra/full-state-verification.json`.

These modifications are analysis annotations. They do not change the canonical
firmware bytes. Experimental/modified BINs are separate library objects.

## Firmware and TunerPro materials

- `catalog/FIRMWARE.md`: full-size images, partial reads and other-size research inputs.
- `catalog/full-partial-relationships.json`: exact byte-equality mappings and base offsets.
- `catalog/TUNERPRO.md` and `catalog/tunerpro.csv`: XDF versions, titles and definition counts.
- `catalog/xdf-address-audit.json`: parsed address/base-offset metadata, not calibration proof.
- `catalog/objects.json` and `catalog/sources.json`: hashes, provenance, deduplication and disposition.

XDF is an XML-based definition format. A syntactically valid XDF is not necessarily
correct for a particular firmware. Check version, image size, base offset,
endianness and conversion equations. Do not apply full-image addresses to a partial
read without the proven offset relationship. Historical names containing “stable”,
“verified” or “safe” are source names, not a new endorsement of every definition.

The library also retains diagnostic XML, map-pack files, native excerpts,
decompiled C, historical analysis scripts, reports and reference documents.
Comparison material for other ECUs is identified by provenance and must not be
treated as BMS46-compatible. Historical scripts may contain machine-specific paths
and write operations; they are reference material, not automatically run tools.

## Publication and rights

The original collection was prepared as a review candidate. Its publication is not a blanket licensing claim.
MIT/Apache notices for the source project do not grant rights to manufacturer
firmware, proprietary diagnostic definitions, third-party PDFs or map packs.
Review `license_status` per object and source provenance before publishing a release.

Identifiable raw binaries are kept in a separate local private hold without
modifying their bytes. Text copies have recognized vehicle IDs/local paths removed;
source and distributed hashes distinguish those copies. Automated checks do not
guarantee removal of every serial, key field or embedded identity. This is not
permission to publish raw vehicle dumps indiscriminately.

Installer binaries, duplicate database caches and compiled temporary artifacts are
not useful source contributions. Large generated files omitted from the bundle
are indexed in `catalog/excluded.json`; historical scripts remain available.

Publish the source repository for diffs/PRs and attach reviewed datasets/projects
as versioned release assets (or use Git LFS when appropriate). GitHub documents
[release assets for large-file distribution](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github).
Do not recursively push a local Ghidra `.rep` database into the annotation branch.
