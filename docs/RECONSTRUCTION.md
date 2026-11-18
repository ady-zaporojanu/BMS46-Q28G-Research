# Reconstruction contract

The text snapshot is the reviewable source of truth. It is not a lossless dump
of Ghidra's internal database, and a `.gpr` without its `.rep` directory is not
a portable project.

## Restored and checked

- Exact ROM hash, size, language and base address.
- Four memory blocks, permissions and volatility model.
- All 45,151 instruction starts and lengths; bytes come from the private ROM.
- 756 function names, entry points and body ranges.
- 3,259 non-default global labels, source types and primary flags.
- 4,523 comment records, across EOL/PRE/POST/PLATE/REPEATABLE.
- 3,211 defined data placements and type/length assignments.
- Ten structure layouts, members and member types, plus referenced primitive,
  array and pointer types (37 exported type records).
- Two explicit CALL_RETURN overrides: 0x57C and 0x105A0.
- 47 bookmarks.

Pointer display aliases such as `/pointer` vs `/pointer32` and `*` vs `*32` are
normalized by the verifier; the model uses 32-bit pointers. These aliases are
not treated as evidence of a semantic difference.
The tested rebuild resolves 37 reference type records into 36 exported types
because equivalent pointer aliases coalesce.

## Preserved for reference, not restored automatically

`functions.jsonl` includes prototypes, signature sources and local-variable
metadata. There are 23 user-defined signatures in the source export. This release
does not apply their calling conventions, variable storage or inferred decompiler
state. Decompiler output may therefore differ. Review and implement signature
restoration as a separate tested contribution; do not silently overwrite this
metadata when exporting from a rebuilt project.

Implicit analysis-generated references/symbols, cache state, user UI settings,
analysis history and private database ownership are not transferred. Instruction
decoding recreates normal references, but full reference-graph identity is not
claimed. No firmware patch or byte modification is performed.

The inherited 73-byte diagnostic response structure and newer 74-byte structure
both remain visible. They reflect different historical interpretations/framing;
their coexistence is not proof they are interchangeable. Prefer the newer bounded
field evidence and resolve discrepancies explicitly in a PR.

## Data model

JSONL uses one record per line, UTF-8 and deterministic sorting. Addresses are
full-image hexadecimal strings, not file offsets into a partial read. See
`tools/snapshot.py` for allowed fields and `annotations/q28g/manifest.json` for
identity and record counts. Comments are keyed by `(address, type)`; functions
by entry address; instructions/data by address; types by path.

Memory ranges model the analysis environment; a reserved RAM/MMIO range is not
proof that every address exists physically or is safe for arbitrary use.
