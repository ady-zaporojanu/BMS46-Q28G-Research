# Changelog

## 0.2.0 — 2026-11-18

- Added a packed copy and ready-to-open copy of the original annotated Ghidra program.
- Verified full function/symbol/type/instruction/reference record preservation, including 23 user signatures.
- Added deduplicated companion research collection: BINs, XDF/XML, map packs, historical tools and evidence.
- Added source/hash catalogs, exact partial/full relationships and XML metadata indexing.
- Retained separate source-repository and review-asset publication workflows.

## 0.1.0 — 2026-11-18

- First source-only collaboration package for the current Q28G research snapshot.
- Consolidated 4,523 comments, 756 function bodies/names and 3,259 global labels.
- Preserved memory model, data definitions, structures, bookmarks and overrides.
- Added isolated CPU32 language sources, guarded reconstruction, verification,
  private export, public snapshot conversion and metadata diff tools.
- Ported 74,049 fan-demand native cases to a clean optional Python environment.
- Added English/Romanian documentation, attribution, contribution workflow,
  issue/PR templates, offline CI and explicit archive allowlisting.
- Excluded firmware and private Ghidra databases from the public package.

Known limitation: signatures/local variables are reference-only metadata and
implicit reference-graph identity is not guaranteed. See docs/RECONSTRUCTION.md.
