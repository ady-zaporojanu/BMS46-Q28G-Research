# Contributing

All experience levels are welcome. Small, reproducible findings are easier to
review than bulk renames. English is preferred for shared findings; Romanian
explanations are welcome alongside them.

1. Open an issue with firmware identity, addresses, your claim and a falsifiable test.
2. Branch from `main` (`research/fan-scaling`, `fix/decoder-ccr`, etc.).
3. Use a fresh reconstructed local project. Keep firmware and raw exports outside Git.
4. Edit comments/labels or tools; export metadata using [QUICKSTART](docs/QUICKSTART.md).
5. Run `python tools/validate.py` and `python -m unittest discover -s tests -p "test_*.py"`.
6. For annotation/decoder changes, rebuild and attach the sanitized verification
   summary. For native behavior claims, run the relevant firmware-dependent tests.
7. Submit a PR describing evidence, uncertainty, attribution and actual tests run.

## Evidence and confidence

- **Observed native fact:** instruction/data-flow evidence for the exact ROM.
- **Bounded model result:** named simulator, inputs and exclusions; not hardware proof.
- **Hardware observation:** acquisition method, relevant hardware/software revision,
  sanitized trace and electrical units.
- **Hypothesis/inherited label:** preserve the original source and unresolved questions.

Use claim-specific CONFIRMED/HIGH/LOW/UNRESOLVED descriptions. Never upgrade a
whole function to “confirmed” because one branch passed. AI-assisted output must
be reviewed; name the verification performed rather than treating generated
explanations as evidence. Cite original sources, not only this repository.

## Concurrent work and conflicts

Coordinate ownership of overlapping routines in an issue. Git merges text;
it does not merge Ghidra databases. Resolve conflicting `(address, comment-type)`
records or symbol names explicitly. Preserve alternative interpretations and
their evidence until resolved. Do not commit `.rep`, `.gpr`, `.gar`, ROMs or full
disassembly. Git LFS does not solve database merge semantics or firmware rights.

Use `python tools/diff_snapshot.py annotations/q28g local-work/proposed-snapshot`
to review changes by record identity. Rebuild after merging, not just after editing.

## Changes requiring extra review

Processor semantics, function boundaries, memory layouts, volatile/MMIO flags,
calling conventions and imported addresses from other firmware revisions need
focused review and a fresh rebuild. Tests running on M68020 are not sufficient
to prove CPU32-specific instructions or peripheral timing.

Contribute only material you can license under the applicable repository license.
Retain third-party notices. Do not post VINs, vehicle serials, key/transponder
material, credentials, proprietary installers/manuals or full firmware images.
The automation catches common mistakes, not every possible sensitive field.

## Maintainer setup after GitHub publication

Enable pull requests and Issues. Protect `main`: require `offline-validation`,
at least one reviewer when collaborators are available, resolved conversations
and no force pushes. Add real maintainers to CODEOWNERS only after their GitHub
handles and responsibilities are agreed. These server settings are instructions,
not configured by files in this package. Publishing and inviting collaborators
are separate actions.
