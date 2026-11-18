# Attribution and licensing

This repository assembles and extends existing BMS46 research. It is not the
original author of Ghidra, the BMW firmware, or all inherited labels.

| Component | Origin / treatment |
| --- | --- |
| BMS46 research lineage and inherited labels | [Bartek0x00/BMS46-Wiki](https://github.com/Bartek0x00/BMS46-Wiki), MIT, copyright 2025 Bartek0x00; notice preserved in `licenses/BMS46-Wiki-MIT.txt` |
| Ghidra processor source | [NSA Ghidra](https://github.com/NationalSecurityAgency/ghidra), Apache-2.0; license in `licenses/Apache-2.0.txt` |
| CPU32 donor patch | [Brad Ackerman / backerman, commit fafd1bb00aaca30ee546de0485896ba4de1bacab](https://github.com/NationalSecurityAgency/ghidra/commit/fafd1bb00aaca30ee546de0485896ba4de1bacab), same Ghidra source lineage |
| Local CPU32_STATUS_V2 changes | Isolated language ID; SR/CCR/RTR data-effect repairs, T0 flag model; Apache-2.0 derivative, not complete hardware semantics |
| Local research additions | Q28G annotation consolidation, diagnostic field analysis, TPU/fan demand follow-up, bounded native tests, portable import/export/verification tooling and collaboration documentation |
| Unicorn | Optional dependency, not vendored; [Unicorn Engine](https://github.com/unicorn-engine/unicorn) |

The original local source tree predates this public package. Its complete commit
history and a verified upstream revision for every inherited annotation are not
available in this export. `research/inherited_sources.csv` records the available
input file hashes; it is provenance evidence, not a license for those source files.
Historical source IDs and report names inside comments refer to that research
lineage; not all external/private artifacts are redistributed here.

Additional comparison research referenced MSS54 community work, including
[karter16/CSL_0401_Binary_Disassembly_Notes](https://github.com/karter16/CSL_0401_Binary_Disassembly_Notes).
Correspondence to another ECU is not proof of a BMS46 function's role. No donor
firmware or proprietary diagnostic definitions are bundled.

Source comments and confidence labels may contain legacy terminology; current
findings must be assessed against evidence, not inferred from the name of a file.

BMW and Siemens names identify the studied hardware/software. This is an
independent community research package, not an official manufacturer release.
Repository licenses do not license firmware, trademarks or third-party manuals.
