# Release validation

Prepared on 2026-11-18. The source-only package was tested locally on Windows
with Python 3.10.6, Ghidra 12.1.2, Eclipse Temurin JDK 25 and Unicorn 2.1.4.

| Check | Result |
| --- | --- |
| Fresh Ghidra raw import and annotation reconstruction | PASS |
| Reconstruction verification | 57,079 checks, PASS |
| Canonical ROM SHA-256 after reconstruction | Unchanged |
| CPU32_STATUS_V2 source installation/compilation | PASS |
| Native fan-demand tests in a fresh virtual environment | 74,049 cases, PASS |
| Python tool regression suite | 10 tests, PASS (including companion collection guards) |
| Re-export of reconstructed project | Exact comments, global labels, instruction boundaries, memory, overrides and bookmarks |

Machine-readable sanitized reports are in `research/validation/`. They record
the checks actually run; they are not a CI badge or proof that GitHub Actions has
already executed. The public CI runs the firmware-free checks only.

Ghidra may canonicalize pointer type names; the verifier compares equivalent
32-bit aliases as documented. The full database, function signatures/local
storage and all implicit reference graphs are not claimed equivalent.
The reconstructed export contains 36 resolved type records versus 37 reference
records due to pointer aliases. This is why exported metadata is reviewed rather
than replacing the reference snapshot wholesale.

Native test reports cover only the modeled instruction subset and specified
inputs. There was no vehicle/bench connection or physical measurement in this
packaging validation. There is no automatic ECU writing in this repository.
