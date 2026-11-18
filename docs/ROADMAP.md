# Research backlog

| Priority | Task | Evidence needed to close |
| --- | --- | --- |
| High | Physical TPU/fan output | Channel configuration, measured period/polarity/duty, firmware/hardware identity; distinguish commanded from measured behavior |
| High | Receive error paths | Full branch analysis around set_DTC and conditional reset; avoid broad error-reset claims |
| High | CPU32 semantics | Independent architecture reference plus targeted p-code cases for unresolved instructions/exception paths |
| High | Function signature reconstruction | Preserve 23 user signatures, storage and calling conventions; round-trip verification |
| Medium | Diagnostic structure framing | Reconcile inherited 73-byte and newer 74-byte descriptions with exact frame boundaries |
| Medium | Injector latency and dwell | Producer/consumer tracing, timer units, physical measurements; no guessed milliseconds/degrees |
| Medium | Unknown function roles | Small evidence-backed proposals, explicit caller/callee and RAM relations |
| Medium | Other BMS46 revisions | Separate hashes/base addresses, correspondence evidence, no blind Q28G address reuse |
| Medium | Linux/macOS Ghidra reproduction | Fresh installation, language build, project rebuild and verification report |
| Low | Public examples and diagrams | Synthetic/sanitized examples with no firmware or identity data |

Create issues from these rows after publication; this file does not claim GitHub
issues, protections or collaborators have already been configured.
