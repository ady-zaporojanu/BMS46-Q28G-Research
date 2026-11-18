# Q28G: matched BIN / XDF pairs

These are the documented v1.09 baseline definitions, preserved as research material. No flashing is performed.

| Layout | BIN | XDF | Full-image start |
| --- | --- | --- | --- |
| LAMBDA2_DTC76 | [BIN](../library/firmware/d3c3abb52362_01119700F000Q28G_CANONICAL.bin) | [XDF](../library/tunerpro/2d99ceefecbd_BMS46_Q28G_v1.09_STABLE_LAMBDA2_DTC76.xdf) | `0x0` |
| PARTIAL_32KB | [BIN](../library/firmware/cf291dd1b497_q28g_calibration_8000.bin) | [XDF](../library/tunerpro/d7eb094bb369_BMS46_Q28G_v1.09_STABLE_PARTIAL_32KB.xdf) | `0x8000` |
| GALLETTO_32KB | [BIN](../library/firmware/709a4c3e15ea_PARTIAL_01119700F000Q28G.bin) | [XDF](../library/tunerpro/378d3cc7c94e_BMS46_Q28G_v1.09_STABLE_GALLETTO_32KB.xdf) | `0x8010` |

The two 32 KiB files differ by a 16-byte offset. Do not interchange their XDFs.
The full definition contains 270 tables, 451 constants and 5 flags. Partial definitions expose the subset available in their file layout.
XML structure and numeric address ranges were checked. Physical units, all formulas and live vehicle behavior were not newly validated by packaging.
In TunerPro, open the BIN with File → Open Bin and choose its paired XDF with XDF → Select XDF.
