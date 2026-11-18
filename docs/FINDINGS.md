# Selected findings and their limits

Latest included analysis: diagnostic follow-up, TPU/fan output path, and fan-demand
producer follow-up. The complete address-level commentary is in the snapshot.

## Received fan demand and command path

The ten-byte descriptor at `0x351CC` (index 7 of table `0x35186`, ID `0x0615`)
dispatches through `0x32DBA` to `0x33CFA`. Native tests prove that dispatch in a
bounded model, not reception on an actual CAN controller.

The receive decode places `payload[1] >> 4` in RAM `0xFF8804`: a **0–15 raw level**,
not a percentage or a single A/C switch. With `0xFF96A4.bit30` set, the decode
slice preserves the previous level. Error/status paths have conditional resets;
not every receive failure clears the request.

`0x23BD2` combines interpolation descriptors `0x8198`, `0x81B6`, `0x81D4`, an
optional additional request, speed influence, ordered hysteresis and filtering.
The two hysteresis conditions are independent sequential checks. A coefficient
of 2 is used in the observed filter path with a minimum one-unit change.

For filtered byte `f` and raw byte `v` at `0xFF832C`:

```text
n = min(255, floor(f * 146 / (v + 1)))
t = floor(153 * n / 128)
b = max(0, t - 76)
c = 0 if b < 3 else clamp(b, 29, 228)
```

All byte pairs produce 169 distinct command values: zero plus 168 nonzero values
within 29–228. Integer arithmetic skips 32 values inside that interval. The raw
voltage-related byte is not the separate diagnostic battery byte `0xFF832A`.

Gate/suppression conditions clear `0xFF880C/D/E` while preserving hysteresis
history at `0xFF8815/16`. Output routine `0x23EF2` stages the final byte at
`0xFF8818` and a TPU parameter at `0xFFFFC4`. This is not measured fan speed.
Diagnostic presentation of a staged byte as a percentage does not establish
physical waveform duty, frequency or actual RPM.

The portable test covers 74,049 cases: dispatch, decode/inhibit, interpolation,
normalization, complete demand/output paths, gate conditions and sequential calls.
It does not execute TPU microcode or prove electrical units, interrupt behavior,
live receive/DTC handling, or elapsed time. Task calls are not milliseconds.

## CPU32 language

The custom language carries local SR/CCR/RTR data-effect fixes and separates T0.
Historical status testing reported 217,952 bounded data-effect cases. That older
suite is not presented as rerun by this package's fan test or offline CI.
TBL userops, privilege traps, stack-bank behavior, exception/RTE semantics,
interrupt timing, trace behavior and hardware peripherals remain incomplete.

## Diagnostic records

The snapshot preserves historical and later diagnostic structures, comments about
field offsets/scaling, and distinctions between raw requests, internal staged
values and physical outputs. It does not bundle the proprietary PRG files or live
vehicle frames used during the original local investigations.

## Function catalog

`research/function_catalog.csv` is the inherited role-confidence baseline:
14 CONFIRMED, 116 HIGH, 626 LOW/UNKNOWN. Some function comments contain older
“HIGH_CONFIDENCE” labels while the catalog deliberately classifies their semantic
role as LOW. Naming confidence and verified semantic role are different claims.
Do not automatically synchronize those labels or infer completeness from names.
