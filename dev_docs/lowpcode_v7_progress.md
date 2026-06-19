# Low-PCode V7 Development Progress

This document records what changed in v7 compared with v6. It is a development note for the Low-PCode analyzer and should be kept in sync with `tools/pcode_ssa_report_v7.py` and `tools/pcode_ssa_batch_v7.py`.

## V7 Goal

V6 made direct source/sink calls and generated helper summaries usable. V7 starts the next layer: memory-object transfer behavior. The immediate target is not a complete heap/byte-range model yet; it is to stop losing stack object identity when Low-PCode computes addresses through nested expressions such as `[EBP + ECX*scale + offset]`, then use that improved stack identity for common library transfer calls.

## What Changed From V6

- V7 keeps v6 behavior:
  - `dfb_source_*` calls become `SOURCE_RET` nodes.
  - `dfb_sink_*` calls become sink anchors.
  - `function_summaries.json` helper summaries are loaded and applied before hardcoded fallback summaries.
  - Expected-source validation remains unchanged.
- V7 adds recursive stack address recovery:
  - V6 often collapsed nested indexed stack addresses into keys such as `REG_0x7200`.
  - V7 walks the SSA graph around address expressions and attempts to recover `EBP_0x...` stack keys through `COPY`, `INT_ADD`, `INT_MULT`, `INT_LEFT`, `INT_AND`, `INT_SEXT`, and `SUBPIECE` patterns.
  - V7 can follow simple stack `LOAD` memory edges back to constant `STORE` values, which lets indexed byte stores like `buf[i]` recover a concrete stack offset when `i` is a local constant.
- V7 adds narrow libc transfer summaries:
  - `memcpy(dest, src, size)` transfers the current source stack memory node to the destination stack key.
  - `memmove(dest, src, size)` is modeled the same way as `memcpy` for current DataFlowBench purposes.
  - `strcpy(dest, src)` transfers the current source stack memory node to the destination stack key.
  - `memset(dest, value, size)` writes a value-derived memory node to the destination stack key.
- V7 writes reports to `output/v7_batch/` and report filenames end in `_v7_report.txt`.

## Current Batch Result

Last verified command:

```powershell
python tools\pcode_ssa_batch_v7.py output\low_pcode output\v7_batch
```

Result:

- PASS: 37
- FAIL: 13
- ERROR: 0

V6 baseline before v7 was PASS 34 / FAIL 16. V7 newly passes:

- DFB046 `case_DFB046_partial_overwrite_subfield`
- DFB122 `case_DFB122_strcpy_buffer`
- DFB123 `case_DFB123_memset_partial_memcpy`

The batch command still exits with code `1` while FAIL cases remain. This is expected and keeps the batch runner usable as a regression gate.

## Current Limits

- V7 still does not implement a general byte-range lattice. It can recover some constant byte offsets, but transfer summaries still link stack keys rather than maintaining complete `[offset, size)` intervals.
- V7 does not yet model heap allocation identity, `malloc`, `free`, or `realloc`.
- V7 does not resolve indirect calls, callback registrations, or function pointer tables.
- V7 does not add special handling for `setjmp`/`longjmp`, TLS, or obfuscated CFG recovery.
- The libc summaries are intentionally narrow and direct-call based.

## Validation Commands

Build helper summaries, then run v7 batch validation:

```powershell
python tools\pcode_summary_builder.py output\low_pcode output\low_pcode\function_summaries.json
python tools\pcode_ssa_batch_v7.py output\low_pcode output\v7_batch
```

Check syntax:

```powershell
python -m py_compile tools\pcode_summary_builder.py tools\pcode_ssa_report_v7.py tools\pcode_ssa_batch_v7.py
```
