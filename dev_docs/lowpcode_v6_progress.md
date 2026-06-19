# Low-PCode V6 Development Progress

This document is a temporary development note. It is kept under `dev_docs/` because it is useful while the Low-PCode engine is still being developed, but it can be removed once the implementation stabilizes.

## Scope

- Analyzer target: DataFlowBench Windows core Low-PCode JSON dumps.
- Current dump input directory: `output/low_pcode/`.
- Current batch output directory: `output/v6_batch/`.
- Expected oracle path: `D:\githubProject\01_tdo_testbed\tdo_testbed\expected`.
- Current engine entry points:
  - `tools/pcode_ssa_report_v6.py`: single-function report and expected validation.
  - `tools/pcode_ssa_batch_v6.py`: batch execution across `*_low_pcode.json` files.
  - `tools/pcode_summary_builder.py`: lightweight helper-function summary DB builder from Low-PCode JSON.

## Current Batch Result

Last verified command:

```powershell
python tools\pcode_ssa_batch_v6.py output\low_pcode output\v6_batch
```

Result:

- PASS: 34
- FAIL: 16
- ERROR: 0

The batch command currently exits with code `1` when any case is `FAIL` or `ERROR`. That is intentional so the script can be used as a regression gate.

## Implemented So Far

- Low-PCode JSON dumper exports enhanced metadata while keeping legacy fields.
- Dumper can batch-export functions whose names start with `case_DFB` and can now include reachable internal helpers.
- V6 expected validation compares actual source IDs with DataFlowBench expected JSON.
- V6 records source calls as `SOURCE_RET` nodes and sink calls as sink anchors.
- V6 selects the first resolved sink argument as the default slice target.
- Batch runner generates per-case reports and aggregate summaries.
- Batch runner now ignores helper JSON files and validates only `case_DFB*_low_pcode.json` inputs.
- x86 stack-argument tracking now preserves multi-push call arguments across value-preparation instructions.
- Low-PCode helper summary DB generation was added:
  - Tracks frame-pointer based argument loads from helper bodies.
  - Emits return, outparam, global read, global write, direct source-call, and simple dereference summaries.
  - Preserves `MOV EBP, ESP` as a frame-base marker during summary construction.
- V6 now loads `function_summaries.json` from the input JSON directory and applies generated helper summaries before name-hinted fallback rules.
- Name-hinted, Low-PCode callsite summaries were added for narrow helper classes:
  - `arg0 -> return` summaries.
  - outparam store summaries.
  - one-level double-pointer outparam summary.
  - precise global main/shadow helper summary.
  - imported arg-to-return and outparam helper summaries.

## PASS Cases

| Case | Function | Actual sources |
|---|---|---|
| DFB001 | `case_DFB001_direct_value` | `dfb_source_A.ret` |
| DFB002 | `case_DFB002_arithmetic_value` | `dfb_source_A.ret` |
| DFB003 | `case_DFB003_cast_value` | `dfb_source_A.ret` |
| DFB010 | `case_DFB010_branch_phi` | `dfb_source_A.ret`, `dfb_source_B.ret` |
| DFB011 | `case_DFB011_loop_phi` | `dfb_source_A.ret` |
| DFB012 | `case_DFB012_switch_merge` | `dfb_source_A.ret`, `dfb_source_B.ret`, `dfb_source_C.ret` |
| DFB020 | `case_DFB020_stack_local` | `dfb_source_A.ret` |
| DFB021 | `case_DFB021_stack_outparam` | `dfb_source_A.ret` |
| DFB022 | `case_DFB022_arg_to_outparam` | `dfb_source_A.ret` |
| DFB023 | `case_DFB023_double_pointer_outparam` | `dfb_source_A.ret` |
| DFB024 | `case_DFB024_global_value_flow` | `dfb_source_A.ret` |
| DFB025 | `case_DFB025_global_field_precise` | `dfb_source_B.ret` |
| DFB026 | `case_DFB026_global_interproc_reader` | `dfb_source_A.ret` |
| DFB040 | `case_DFB040_struct_field_precise` | `dfb_source_B.ret` |
| DFB042 | `case_DFB042_union_alias` | `dfb_source_A.ret` |
| DFB043 | `case_DFB043_array_constant_index` | `dfb_source_B.ret` |
| DFB044 | `case_DFB044_array_variable_index` | `dfb_source_A.ret` |
| DFB045 | `case_DFB045_nested_aggregate_field` | `dfb_source_A.ret` |
| DFB050 | `case_DFB050_identity_call` | `dfb_source_A.ret` |
| DFB051 | `case_DFB051_nested_call` | `dfb_source_A.ret` |
| DFB052 | `case_DFB052_callsite_context` | `dfb_source_A.ret` |
| DFB054 | `case_DFB054_status_outparam` | `dfb_source_A.ret` |
| DFB056 | `case_DFB056_arg_to_ret_summary` | `dfb_source_A.ret` |
| DFB057 | `case_DFB057_struct_field_to_ret_summary` | `dfb_source_A.ret` |
| DFB058 | `case_DFB058_arg_to_outparam_summary` | `dfb_source_A.ret` |
| DFB059 | `case_DFB059_inout_field_update_summary` | `dfb_source_A.ret` |
| DFB060 | `case_DFB060_recursion` | `dfb_source_A.ret` |
| DFB070 | `case_DFB070_function_pointer` | `dfb_source_A.ret` |
| DFB101 | `case_DFB101_tail_call_candidate` | `dfb_source_A.ret` |
| DFB102 | `case_DFB102_signed_unsigned_boundary` | `dfb_source_A.ret` |
| DFB120 | `case_DFB120_memcpy_buffer` | `dfb_source_A.ret` |
| DFB121 | `case_DFB121_memmove_buffer` | `dfb_source_A.ret` |
| DFB130 | `case_DFB130_shared_import_arg_to_ret` | `dfb_source_A.ret` |
| DFB131 | `case_DFB131_shared_import_outparam` | `dfb_source_A.ret` |

## Remaining FAIL Cases

| Case | Function | Missing expected | Notes |
|---|---|---|---|
| DFB030 | `case_DFB030_heap_field` | `dfb_source_A.ret` | Needs heap object and field-sensitive memory model. |
| DFB031 | `case_DFB031_heap_realloc_preserve` | `dfb_source_A.ret` | Needs heap identity preserved across `realloc`. |
| DFB041 | `case_DFB041_pointer_arithmetic_field` | `dfb_source_A.ret` | Needs pointer arithmetic and field offset precision. |
| DFB046 | `case_DFB046_partial_overwrite_subfield` | `dfb_source_A.ret` | Needs subfield and partial overwrite precision. |
| DFB053 | `case_DFB053_large_struct_return` | `dfb_source_long_A.ret` | Needs ABI model for large struct return. |
| DFB055 | `case_DFB055_deep_field_passthrough` | `dfb_source_A.ret` | Needs callee summary for deep field passthrough and indirect sink recognition. |
| DFB071 | `case_DFB071_callback_registration` | `dfb_source_A.ret` | Needs callback registration and later invocation modeling. |
| DFB072 | `case_DFB072_function_pointer_table` | `dfb_source_A.ret` | Needs function pointer table resolution. |
| DFB073 | `case_DFB073_indirect_sink_wrapper` | `dfb_source_A.ret` | Needs indirect sink wrapper recognition. |
| DFB091 | `case_DFB091_tls_value` | `dfb_source_A.ret` | Needs TLS/global region modeling. |
| DFB100 | `case_DFB100_varargs` | `dfb_source_A.ret` | Needs varargs argument recovery. |
| DFB110 | `case_DFB110_setjmp_longjmp` | `dfb_source_A.ret` | Needs non-local control-flow modeling. |
| DFB122 | `case_DFB122_strcpy_buffer` | `dfb_source_A.ret` | Needs string-copy buffer transfer model. |
| DFB123 | `case_DFB123_memset_partial_memcpy` | `dfb_source_A.ret` | Currently finds forbidden `dfb_source_B.ret`; needs byte/subrange precision. |
| DFB200 | `case_DFB200_obf_bcf_multistep` | `dfb_source_A.ret`, `dfb_source_B.ret` | Needs stronger obfuscated CFG/path merge handling. |
| DFB201 | `case_DFB201_obf_fla_statemachine` | `dfb_source_A.ret`, `dfb_source_C.ret` | Needs flattened state-machine CFG handling. |

## Development Notes

The current V6 helper summaries are intentionally narrow. They are useful as a bridge while the real interprocedural design is being built, but the long-term direction should be summary-driven rather than case-name-driven.

Recommended next steps:

1. Done: extend the Ghidra dumper to include reachable helper functions, not only `case_DFB*` entry functions.
2. Done for narrow helper patterns: build per-function Low-PCode summaries for return, outparam, global writes, global reads, and simple pointer dereferences.
3. Add a memory object abstraction for stack/global/heap regions with field offsets and byte ranges.
4. Continue replacing hardcoded helper-name summaries with summaries derived from helper bodies; current v6 still keeps name-hinted summaries as fallback.
5. Add import/library summaries for `malloc`, `free`, `realloc`, `memcpy`, `memmove`, `strcpy`, and `memset`.
6. Add indirect call resolution for function pointers, callback registration, and function pointer tables.
7. Add CFG recovery improvements for obfuscated branch/control-flow flattening cases.

### Reachable Helper Dumper Update

`scripts/lowpcode_json_dumper.py` now starts from all `case_DFB*` roots, follows resolved call references to internal non-source/non-sink functions, and exports those helpers to the same directory. It also writes `low_pcode_extraction_manifest.json` with roots, exported functions, call edges, and skipped terminal/external targets.

Current traversal limit:

```text
REACHABLE_HELPER_MAX_DEPTH = 8
```

The updated dumper still skips `dfb_source_*`, `dfb_sink_*`, external functions, and empty-body targets because those are boundary terminals for the current source/sink analyzer.

### Helper Summary DB Update

`tools/pcode_summary_builder.py` reads helper Low-PCode JSON files from `output/low_pcode/` and writes `output/low_pcode/function_summaries.json`. V6 loads that DB automatically for case analysis when it is present beside the case JSON files.

The current summary builder is intentionally lightweight. It handles direct frame-pointer argument loads, returns, outparam stores, one-level double-pointer stores, global writes, global reads, direct `dfb_source_*` returns, and simple `deref(argN)` returns. It does not yet model heap identity, byte ranges, varargs, non-local control flow, indirect call target resolution, or obfuscated CFG recovery.

## Useful Commands

Run one case:

```powershell
python tools\pcode_ssa_report_v6.py output\low_pcode\case_DFB021_stack_outparam_low_pcode.json output\v6_batch\reports\case_DFB021_stack_outparam_v6_report.txt
```

Run all dumped cases:

```powershell
python tools\pcode_summary_builder.py output\low_pcode output\low_pcode\function_summaries.json
python tools\pcode_ssa_batch_v6.py output\low_pcode output\v6_batch
```

Check syntax:

```powershell
python -m py_compile tools\pcode_summary_builder.py tools\pcode_ssa_report_v6.py tools\pcode_ssa_batch_v6.py scripts\lowpcode_json_dumper.py
```
