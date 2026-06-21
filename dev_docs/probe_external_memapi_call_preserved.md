# External MemAPI Call-Preserved Probe

Purpose: verify the `ExternalSummaryProvider` path when `memcpy`, `memmove`,
`strcpy`, `memset`, and partial `memcpy` survive as real external call targets.

The default `samples/low_pcode` regression root intentionally stays unchanged.
Current DFB120/DFB121 binaries are compiler-lowered inline-copy forms, which are
valuable regression assets for ordinary low-pcode load/store range analysis.
Replacing them would lose that coverage.

This probe is kept as a separate fixture root:

```text
samples/low_pcode_probes/external_memapi_call_preserved/
```

It is not part of full regression by default. Full regression is already
expensive, and this probe tests one narrow question: whether trusted external
memory API summaries work when the call target is preserved. Run it only as a
focused Phase 6 check.

## Build Shape

The probe uses a small PE x64 DLL built directly from:

```text
tdo_testbed/src/cases_memory_api.c
tdo_testbed/src/dfbench_sources_sinks.c
```

It is compiled with builtin expansion disabled:

```text
-fno-builtin
-fno-builtin-memcpy
-fno-builtin-memmove
-fno-builtin-memset
-fno-builtin-strcpy
```

The resulting import table must contain `memcpy`, `memmove`, `memset`, and
`strcpy`. This is checked before trusting the probe.

## Local Verification

2026-06-21 local probe:

```text
x86_64-w64-mingw32-objdump -p output/probes/external_memapi_call_preserved/bin/dfbench_external_memapi_probe_x64.dll
```

Confirmed preserved imports:

```text
memcpy
memmove
memset
strcpy
```

Confirmed extracted low-pcode call targets:

```text
DFB120 -> memcpy
DFB121 -> memmove
DFB122 -> strcpy
DFB123 -> memset + memcpy
```

Focused regression:

```text
.venv/bin/python -B tools/pcode_slicegraph_v8_phase1.py \
  samples/low_pcode_probes/external_memapi_call_preserved \
  output/v8_probe_external_memapi_call_preserved \
  expected \
  --cases case_DFB120 case_DFB121 case_DFB122 case_DFB123
```

Result:

```text
PASS 4 / FAIL 0
```

## Policy

- Do not overwrite `samples/low_pcode`.
- Do not add this probe to default full regression.
- Do not commit generated probe JSON or Ghidra project output.
- Keep the analysis convention-free: external API names are consumed only by
  the external summary provider, and resulting graph edges carry provider,
  effect, trust, provenance, and cache-key metadata.
