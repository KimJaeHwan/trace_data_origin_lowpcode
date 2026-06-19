# V7 Low-PCode Batch Expected Validation

## Summary

- FAIL: 13
- PASS: 37

## Cases

| verdict | case | function | actual | expected | report |
|---|---|---|---|---|---|
| PASS | DFB001 | case_DFB001_direct_value | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB001_direct_value_v7_report.txt |
| PASS | DFB002 | case_DFB002_arithmetic_value | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB002_arithmetic_value_v7_report.txt |
| PASS | DFB003 | case_DFB003_cast_value | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB003_cast_value_v7_report.txt |
| PASS | DFB010 | case_DFB010_branch_phi | dfb_source_A.ret, dfb_source_B.ret | dfb_source_A.ret, dfb_source_B.ret | reports/case_DFB010_branch_phi_v7_report.txt |
| PASS | DFB011 | case_DFB011_loop_phi | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB011_loop_phi_v7_report.txt |
| PASS | DFB012 | case_DFB012_switch_merge | dfb_source_A.ret, dfb_source_B.ret, dfb_source_C.ret | dfb_source_A.ret, dfb_source_B.ret, dfb_source_C.ret | reports/case_DFB012_switch_merge_v7_report.txt |
| PASS | DFB020 | case_DFB020_stack_local | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB020_stack_local_v7_report.txt |
| PASS | DFB021 | case_DFB021_stack_outparam | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB021_stack_outparam_v7_report.txt |
| PASS | DFB022 | case_DFB022_arg_to_outparam | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB022_arg_to_outparam_v7_report.txt |
| PASS | DFB023 | case_DFB023_double_pointer_outparam | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB023_double_pointer_outparam_v7_report.txt |
| PASS | DFB024 | case_DFB024_global_value_flow | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB024_global_value_flow_v7_report.txt |
| PASS | DFB025 | case_DFB025_global_field_precise | dfb_source_B.ret | dfb_source_B.ret | reports/case_DFB025_global_field_precise_v7_report.txt |
| PASS | DFB026 | case_DFB026_global_interproc_reader | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB026_global_interproc_reader_v7_report.txt |
| FAIL | DFB030 | case_DFB030_heap_field | - | dfb_source_A.ret | reports/case_DFB030_heap_field_v7_report.txt |
| FAIL | DFB031 | case_DFB031_heap_realloc_preserve | - | dfb_source_A.ret | reports/case_DFB031_heap_realloc_preserve_v7_report.txt |
| PASS | DFB040 | case_DFB040_struct_field_precise | dfb_source_B.ret | dfb_source_B.ret | reports/case_DFB040_struct_field_precise_v7_report.txt |
| FAIL | DFB041 | case_DFB041_pointer_arithmetic_field | - | dfb_source_A.ret | reports/case_DFB041_pointer_arithmetic_field_v7_report.txt |
| PASS | DFB042 | case_DFB042_union_alias | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB042_union_alias_v7_report.txt |
| PASS | DFB043 | case_DFB043_array_constant_index | dfb_source_B.ret | dfb_source_B.ret | reports/case_DFB043_array_constant_index_v7_report.txt |
| PASS | DFB044 | case_DFB044_array_variable_index | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB044_array_variable_index_v7_report.txt |
| PASS | DFB045 | case_DFB045_nested_aggregate_field | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB045_nested_aggregate_field_v7_report.txt |
| PASS | DFB046 | case_DFB046_partial_overwrite_subfield | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB046_partial_overwrite_subfield_v7_report.txt |
| PASS | DFB050 | case_DFB050_identity_call | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB050_identity_call_v7_report.txt |
| PASS | DFB051 | case_DFB051_nested_call | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB051_nested_call_v7_report.txt |
| PASS | DFB052 | case_DFB052_callsite_context | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB052_callsite_context_v7_report.txt |
| FAIL | DFB053 | case_DFB053_large_struct_return | - | dfb_source_long_A.ret | reports/case_DFB053_large_struct_return_v7_report.txt |
| PASS | DFB054 | case_DFB054_status_outparam | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB054_status_outparam_v7_report.txt |
| FAIL | DFB055 | case_DFB055_deep_field_passthrough | - | dfb_source_A.ret | reports/case_DFB055_deep_field_passthrough_v7_report.txt |
| PASS | DFB056 | case_DFB056_arg_to_ret_summary | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB056_arg_to_ret_summary_v7_report.txt |
| PASS | DFB057 | case_DFB057_struct_field_to_ret_summary | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB057_struct_field_to_ret_summary_v7_report.txt |
| PASS | DFB058 | case_DFB058_arg_to_outparam_summary | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB058_arg_to_outparam_summary_v7_report.txt |
| PASS | DFB059 | case_DFB059_inout_field_update_summary | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB059_inout_field_update_summary_v7_report.txt |
| PASS | DFB060 | case_DFB060_recursion | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB060_recursion_v7_report.txt |
| PASS | DFB070 | case_DFB070_function_pointer | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB070_function_pointer_v7_report.txt |
| FAIL | DFB071 | case_DFB071_callback_registration | - | dfb_source_A.ret | reports/case_DFB071_callback_registration_v7_report.txt |
| FAIL | DFB072 | case_DFB072_function_pointer_table | - | dfb_source_A.ret | reports/case_DFB072_function_pointer_table_v7_report.txt |
| FAIL | DFB073 | case_DFB073_indirect_sink_wrapper | - | dfb_source_A.ret | reports/case_DFB073_indirect_sink_wrapper_v7_report.txt |
| FAIL | DFB091 | case_DFB091_tls_value | - | dfb_source_A.ret | reports/case_DFB091_tls_value_v7_report.txt |
| FAIL | DFB100 | case_DFB100_varargs | - | dfb_source_A.ret | reports/case_DFB100_varargs_v7_report.txt |
| PASS | DFB101 | case_DFB101_tail_call_candidate | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB101_tail_call_candidate_v7_report.txt |
| PASS | DFB102 | case_DFB102_signed_unsigned_boundary | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB102_signed_unsigned_boundary_v7_report.txt |
| FAIL | DFB110 | case_DFB110_setjmp_longjmp | - | dfb_source_A.ret | reports/case_DFB110_setjmp_longjmp_v7_report.txt |
| PASS | DFB120 | case_DFB120_memcpy_buffer | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB120_memcpy_buffer_v7_report.txt |
| PASS | DFB121 | case_DFB121_memmove_buffer | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB121_memmove_buffer_v7_report.txt |
| PASS | DFB122 | case_DFB122_strcpy_buffer | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB122_strcpy_buffer_v7_report.txt |
| PASS | DFB123 | case_DFB123_memset_partial_memcpy | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB123_memset_partial_memcpy_v7_report.txt |
| PASS | DFB130 | case_DFB130_shared_import_arg_to_ret | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB130_shared_import_arg_to_ret_v7_report.txt |
| PASS | DFB131 | case_DFB131_shared_import_outparam | dfb_source_A.ret | dfb_source_A.ret | reports/case_DFB131_shared_import_outparam_v7_report.txt |
| FAIL | DFB200 | case_DFB200_obf_bcf_multistep | dfb_source_A.ret | dfb_source_A.ret, dfb_source_B.ret | reports/case_DFB200_obf_bcf_multistep_v7_report.txt |
| FAIL | DFB201 | case_DFB201_obf_fla_statemachine | - | dfb_source_A.ret, dfb_source_C.ret | reports/case_DFB201_obf_fla_statemachine_v7_report.txt |
