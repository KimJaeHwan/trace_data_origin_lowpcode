DATA_SLICE_EDGES = {
    "data",
    "memory",
    "summary_data",
    "summary_memory",
    "call_in_stack",
    "call_in_reg",
    "call_in_mem",
    "call_out_reg",
    "call_out_mem",
    "call_out_global",
}

DATA_CONTROL_SLICE_EDGES = DATA_SLICE_EDGES | {"control", "call_control"}
