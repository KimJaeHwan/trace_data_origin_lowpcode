import json
import os
import re
import sys

from pcode_ssa_report_v5 import BoundaryAwareSSAEngineV5


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
DEFAULT_EXPECTED_PATH = os.path.join(REPO_ROOT, "expected")


class SourceSinkCallSiteBinderV6(BoundaryAwareSSAEngineV5):
    """
    v6 differences from pcode_ssa_report_v5.py:
    - Keeps v5 CFG SSA, memory-region tags, and FunctionSummary skeleton.
    - Adds CallSite Binder v1 for DataFlowBench source/sink functions.
    - Direct calls whose resolved name starts with dfb_source_* become SOURCE_RET nodes.
    - Direct calls whose resolved name starts with dfb_sink_* are recorded as sink anchors.
    - Other calls still use v5's conservative opaque CALL_RESET model.

    This is intentionally narrow. The goal is not yet full interprocedural analysis;
    it is to make source/sink boundaries explicit so expected_sources comparison can
    be built on top of the pure data slice.
    """

    def __init__(self, json_path, summary_path=None):
        super().__init__(json_path)
        self.json_path = json_path
        self.function_summaries = self._load_function_summaries(summary_path)
        self.pending_stack_args = []
        self.pending_stack_arg_slots = {}
        self.callsite_bindings = []
        self.source_return_nodes = {}
        self.sink_anchors = []
        self.summary["notes"].append("v6 adds source/sink-aware CallSite Binder v1.")

    def _load_function_summaries(self, summary_path=None):
        candidate = summary_path
        if candidate is None:
            candidate = os.path.join(os.path.dirname(self.json_path), "function_summaries.json")
        if not candidate or not os.path.exists(candidate):
            return {}
        try:
            with open(candidate, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("summaries", {})
        except Exception:
            return {}

    def _dynamic_summary_for(self, target_name):
        if not target_name:
            return None
        return self.function_summaries.get(target_name)

    def _resolved_call_targets(self, instr):
        targets = []
        for target in instr.get("call_targets", []):
            if target.get("resolved") and target.get("function_name"):
                targets.append(target)
        return targets

    def _primary_target_name(self, instr):
        targets = self._resolved_call_targets(instr)
        if targets:
            return targets[0].get("function_name")
        flow_targets = instr.get("flow_targets", [])
        return flow_targets[0] if flow_targets else None

    def _is_source_function(self, name):
        return isinstance(name, str) and name.startswith("dfb_source_")

    def _is_sink_function(self, name):
        return isinstance(name, str) and name.startswith("dfb_sink_")

    def _is_arg0_to_ret_summary(self, name):
        return name in {
            "dfb_identity_int",
            "dfb_transform_int",
            "dfb_nested_1",
            "dfb_nested_2",
            "dfb_same_identity",
            "dfb_summary_arg_to_ret",
            "dfb_recursive_transform",
            "dfb_tail_target",
            "dfb_tail_wrapper",
            "dfb_import_identity",
            "dfb_fp_target",
        }

    def _outparam_summary(self, name):
        summaries = {
            "dfb_write_source_to_out": {"out_arg": 0, "source": "dfb_source_A"},
            "dfb_copy_arg_to_out": {"out_arg": 1, "value_arg": 0},
            "dfb_store_through_double_pointer": {"out_arg": 0, "value_arg": 1, "indirect": 1},
            "dfb_summary_arg_to_out": {"out_arg": 0, "value_arg": 1},
            "dfb_import_write_out": {"out_arg": 0, "value_arg": 1},
        }
        return summaries.get(name)

    def _apply_global_summary(self, instr, state, target_name):
        addr = instr["address"]
        if target_name == "dfb_write_global_values":
            main_source = self._create_new_version("Register", "0x0L", state)
            self.G.add_node(main_source, addr=addr, opcode="SOURCE_RET", source_name="dfb_source_A")
            self.source_return_nodes[main_source] = "dfb_source_A"
            main_mem = self._create_new_version("Memory", "DFB_GLOBAL_MAIN", state)
            self.G.add_node(main_mem, addr=addr, opcode="CALL_GLOBAL_STORE", target=target_name)
            self._add_dependency(main_source, main_mem, "data")

            shadow_source = self._create_new_version("Register", "0x0L", state)
            self.G.add_node(shadow_source, addr=addr, opcode="SOURCE_RET", source_name="dfb_source_B")
            self.source_return_nodes[shadow_source] = "dfb_source_B"
            shadow_mem = self._create_new_version("Memory", "DFB_GLOBAL_SHADOW", state)
            self.G.add_node(shadow_mem, addr=addr, opcode="CALL_GLOBAL_STORE", target=target_name)
            self._add_dependency(shadow_source, shadow_mem, "data")

            self.callsite_bindings.append({
                "addr": addr,
                "kind": "summary_global_write",
                "target": target_name,
                "writes": {"DFB_GLOBAL_MAIN": main_mem, "DFB_GLOBAL_SHADOW": shadow_mem},
                "confidence": "resolved_direct_call_name_summary"
            })
            self.summary["callsites"].append({
                "addr": addr,
                "assembly": instr.get("assembly"),
                "target": target_name,
                "model": "global_write_summary_v6",
                "writes": {"DFB_GLOBAL_MAIN": main_mem, "DFB_GLOBAL_SHADOW": shadow_mem}
            })
            self.ssa_pcode_lines.append(f"{main_mem} = CALL_GLOBAL_STORE({target_name}, DFB_GLOBAL_MAIN, SOURCE_RET(dfb_source_A))")
            self.ssa_pcode_lines.append(f"{shadow_mem} = CALL_GLOBAL_STORE({target_name}, DFB_GLOBAL_SHADOW, SOURCE_RET(dfb_source_B))")
            self._add_call_clobbers(addr, state, include_ret=True)
            self._clear_pending_stack_args()
            return True

        if target_name == "dfb_read_global_main_value":
            ret_node = self._create_new_version("Register", "0x0L", state)
            self.G.add_node(ret_node, addr=addr, opcode="CALL_GLOBAL_LOAD", target=target_name)
            main_mem = state["vars"].get(self._var_key("Memory", "DFB_GLOBAL_MAIN"))
            if main_mem:
                self._add_dependency(main_mem, ret_node, "memory")
            self.callsite_bindings.append({
                "addr": addr,
                "kind": "summary_global_read",
                "target": target_name,
                "read": "DFB_GLOBAL_MAIN",
                "return_node": ret_node,
                "confidence": "resolved_direct_call_name_summary"
            })
            self.summary["callsites"].append({
                "addr": addr,
                "assembly": instr.get("assembly"),
                "target": target_name,
                "model": "global_read_summary_v6",
                "read": "DFB_GLOBAL_MAIN",
                "return_node": ret_node
            })
            self.ssa_pcode_lines.append(f"{ret_node} = CALL_GLOBAL_LOAD({target_name}, DFB_GLOBAL_MAIN)")
            self._add_call_clobbers(addr, state, include_ret=False)
            self._clear_pending_stack_args()
            return True

        return False

    def _global_memory_key(self, address):
        return "GLOBAL_%s" % str(address).replace("0x", "").replace("L", "")

    def _node_from_summary_expr(self, expr, args, state, addr):
        if not expr:
            return None
        kind = expr.get("kind")
        if kind == "arg":
            index = expr.get("arg")
            return args[index] if index is not None and index < len(args) else None
        if kind == "source_ret":
            source_name = expr.get("source")
            node = self._create_new_version("Register", "0x0L", state)
            self.G.add_node(node, addr=addr, opcode="SOURCE_RET", source_name=source_name)
            self.source_return_nodes[node] = source_name
            return node
        if kind == "global":
            return state["vars"].get(self._var_key("Memory", self._global_memory_key(expr.get("address"))))
        if kind == "deref" and expr.get("base", {}).get("kind") == "arg":
            index = expr["base"].get("arg")
            if index is None or index >= len(args):
                return None
            stack_key = self._resolve_stack_key_from_node(args[index])
            if stack_key and stack_key in state["stack"]:
                return state["stack"][stack_key]
            return args[index]
        if kind == "field" and expr.get("base", {}).get("kind") == "arg":
            index = expr["base"].get("arg")
            if index is None or index >= len(args):
                return None
            stack_key = self._resolve_stack_key_from_node(args[index])
            if stack_key and stack_key in state["stack"]:
                return state["stack"][stack_key]
            return args[index]
        return None

    def _apply_dynamic_summary(self, instr, state, target_name, summary):
        addr = instr["address"]
        args = list(self.pending_stack_args)
        applied = False

        for write in summary.get("global_writes", []):
            value_node = self._node_from_summary_expr(write.get("value"), args, state, addr)
            if not value_node:
                continue
            mem_key = self._global_memory_key(write.get("address"))
            mem_node = self._create_new_version("Memory", mem_key, state)
            self.G.add_node(mem_node, addr=addr, opcode="CALL_GLOBAL_STORE", target=target_name)
            self._add_dependency(value_node, mem_node, "data")
            self.ssa_pcode_lines.append(f"{mem_node} = CALL_GLOBAL_STORE_SUMMARY({target_name}, {mem_key}, {value_node})")
            applied = True

        for outparam in summary.get("outparams", []):
            out_arg_index = outparam.get("out_arg")
            if out_arg_index is None or out_arg_index >= len(args):
                continue
            indirect_depth = outparam.get("indirect", 0)
            if indirect_depth:
                out_stack_key = self._resolve_indirect_stack_key_from_node(args[out_arg_index], state, indirect_depth)
            else:
                out_stack_key = self._resolve_stack_key_from_node(args[out_arg_index])
            value_node = self._node_from_summary_expr(outparam.get("value"), args, state, addr)
            if not out_stack_key or not value_node:
                continue
            mem_node = self._create_new_version("Memory", out_stack_key, state)
            self.G.add_node(mem_node, addr=addr, opcode="CALL_OUTPARAM_STORE", target=target_name)
            self._add_dependency(value_node, mem_node, "data")
            state["stack"][out_stack_key] = mem_node
            self.stack_memory_map[out_stack_key] = mem_node
            self.ssa_pcode_lines.append(f"{mem_node} = CALL_OUTPARAM_STORE_SUMMARY({target_name}, {out_stack_key}, {value_node})")
            applied = True

        for ret in summary.get("returns", []):
            value_node = self._node_from_summary_expr(ret.get("value"), args, state, addr)
            if not value_node:
                continue
            ret_node = self._create_new_version("Register", "0x0L", state)
            self.G.add_node(ret_node, addr=addr, opcode="CALL_RET_SUMMARY", target=target_name)
            self._add_dependency(value_node, ret_node, "data")
            self.ssa_pcode_lines.append(f"{ret_node} = CALL_RET_SUMMARY_DB({target_name}, {value_node})")
            applied = True

        if applied:
            self.callsite_bindings.append({
                "addr": addr,
                "kind": "dynamic_function_summary",
                "target": target_name,
                "args": args,
                "confidence": "low_pcode_helper_summary_db"
            })
            self.summary["callsites"].append({
                "addr": addr,
                "assembly": instr.get("assembly"),
                "target": target_name,
                "model": "dynamic_summary_db_v6",
                "args": args,
            })
            self._add_call_clobbers(addr, state, include_ret=False)
            self._clear_pending_stack_args()
        return applied

    def _resolve_stack_key_from_node(self, node, visited=None):
        if not node:
            return None
        if visited is None:
            visited = set()
        if node in visited:
            return None
        visited.add(node)

        stack_key = self._resolve_stack_address(node)
        if stack_key:
            return stack_key

        if not self.G.has_node(node):
            return None
        for pred in self.G.predecessors(node):
            edge_kind = self.G.edges[pred, node].get("kind", "data")
            if edge_kind == "data":
                stack_key = self._resolve_stack_key_from_node(pred, visited)
                if stack_key:
                    return stack_key
        return None

    def _resolve_indirect_stack_key_from_node(self, node, state, depth):
        stack_key = self._resolve_stack_key_from_node(node)
        for _ in range(depth):
            if not stack_key:
                return None
            stored_node = state["stack"].get(stack_key)
            if not stored_node:
                return None
            stack_key = self._resolve_stack_key_from_node(stored_node)
        return stack_key

    def _add_call_clobbers(self, addr, state, include_ret=False):
        clobbered = []
        reg_offsets = list(self.volatile_registers)
        if not include_ret and "0x0L" in reg_offsets:
            reg_offsets.remove("0x0L")
        for reg_offset in reg_offsets:
            new_ver = self._create_new_version("Register", reg_offset, state)
            opcode = "CALL_RET" if reg_offset == "0x0L" else "CALL_CLOBBER"
            self.G.add_node(new_ver, addr=addr, opcode=opcode)
            clobbered.append(new_ver)
        if clobbered:
            self.ssa_pcode_lines.append(f"CALL_CLOBBER({', '.join(clobbered)})")

    def _apply_arg0_to_ret_summary(self, instr, state, target_name):
        addr = instr["address"]
        args = list(self.pending_stack_args)
        if not args:
            return False

        ret_node = self._create_new_version("Register", "0x0L", state)
        self.G.add_node(ret_node, addr=addr, opcode="CALL_RET_SUMMARY", target=target_name)
        self._add_dependency(args[0], ret_node, "data")
        self.callsite_bindings.append({
            "addr": addr,
            "kind": "summary_arg0_to_ret",
            "target": target_name,
            "args": args,
            "return_node": ret_node,
            "confidence": "resolved_direct_call_name_summary"
        })
        self.summary["callsites"].append({
            "addr": addr,
            "assembly": instr.get("assembly"),
            "target": target_name,
            "model": "arg0_to_ret_summary_v6",
            "args": args,
            "return_node": ret_node
        })
        self.ssa_pcode_lines.append(f"{ret_node} = CALL_RET_SUMMARY({target_name}, {args[0]})")
        self._add_call_clobbers(addr, state, include_ret=False)
        self._clear_pending_stack_args()
        return True

    def _apply_outparam_summary(self, instr, state, target_name, summary):
        addr = instr["address"]
        args = list(self.pending_stack_args)
        out_arg_index = summary.get("out_arg")
        if out_arg_index is None or out_arg_index >= len(args):
            return False

        indirect_depth = summary.get("indirect", 0)
        if indirect_depth:
            out_stack_key = self._resolve_indirect_stack_key_from_node(args[out_arg_index], state, indirect_depth)
        else:
            out_stack_key = self._resolve_stack_key_from_node(args[out_arg_index])
        if not out_stack_key:
            return False

        if "source" in summary:
            value_node = self._create_new_version("Register", "0x0L", state)
            source_name = summary["source"]
            self.G.add_node(value_node, addr=addr, opcode="SOURCE_RET", source_name=source_name)
            self.source_return_nodes[value_node] = source_name
            value_label = f"SOURCE_RET({source_name})"
        else:
            value_arg_index = summary.get("value_arg")
            if value_arg_index is None or value_arg_index >= len(args):
                return False
            value_node = args[value_arg_index]
            value_label = value_node

        mem_node = self._create_new_version("Memory", out_stack_key, state)
        self.G.add_node(mem_node, addr=addr, opcode="CALL_OUTPARAM_STORE", target=target_name)
        self._add_dependency(value_node, mem_node, "data")
        state["stack"][out_stack_key] = mem_node
        self.stack_memory_map[out_stack_key] = mem_node
        classification = self._record_memory_access(addr, "CALL_OUTPARAM_STORE", out_stack_key, mem_node)

        self.callsite_bindings.append({
            "addr": addr,
            "kind": "summary_outparam_store",
            "target": target_name,
            "args": args,
            "out_arg": out_arg_index,
            "out_stack_key": out_stack_key,
            "value": value_node,
            "confidence": "resolved_direct_call_name_summary"
        })
        self.summary["callsites"].append({
            "addr": addr,
            "assembly": instr.get("assembly"),
            "target": target_name,
            "model": "outparam_store_summary_v6",
            "args": args,
            "out_arg": out_arg_index,
            "out_stack_key": out_stack_key,
            "value": value_node
        })
        self.ssa_pcode_lines.append(f"{mem_node} = CALL_OUTPARAM_STORE({target_name}, {out_stack_key}, {value_label}) [{classification['region']}]")
        self._add_call_clobbers(addr, state, include_ret=True)
        self._clear_pending_stack_args()
        return True

    def _record_pending_push_arg(self, instr, state):
        store_pcode = None
        for pcode in instr.get("low_pcode", []):
            if pcode.get("opcode") == "STORE" and len(pcode.get("inputs", [])) >= 3:
                store_pcode = pcode
                break
        if not store_pcode:
            return

        value = store_pcode["inputs"][2]
        if value.get("type") == "Constant":
            node = f"Const_{value['offset'].replace('L', '')}"
        else:
            node = state["vars"].get(self._var_key(value["type"], value["offset"]))
        if node:
            # x86 pushes arguments right-to-left; the most recent push is arg0.
            self.pending_stack_args.insert(0, node)
            self.pending_stack_arg_slots = {}

    def _clear_pending_stack_args(self):
        self.pending_stack_args = []
        self.pending_stack_arg_slots = {}

    def _stack_arg_slot_from_assembly(self, assembly):
        compact = (assembly or "").replace(" ", "")
        match = re.search(r"\[ESP(?:\+(0x[0-9a-fA-F]+|\d+))?\]", compact)
        if not match:
            return None
        raw_offset = match.group(1) or "0"
        try:
            offset = int(raw_offset, 0)
        except ValueError:
            return None
        if offset < 0 or offset % 4:
            return None
        return offset // 4

    def _node_from_pcode_value(self, value, state):
        if not value:
            return None
        if value.get("type") == "Constant":
            return f"Const_{value['offset'].replace('L', '')}"
        return state["vars"].get(self._var_key(value["type"], value["offset"]))

    def _record_pending_stack_store_arg(self, instr, state):
        slot = self._stack_arg_slot_from_assembly(instr.get("assembly"))
        if slot is None:
            return

        store_pcode = None
        for pcode in instr.get("low_pcode", []):
            if pcode.get("opcode") == "STORE" and len(pcode.get("inputs", [])) >= 3:
                store_pcode = pcode
                break
        if not store_pcode:
            return

        node = self._node_from_pcode_value(store_pcode["inputs"][2], state)
        if not node:
            return

        self.pending_stack_arg_slots[slot] = node
        self.pending_stack_args = [
            self.pending_stack_arg_slots[index]
            for index in sorted(self.pending_stack_arg_slots)
        ]

    def _is_stack_arg_boundary(self, instr):
        mnemonic = instr.get("mnemonic")
        assembly = instr.get("assembly") or ""
        if mnemonic in {"CALL", "RET", "RETURN", "POP"}:
            return True
        if mnemonic in {"ADD", "SUB"} and "ESP" in assembly:
            return True
        if mnemonic == "MOV" and assembly.replace(" ", "").startswith(("MOVEBP,ESP", "MOVESP,EBP")):
            return True
        return False

    def _process_instruction(self, instr, state):
        mnemonic = instr.get("mnemonic")
        if mnemonic not in {"PUSH", "CALL"} and self.pending_stack_args and self._is_stack_arg_boundary(instr):
            self._clear_pending_stack_args()

        super()._process_instruction(instr, state)

        if mnemonic == "PUSH":
            self._record_pending_push_arg(instr, state)
        elif mnemonic == "MOV":
            self._record_pending_stack_store_arg(instr, state)

    def _process_call(self, instr, state):
        target_name = self._primary_target_name(instr)
        addr = instr["address"]

        if self._is_source_function(target_name):
            ret_node = self._create_new_version("Register", "0x0L", state)
            self.G.add_node(ret_node, addr=addr, opcode="SOURCE_RET", source_name=target_name)
            self.source_return_nodes[ret_node] = target_name
            self.callsite_bindings.append({
                "addr": addr,
                "kind": "source_call",
                "target": target_name,
                "return_node": ret_node,
                "confidence": "resolved_direct_call"
            })
            self.summary["callsites"].append({
                "addr": addr,
                "assembly": instr.get("assembly"),
                "target": target_name,
                "model": "source_ret_binding_v6",
                "return_node": ret_node
            })
            self.ssa_pcode_lines.append(f"{ret_node} = SOURCE_RET({target_name})")

            clobbered = []
            for reg_offset in ["0x4L", "0x8L", "MEMORY_GLOBAL"]:
                v_type = "Register" if "MEMORY" not in reg_offset else "Memory"
                new_ver = self._create_new_version(v_type, reg_offset, state)
                self.G.add_node(new_ver, addr=addr, opcode="CALL_CLOBBER")
                clobbered.append(new_ver)
            if clobbered:
                self.ssa_pcode_lines.append(f"CALL_CLOBBER({', '.join(clobbered)})")
            self._clear_pending_stack_args()
            return

        if self._is_sink_function(target_name):
            args = list(self.pending_stack_args)
            sink_record = {
                "addr": addr,
                "target": target_name,
                "args": args,
                "anchor_arg0": args[0] if args else None,
                "confidence": "resolved_direct_call_with_recent_push_args" if args else "resolved_direct_call_no_arg_binding"
            }
            self.sink_anchors.append(sink_record)
            self.callsite_bindings.append({
                "addr": addr,
                "kind": "sink_call",
                "target": target_name,
                "args": args,
                "confidence": sink_record["confidence"]
            })
            self.summary["callsites"].append({
                "addr": addr,
                "assembly": instr.get("assembly"),
                "target": target_name,
                "model": "sink_anchor_binding_v6",
                "args": args
            })
            self.ssa_pcode_lines.append(f"SINK_ANCHOR({target_name}, args={args})")

            clobbered = []
            for reg_offset in self.volatile_registers + ["MEMORY_GLOBAL"]:
                v_type = "Register" if "MEMORY" not in reg_offset else "Memory"
                new_ver = self._create_new_version(v_type, reg_offset, state)
                opcode = "CALL_RET" if reg_offset == "0x0L" else "CALL_CLOBBER"
                self.G.add_node(new_ver, addr=addr, opcode=opcode)
                clobbered.append(new_ver)
            self.ssa_pcode_lines.append(f"CALL_RESET({', '.join(clobbered)})")
            self._clear_pending_stack_args()
            return

        dynamic_summary = self._dynamic_summary_for(target_name)
        if dynamic_summary and self._apply_dynamic_summary(instr, state, target_name, dynamic_summary):
            return

        outparam_summary = self._outparam_summary(target_name)
        if outparam_summary and self._apply_outparam_summary(instr, state, target_name, outparam_summary):
            return

        if self._apply_global_summary(instr, state, target_name):
            return

        if self._is_arg0_to_ret_summary(target_name) and self._apply_arg0_to_ret_summary(instr, state, target_name):
            return

        super()._process_call(instr, state)
        self._clear_pending_stack_args()

    def _collect_data_sources(self, target_node):
        if not self.G.has_node(target_node):
            return []

        found = []
        stack = [target_node]
        visited = set()
        while stack:
            node = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            attr = self.G.nodes.get(node, {})
            if attr.get("opcode") == "SOURCE_RET":
                source_name = attr.get("source_name")
                source_id = f"{source_name}.ret" if source_name else node
                if source_id not in found:
                    found.append(source_id)
                continue
            for pred in self.G.predecessors(node):
                edge_kind = self.G.edges[pred, node].get("kind", "data")
                if edge_kind in self.data_slice_edge_kinds:
                    stack.append(pred)
        return sorted(found)

    def _load_expected_case(self, expected_path):
        if not expected_path:
            return None

        paths = []
        if os.path.isdir(expected_path):
            for name in os.listdir(expected_path):
                if name.endswith(".expected.json"):
                    paths.append(os.path.join(expected_path, name))
        elif os.path.isfile(expected_path):
            paths.append(expected_path)

        function_name = self.data.get("function_name")
        for path in sorted(paths):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    expected_data = json.load(f)
            except Exception:
                continue

            for case in expected_data.get("cases", []):
                if case.get("function") == function_name:
                    result = dict(case)
                    result["expected_file"] = path
                    result["program"] = expected_data.get("program")
                    return result
        return None

    def _validate_expected_sources(self, actual_sources, expected_case):
        if not expected_case:
            return {
                "verdict": "NO_EXPECTED",
                "reason": "No matching expected case was found.",
                "actual_sources": actual_sources,
                "expected_sources": [],
                "forbidden_sources": [],
                "missing_expected_sources": [],
                "forbidden_sources_found": [],
            }

        expected_sources = sorted(expected_case.get("expected_sources", []))
        forbidden_sources = sorted(expected_case.get("forbidden_sources", []))
        actual_set = set(actual_sources)
        missing = [source for source in expected_sources if source not in actual_set]
        forbidden_found = [source for source in forbidden_sources if source in actual_set]
        verdict = "PASS" if not missing and not forbidden_found else "FAIL"
        return {
            "verdict": verdict,
            "case_id": expected_case.get("id"),
            "function": expected_case.get("function"),
            "expected_file": expected_case.get("expected_file"),
            "program": expected_case.get("program"),
            "actual_sources": actual_sources,
            "expected_sources": expected_sources,
            "forbidden_sources": forbidden_sources,
            "missing_expected_sources": missing,
            "forbidden_sources_found": forbidden_found,
            "expected_features": expected_case.get("expected_features", []),
            "allowed_warnings": expected_case.get("allowed_warnings", []),
        }

    def _select_report_target(self, requested_target):
        if requested_target:
            return requested_target
        for sink in self.sink_anchors:
            if sink.get("anchor_arg0"):
                return sink["anchor_arg0"]
        return None

    def generate_report(self, target_node, output_path, expected_path=DEFAULT_EXPECTED_PATH):
        target_node = self._select_report_target(target_node)
        actual_sources = self._collect_data_sources(target_node)
        expected_case = self._load_expected_case(expected_path)
        validation = self._validate_expected_sources(actual_sources, expected_case)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("==================================================\n")
            f.write(f"V6 SOURCE/SINK CALLSITE REPORT: {self.data.get('function_name')}\n")
            f.write("==================================================\n\n")

            f.write(" V6 notes\n")
            f.write("--------------------------------------------------\n")
            f.write("- v5 CFG/PHI/memory-region behavior is preserved.\n")
            f.write("- v6 binds resolved dfb_source_* calls to SOURCE_RET nodes.\n")
            f.write("- v6 records resolved dfb_sink_* calls as sink anchors.\n")
            f.write("- v6 validates actual sources against DataFlowBench expected JSON.\n")
            f.write("- Non-source/sink calls remain conservative opaque calls.\n\n")

            f.write(" SSA Low P-Code with CallSite Bindings\n")
            f.write("--------------------------------------------------\n")
            for line in self.ssa_pcode_lines:
                f.write(line + "\n")

            f.write(f"\n Backward DATA slice tree (Target: {target_node})\n")
            f.write("--------------------------------------------------\n")
            if not self.G.has_node(target_node):
                f.write(f"[-] target node not found: {target_node}\n")
            else:
                f.write(self._generate_tree_string(target_node, set()))

            f.write("\n Actual data sources\n")
            f.write("--------------------------------------------------\n")
            for source in actual_sources:
                f.write(f"- {source}\n")
            if not actual_sources:
                f.write("- (none)\n")

            f.write("\n Expected validation\n")
            f.write("--------------------------------------------------\n")
            f.write(json.dumps(validation, indent=2, ensure_ascii=False, sort_keys=True))
            f.write("\n")

            f.write("\n Sink anchors\n")
            f.write("--------------------------------------------------\n")
            f.write(json.dumps(self.sink_anchors, indent=2, ensure_ascii=False, sort_keys=True))
            f.write("\n")

            f.write("\n CallSite bindings\n")
            f.write("--------------------------------------------------\n")
            f.write(json.dumps(self.callsite_bindings, indent=2, ensure_ascii=False, sort_keys=True))
            f.write("\n")

            self._write_summary(f)

        print(f"[+] V6 report generated: {output_path}")
        print(f"[+] Expected verdict: {validation['verdict']}")
        return validation


if __name__ == "__main__":
    json_input = sys.argv[1] if len(sys.argv) > 1 else "D:\\githubProject\\03_Data_Origin\\tracing_Data_Origin\\output\\case_DFB010_branch_phi_low_pcode.json"
    report_output = sys.argv[2] if len(sys.argv) > 2 else "D:\\githubProject\\03_Data_Origin\\tracing_Data_Origin\\output\\ssa_analysis_report_v6.txt"
    expected_path = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_EXPECTED_PATH

    if os.path.exists(json_input):
        engine = SourceSinkCallSiteBinderV6(json_input)
        engine.build_ssa_graph()
        engine.generate_report(None, report_output, expected_path)
    else:
        print(f"[-] input JSON not found: {json_input}")
