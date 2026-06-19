import json
import networkx as nx
import os


class MemoryRegionClassifier:
    """
    v5 addition over v3:
    - v3 only knew a synthetic stack slot such as EBP_0xfffffffc.
    - v5 starts classifying memory into boundary-relevant regions.

    This is intentionally conservative. The current lowpcode_json_dumper output has
    instruction p-code and CFG flow, but it does not yet include Ghidra StackFrame,
    MemoryBlock, symbol/import, or xref metadata. Those should be added later as
    classifier hints. Low P-Code def-use remains the source of truth.
    """

    def __init__(self, reg_map):
        self.reg_map = reg_map

    def _parse_u32_signed(self, value):
        if not isinstance(value, str):
            return None
        value = value.replace("L", "")
        try:
            parsed = int(value, 16)
        except ValueError:
            return None
        if parsed & 0x80000000:
            parsed -= 0x100000000
        return parsed

    def classify_stack_key(self, stack_key):
        if not stack_key or "_" not in stack_key:
            return {"region": "unknown_external", "confidence": "unresolved"}

        base_reg, raw_offset = stack_key.split("_", 1)
        signed_offset = self._parse_u32_signed(raw_offset)

        if base_reg in {"EBP", "RBP"} and signed_offset is not None:
            if signed_offset < 0:
                return {"region": "local_stack", "confidence": "frame_pointer_offset", "offset": signed_offset}
            if signed_offset > 0:
                return {"region": "caller_stack_or_param", "confidence": "frame_pointer_offset", "offset": signed_offset}
            return {"region": "frame_base", "confidence": "frame_pointer_offset", "offset": signed_offset}

        if base_reg in {"ESP", "RSP"}:
            return {"region": "stack_pointer_relative", "confidence": "needs_callsite_binding", "offset": signed_offset}

        return {"region": "unknown_external", "confidence": "unclassified_stack_expr"}

    def classify_address_input(self, inp):
        if inp.get("type") != "Address":
            return None
        return {"region": "global_or_code_address", "confidence": "address_varnode", "offset": inp.get("offset")}


class BoundaryAwareSSAEngineV5:
    """
    v5 differences from pcode_ssa_report_v3.py:
    - Keeps v3's CFG basic blocks, PHI merge, and edge-kind separated data slice.
    - Adds MemoryRegionClassifier for local_stack/caller_stack/global/unknown tagging.
    - Adds a FunctionSummary skeleton built from use-before-def inputs and externally
      observable outputs.
    - Treats CALL_RESET as a temporary opaque model, but records that richer CallSite
      binding is the next required step.

    Design rule:
    - Do not rely on High P-Code or decompiler output.
    - Ghidra analysis metadata may be used later as hints, not as truth.
    """

    def __init__(self, json_path):
        with open(json_path, "r", encoding="utf-8") as f:
            self.data = json.load(f)

        self.G = nx.DiGraph()
        self.counters = {}
        self.stacks = {}
        self.ssa_pcode_lines = []
        self.stack_memory_map = {}
        self.unique_definitions = {}

        self.last_cbranch_cond = None
        self.addr_to_instr = {instr["address"]: instr for instr in self.data["instructions"]}
        self.block_starts = []
        self.blocks = {}
        self.block_successors = {}
        self.block_predecessors = {}

        self.reg_map = {
            "0x0L": "EAX", "0x4L": "ECX", "0x8L": "EDX", "0xcL": "EBX",
            "0x10L": "ESP", "0x14L": "EBP", "0x18L": "ESI", "0x1cL": "EDI",
            "0x200L": "CF", "0x202L": "PF", "0x206L": "ZF", "0x207L": "SF", "0x20bL": "OF"
        }
        self.volatile_registers = ["0x0L", "0x4L", "0x8L"]
        self.data_slice_edge_kinds = {"data", "memory"}
        self.region_classifier = MemoryRegionClassifier(self.reg_map)

        self.summary = {
            "function": self.data.get("function_name"),
            "inputs": {},
            "outputs": {},
            "memory_accesses": [],
            "callsites": [],
            "notes": [
                "v5 summary is derived from Low P-Code use-before-def and writes.",
                "Current JSON lacks stack-frame, symbol/import, xref, and memory-block metadata.",
                "CALL effects are still opaque until CallSite Binder is implemented."
            ],
        }

    def _add_dependency(self, source, target, kind="data"):
        self.G.add_edge(source, target, kind=kind)

    def _record_summary_item(self, section, key, value):
        bucket = self.summary[section].setdefault(key, [])
        if value not in bucket:
            bucket.append(value)

    def _prettify_var(self, var_type, offset, version=None):
        clean_offset = offset[:-1] if isinstance(offset, str) and offset.startswith("0x") and offset.endswith("L") else offset
        name = self.reg_map.get(offset, f"{var_type}_{clean_offset}")
        if version is not None:
            return f"{name}#{version}"
        return name

    def _var_key(self, var_type, offset):
        return f"{var_type}_{offset}"

    def _split_var_key(self, key):
        if "_" not in key:
            return None, None
        return key.split("_", 1)

    def _is_phi_mergeable_key(self, key):
        var_type, _ = self._split_var_key(key)
        return var_type in {"Register", "Memory"}

    def _get_current_version(self, var_type, offset, state=None, addr=None):
        key = self._var_key(var_type, offset)
        if state is not None and key in state["vars"]:
            return state["vars"][key]

        if state is not None and key not in state["defined"] and var_type in {"Register", "Memory"}:
            self._record_summary_item("inputs", key, {"addr": addr, "reason": "use_before_def"})

        if key not in self.stacks or not self.stacks[key]:
            self.counters[key] = 0
            self.stacks[key] = [0]
        node_name = self._prettify_var(var_type, offset, self.stacks[key][-1])
        if state is not None:
            state["vars"][key] = node_name
        return node_name

    def _create_new_version(self, var_type, offset, state=None):
        key = self._var_key(var_type, offset)
        if key not in self.counters:
            self.counters[key] = 0
        self.counters[key] += 1
        if key not in self.stacks:
            self.stacks[key] = []
        self.stacks[key].append(self.counters[key])
        node_name = self._prettify_var(var_type, offset, self.counters[key])
        if state is not None:
            state["vars"][key] = node_name
            state["defined"].add(key)
        return node_name

    def _normalize_addr(self, addr):
        if addr is None:
            return None
        if isinstance(addr, int):
            return f"{addr:08x}"
        addr = str(addr).replace("L", "")
        try:
            return f"{int(addr, 16):08x}"
        except ValueError:
            return addr

    def _new_state(self):
        return {"vars": {}, "stack": {}, "defined": set(), "branch_cond": None}

    def _copy_state(self, state):
        return {
            "vars": dict(state["vars"]),
            "stack": dict(state["stack"]),
            "defined": set(state["defined"]),
            "branch_cond": state.get("branch_cond"),
        }

    def _resolve_stack_address(self, addr_node):
        if addr_node in self.unique_definitions:
            pcode_info = self.unique_definitions[addr_node]
            if pcode_info["opcode"] == "INT_ADD":
                inputs = pcode_info["inputs"]
                if len(inputs) == 2:
                    reg_offset = inputs[0].get("offset", "")
                    reg_name = self.reg_map.get(reg_offset, "REG")
                    const_val = inputs[1].get("offset", "0").replace("L", "")
                    return f"{reg_name}_{const_val}"
        return None

    def _successor_addresses(self, instr):
        flow_type = instr.get("flow_type") or ""
        mnemonic = instr.get("mnemonic") or ""
        fallthrough = self._normalize_addr(instr.get("fallthrough"))
        targets = [self._normalize_addr(target) for target in instr.get("flow_targets", [])]
        targets = [target for target in targets if target in self.addr_to_instr]

        if "CALL" in flow_type or mnemonic == "CALL":
            return [fallthrough] if fallthrough in self.addr_to_instr else []
        if flow_type == "CONDITIONAL_JUMP" or mnemonic in ["JZ", "JNZ", "CBRANCH"]:
            successors = list(targets)
            if fallthrough in self.addr_to_instr:
                successors.append(fallthrough)
            return successors
        if flow_type == "UNCONDITIONAL_JUMP" or mnemonic == "JMP":
            return targets
        if mnemonic in ["RET", "RETURN"] or flow_type == "TERMINATOR":
            return []
        return [fallthrough] if fallthrough in self.addr_to_instr else []

    def _build_basic_blocks(self):
        instructions = self.data["instructions"]
        if not instructions:
            return

        leaders = {instructions[0]["address"]}
        for instr in instructions:
            for successor in self._successor_addresses(instr):
                leaders.add(successor)

        leader_set = set(leaders)
        current_start = None
        for instr in instructions:
            addr = instr["address"]
            if current_start is None or addr in leader_set:
                current_start = addr
                self.block_starts.append(current_start)
                self.blocks[current_start] = []
            self.blocks[current_start].append(instr)

        addr_to_block = {}
        for block_start, block_instrs in self.blocks.items():
            for instr in block_instrs:
                addr_to_block[instr["address"]] = block_start

        for block_start, block_instrs in self.blocks.items():
            successors = []
            for successor_addr in self._successor_addresses(block_instrs[-1]):
                successor_block = addr_to_block.get(successor_addr)
                if successor_block and successor_block not in successors:
                    successors.append(successor_block)
            self.block_successors[block_start] = successors

        self.block_predecessors = {block_start: [] for block_start in self.block_starts}
        for block_start, successors in self.block_successors.items():
            for successor in successors:
                self.block_predecessors[successor].append(block_start)

    def _merge_block_states(self, block_start, predecessor_states):
        if not predecessor_states:
            return self._new_state()
        if len(predecessor_states) == 1:
            return self._copy_state(predecessor_states[0])

        merged = self._copy_state(predecessor_states[0])
        merged["branch_cond"] = predecessor_states[0].get("branch_cond")
        for state in predecessor_states[1:]:
            merged["defined"].update(state["defined"])
            if merged["branch_cond"] != state.get("branch_cond"):
                merged["branch_cond"] = None

        mergeable_keys = sorted({
            key
            for state in predecessor_states
            for key in state["vars"]
            if self._is_phi_mergeable_key(key)
        })

        for key in mergeable_keys:
            var_type, offset = self._split_var_key(key)
            incoming_nodes = []
            for state in predecessor_states:
                node = state["vars"].get(key)
                if node and node not in incoming_nodes:
                    incoming_nodes.append(node)

            if len(incoming_nodes) <= 1:
                if incoming_nodes:
                    merged["vars"][key] = incoming_nodes[0]
                    if var_type == "Memory" and offset in merged["stack"]:
                        merged["stack"][offset] = incoming_nodes[0]
                continue

            phi_output = self._create_new_version(var_type, offset, merged)
            branch_cond = merged.get("branch_cond")
            self.G.add_node(phi_output, addr=block_start, opcode="MLIL_VAR_PHI", path_condition=branch_cond)
            for incoming_node in incoming_nodes:
                if self.G.has_node(incoming_node):
                    self._add_dependency(incoming_node, phi_output, "data")

            if var_type == "Memory" and offset in {stack_key for state in predecessor_states for stack_key in state["stack"]}:
                merged["stack"][offset] = phi_output
                self.stack_memory_map[offset] = phi_output
            phi_inputs = ", ".join(incoming_nodes)
            self.ssa_pcode_lines.append(f"\n[phi] {phi_output} = MLIL_VAR_PHI({phi_inputs}) [path condition: {branch_cond}]")

        return merged

    def _add_input_node(self, inp, addr, state):
        if inp["type"] == "Constant":
            node_name = f"Const_{inp['offset'].replace('L','')}"
            input_str = inp["offset"].replace("L", "")
        else:
            node_name = self._get_current_version(inp["type"], inp["offset"], state, addr)
            input_str = node_name

        if not self.G.has_node(node_name):
            self.G.add_node(node_name, addr=addr)
        return node_name, input_str

    def _record_memory_access(self, addr, opcode, stack_key, node_name):
        classification = self.region_classifier.classify_stack_key(stack_key)
        record = {"addr": addr, "opcode": opcode, "stack_key": stack_key, "node": node_name, **classification}
        self.summary["memory_accesses"].append(record)
        return classification

    def _record_external_output(self, key, addr, node, reason, classification=None):
        value = {"addr": addr, "node": node, "reason": reason}
        if classification:
            value.update(classification)
        self._record_summary_item("outputs", key, value)

    def _process_call(self, instr, state):
        addr = instr["address"]
        clobbered_vars = []
        call_record = {
            "addr": addr,
            "assembly": instr.get("assembly"),
            "flow_targets": instr.get("flow_targets", []),
            "model": "opaque_call_reset_v5_temporary",
            "next_step": "replace with CallSite Binder + callee FunctionSummary application",
        }
        self.summary["callsites"].append(call_record)

        for reg_offset in self.volatile_registers + ["MEMORY_GLOBAL"]:
            v_type = "Register" if "MEMORY" not in reg_offset else "Memory"
            new_ver = self._create_new_version(v_type, reg_offset, state)
            opcode = "CALL_RET" if reg_offset == "0x0L" else "CALL_CLOBBER"
            self.G.add_node(new_ver, addr=addr, opcode=opcode)
            clobbered_vars.append(new_ver)
            output_key = self._var_key(v_type, reg_offset)
            classification = {"region": "register" if v_type == "Register" else "unknown_external_memory", "confidence": "opaque_call"}
            self._record_external_output(output_key, addr, new_ver, "opaque_call_clobber", classification)

        self.ssa_pcode_lines.append(f"CALL_RESET({', '.join(clobbered_vars)})")

    def _process_instruction(self, instr, state):
        addr = instr["address"]
        mnemonic = instr["mnemonic"]
        assembly = instr["assembly"]
        self.ssa_pcode_lines.append(f"// --- {addr}: {assembly} ---")

        if mnemonic in ["JZ", "JNZ", "CBRANCH"] or instr.get("flow_type") == "CONDITIONAL_JUMP":
            branch_cond = self._get_current_version("Register", "0x206L", state, addr)
            state["branch_cond"] = branch_cond
            self.last_cbranch_cond = branch_cond
            self.ssa_pcode_lines.append(f"CBRANCH(IF NOT {branch_cond} GOTO TARGET)")
            return

        if mnemonic == "CALL" or "CALL" in (instr.get("flow_type") or ""):
            self._process_call(instr, state)
            return

        for pcode in instr.get("low_pcode", []):
            if "error" in pcode:
                continue
            opcode = pcode["opcode"]
            output = pcode["output"]
            inputs = pcode["inputs"]

            input_nodes = []
            input_strs = []
            for inp in inputs:
                address_hint = self.region_classifier.classify_address_input(inp)
                if address_hint:
                    self.summary["memory_accesses"].append({"addr": addr, "opcode": opcode, **address_hint})
                node_name, input_str = self._add_input_node(inp, addr, state)
                input_nodes.append(node_name)
                input_strs.append(input_str)

            if opcode == "STORE" and len(input_nodes) >= 3:
                addr_node = input_nodes[1]
                value_node = input_nodes[2]
                stack_key = self._resolve_stack_address(addr_node)
                if stack_key:
                    mem_node = self._create_new_version("Memory", stack_key, state)
                    self.G.add_node(mem_node, addr=addr, opcode="STORE_VAL")
                    self._add_dependency(value_node, mem_node, "data")
                    self._add_dependency(addr_node, mem_node, "address")
                    state["stack"][stack_key] = mem_node
                    self.stack_memory_map[stack_key] = mem_node
                    classification = self._record_memory_access(addr, "STORE", stack_key, mem_node)
                    if classification["region"] != "local_stack":
                        self._record_external_output(self._var_key("Memory", stack_key), addr, mem_node, "store_to_external_region", classification)
                    self.ssa_pcode_lines.append(f"{mem_node} = STORE_STACK({stack_key}, {value_node}) [{classification['region']}]")
                    continue

            if output:
                output_node = self._create_new_version(output["type"], output["offset"], state)
                self.G.add_node(output_node, addr=addr, opcode=opcode)

                if output["type"] == "Unique":
                    self.unique_definitions[output_node] = {"opcode": opcode, "inputs": inputs}

                for idx, inp_node in enumerate(input_nodes):
                    edge_kind = "address" if opcode == "LOAD" and idx in {0, 1} else "data"
                    self._add_dependency(inp_node, output_node, edge_kind)

                if opcode == "LOAD" and len(input_nodes) >= 2:
                    addr_node = input_nodes[1]
                    stack_key = self._resolve_stack_address(addr_node)
                    if stack_key and stack_key in state["stack"]:
                        last_store_node = state["stack"][stack_key]
                        classification = self._record_memory_access(addr, "LOAD", stack_key, output_node)
                        self._add_dependency(last_store_node, output_node, "memory")
                        self.ssa_pcode_lines.append(f"{output_node} = LOAD_STACK({stack_key}) -> Linked to {last_store_node} [{classification['region']}]")
                        continue

                self.ssa_pcode_lines.append(f"{output_node} = {opcode}({', '.join(input_strs)})")
            else:
                self.ssa_pcode_lines.append(f"{opcode}({', '.join(input_strs)})")

    def _process_block(self, block_start, input_state):
        state = self._copy_state(input_state)
        for instr in self.blocks[block_start]:
            self._process_instruction(instr, state)
        return state

    def build_ssa_graph(self):
        self._build_basic_blocks()
        if not self.block_starts:
            return self.G

        entry = self.block_starts[0]
        block_output_states = {}
        pending = set(self.block_starts)

        while pending:
            progressed = False
            for block_start in list(self.block_starts):
                if block_start not in pending:
                    continue
                predecessors = self.block_predecessors.get(block_start, [])
                ready = block_start == entry or all(pred in block_output_states for pred in predecessors)
                if not ready:
                    continue
                predecessor_states = [block_output_states[pred] for pred in predecessors]
                input_state = self._new_state() if block_start == entry and not predecessor_states else self._merge_block_states(block_start, predecessor_states)
                block_output_states[block_start] = self._process_block(block_start, input_state)
                pending.remove(block_start)
                progressed = True

            if not progressed:
                block_start = sorted(pending)[0]
                predecessor_states = [block_output_states[pred] for pred in self.block_predecessors.get(block_start, []) if pred in block_output_states]
                input_state = self._merge_block_states(block_start, predecessor_states)
                block_output_states[block_start] = self._process_block(block_start, input_state)
                pending.remove(block_start)

        return self.G

    def _generate_tree_string(self, node, visited, indent="", edge_kinds=None):
        if edge_kinds is None:
            edge_kinds = self.data_slice_edge_kinds
        if node in visited:
            return f"{indent}└── [cycle] {node}\n"
        visited.add(node)

        attr = self.G.nodes.get(node, {})
        opcode = attr.get("opcode", "Constant")
        addr = attr.get("addr", "INIT")

        if opcode == "MLIL_VAR_PHI":
            result = f"{indent}├── [PHI] {node:<25} [addr: {addr}]\n"
            indent_delta = "│   "
        else:
            result = f"{indent}├── {node:<31} [addr: {addr}] [op: {opcode}]\n"
            indent_delta = "    "

        predecessors = [
            pred
            for pred in self.G.predecessors(node)
            if self.G.edges[pred, node].get("kind", "data") in edge_kinds
        ]
        for pred in predecessors:
            result += self._generate_tree_string(pred, visited.copy(), indent + indent_delta, edge_kinds)
        return result

    def _write_summary(self, f):
        f.write("\n Function Boundary Summary Skeleton\n")
        f.write("--------------------------------------------------\n")
        f.write(json.dumps(self.summary, indent=2, ensure_ascii=False, sort_keys=True))
        f.write("\n")

    def generate_report(self, target_node, output_path):
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("==================================================\n")
            f.write(f"V5 LOW-PCODE CFG SSA DATA-SLICE REPORT: {self.data.get('function_name')}\n")
            f.write("==================================================\n\n")

            f.write(" V5 notes\n")
            f.write("--------------------------------------------------\n")
            f.write("- v3 CFG/PHI/data-edge behavior is preserved.\n")
            f.write("- v5 adds memory region classification and function boundary summary skeleton.\n")
            f.write("- Current dumper JSON is enough for intra-function Low-PCode SSA/CFG.\n")
            f.write("- Future call boundary work needs stack-frame, symbol/import, xref, and memory-block hints.\n\n")

            f.write(" SSA Low P-Code\n")
            f.write("--------------------------------------------------\n")
            for line in self.ssa_pcode_lines:
                f.write(line + "\n")

            f.write(f"\n Backward DATA slice tree (Target: {target_node})\n")
            f.write("--------------------------------------------------\n")
            if not self.G.has_node(target_node):
                f.write(f"[-] target node not found: {target_node}\n")
            else:
                f.write(self._generate_tree_string(target_node, set()))

            self._write_summary(f)

        print(f"[+] V5 report generated: {output_path}")


if __name__ == "__main__":
    json_input = "D:\\githubProject\\03_Data_Origin\\tracing_Data_Origin\\output\\case_DFB010_branch_phi_low_pcode.json"
    report_output = "D:\\githubProject\\03_Data_Origin\\tracing_Data_Origin\\output\\ssa_analysis_report_v5.txt"

    if os.path.exists(json_input):
        engine = BoundaryAwareSSAEngineV5(json_input)
        engine.build_ssa_graph()
        target_variable = "Unique_0x41500#2"
        engine.generate_report(target_variable, report_output)
    else:
        print(f"[-] input JSON not found: {json_input}")