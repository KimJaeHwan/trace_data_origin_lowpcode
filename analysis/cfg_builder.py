from __future__ import annotations

import networkx as nx


class CFGBuilder:
    def build(self, instructions: list[dict]) -> nx.DiGraph:
        cfg = nx.DiGraph()
        if not instructions:
            return cfg

        addr_to_instr = {instr["address"]: instr for instr in instructions}
        leaders = {instructions[0]["address"]}
        for instr in instructions:
            for successor in self._successor_addresses(instr, addr_to_instr):
                leaders.add(successor)

        blocks: dict[str, list[dict]] = {}
        block_starts: list[str] = []
        current_start = None
        for instr in instructions:
            addr = instr["address"]
            if current_start is None or addr in leaders:
                current_start = addr
                block_starts.append(current_start)
                blocks[current_start] = []
            blocks[current_start].append(instr)

        addr_to_block = {}
        for block_start, block_instrs in blocks.items():
            cfg.add_node(block_start, kind="basic_block", start=block_start)
            for instr in block_instrs:
                addr_to_block[instr["address"]] = block_start

        for block_start, block_instrs in blocks.items():
            for successor_addr in self._successor_addresses(block_instrs[-1], addr_to_instr):
                successor_block = addr_to_block.get(successor_addr)
                if successor_block and successor_block != block_start:
                    cfg.add_edge(block_start, successor_block, kind="flow")
        return cfg

    def _successor_addresses(self, instr: dict, addr_to_instr: dict[str, dict]) -> list[str]:
        flow_type = instr.get("flow_type") or ""
        mnemonic = (instr.get("mnemonic") or "").upper()
        fallthrough = instr.get("fallthrough")
        targets = [target for target in instr.get("flow_targets", []) if target in addr_to_instr]

        if "CALL" in flow_type or mnemonic in {"CALL", "BL"}:
            return [fallthrough] if fallthrough in addr_to_instr else []
        if flow_type == "CONDITIONAL_JUMP" or mnemonic in {"JZ", "JNZ", "CBRANCH", "B.EQ", "B.NE"}:
            successors = list(targets)
            if fallthrough in addr_to_instr:
                successors.append(fallthrough)
            return successors
        if flow_type == "UNCONDITIONAL_JUMP" or mnemonic in {"JMP", "B"}:
            return targets
        if mnemonic in {"RET", "RETURN"} or flow_type == "TERMINATOR":
            return []
        return [fallthrough] if fallthrough in addr_to_instr else []
