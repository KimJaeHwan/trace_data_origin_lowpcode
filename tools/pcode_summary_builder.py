import argparse
import json
import os


REG_EAX = "Register:0x0L"
REG_EBP = "Register:0x14L"
REG_ESP = "Register:0x10L"


def clean_offset(value):
    if value is None:
        return None
    return str(value).replace("L", "")


def parse_int(value):
    value = clean_offset(value)
    if value is None:
        return None
    try:
        parsed = int(value, 16)
    except ValueError:
        return None
    if parsed & 0x80000000:
        parsed -= 0x100000000
    return parsed


def var_key(varnode):
    if not varnode:
        return None
    return "%s:%s" % (varnode.get("type"), varnode.get("offset"))


def is_reg(varnode, offset):
    return bool(varnode) and varnode.get("type") == "Register" and varnode.get("offset") == offset


def arg_index_from_stack_offset(offset):
    if offset is None or offset < 8 or (offset - 8) % 4 != 0:
        return None
    return int((offset - 8) / 4)


def expr_const(value):
    return {"kind": "const", "value": clean_offset(value)}


def expr_unknown(reason=None):
    result = {"kind": "unknown"}
    if reason:
        result["reason"] = reason
    return result


def expr_equal(left, right):
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def append_unique(items, item):
    if not any(expr_equal(existing, item) for existing in items):
        items.append(item)


class LowPcodeSummaryBuilder:
    def __init__(self, json_path):
        self.json_path = json_path
        with open(json_path, "r", encoding="utf-8") as f:
            self.data = json.load(f)
        self.function = self.data.get("function_name")
        self.env = {
            REG_EBP: {"kind": "frame_base"},
            REG_ESP: {"kind": "stack_pointer"},
        }
        self.summary = {
            "function": self.function,
            "json": json_path,
            "returns": [],
            "outparams": [],
            "global_reads": [],
            "global_writes": [],
            "calls": [],
            "notes": [],
        }

    def _expr_for_input(self, varnode):
        if not varnode:
            return expr_unknown("missing_input")
        if varnode.get("type") == "Constant":
            return expr_const(varnode.get("offset"))
        if varnode.get("type") == "Address":
            return {"kind": "global", "address": clean_offset(varnode.get("offset"))}
        return self.env.get(var_key(varnode), expr_unknown("unbound_%s" % var_key(varnode)))

    def _assign(self, output, expr):
        key = var_key(output)
        if key:
            self.env[key] = expr

    def _stack_addr_expr(self, left, right):
        if left.get("kind") == "frame_base" and right.get("kind") == "const":
            return {"kind": "stack_addr", "offset": parse_int(right.get("value"))}
        if right.get("kind") == "frame_base" and left.get("kind") == "const":
            return {"kind": "stack_addr", "offset": parse_int(left.get("value"))}
        if right.get("kind") == "const" and left.get("kind") in {"arg", "deref", "global", "field"}:
            return {"kind": "field", "base": left, "offset": parse_int(right.get("value"))}
        if left.get("kind") == "const" and right.get("kind") in {"arg", "deref", "global", "field"}:
            return {"kind": "field", "base": right, "offset": parse_int(left.get("value"))}
        return None

    def _load_expr(self, addr_expr):
        if addr_expr.get("kind") == "stack_addr":
            arg_index = arg_index_from_stack_offset(addr_expr.get("offset"))
            if arg_index is not None:
                return {"kind": "arg", "arg": arg_index}
            return {"kind": "local_stack", "offset": addr_expr.get("offset")}
        if addr_expr.get("kind") == "global":
            append_unique(self.summary["global_reads"], {"address": addr_expr.get("address")})
            return {"kind": "global", "address": addr_expr.get("address")}
        if addr_expr.get("kind") in {"arg", "field", "deref", "global"}:
            return {"kind": "deref", "base": addr_expr}
        return expr_unknown("load_from_%s" % addr_expr.get("kind"))

    def _record_store(self, address_expr, value_expr):
        if address_expr.get("kind") == "arg":
            append_unique(self.summary["outparams"], {
                "out_arg": address_expr.get("arg"),
                "indirect": 0,
                "value": value_expr,
            })
            return
        if address_expr.get("kind") == "deref" and address_expr.get("base", {}).get("kind") == "arg":
            append_unique(self.summary["outparams"], {
                "out_arg": address_expr["base"].get("arg"),
                "indirect": 1,
                "value": value_expr,
            })
            return
        if address_expr.get("kind") == "global":
            append_unique(self.summary["global_writes"], {
                "address": address_expr.get("address"),
                "value": value_expr,
            })

    def _process_call(self, instr):
        targets = [target for target in instr.get("call_targets", []) if target.get("resolved") and target.get("function_name")]
        target_name = targets[0].get("function_name") if targets else None
        if not target_name:
            return
        self.summary["calls"].append({"addr": instr.get("address"), "target": target_name})
        if target_name.startswith("dfb_source_"):
            self.env[REG_EAX] = {"kind": "source_ret", "source": target_name}
        else:
            self.env[REG_EAX] = {"kind": "call_ret", "target": target_name}

    def _process_pcode(self, pcode):
        if "error" in pcode:
            return
        opcode = pcode.get("opcode")
        output = pcode.get("output")
        inputs = pcode.get("inputs", [])

        if opcode == "COPY" and output and output.get("type") == "Address" and inputs:
            value_expr = self._expr_for_input(inputs[0])
            self._record_store({"kind": "global", "address": clean_offset(output.get("offset"))}, value_expr)
            return

        if opcode == "COPY" and inputs:
            if is_reg(output, "0x14L") and is_reg(inputs[0], "0x10L"):
                self._assign(output, {"kind": "frame_base"})
                return
            self._assign(output, self._expr_for_input(inputs[0]))
            return

        if opcode in {"INT_ADD", "PTRADD", "PTRSUB"} and len(inputs) >= 2:
            left = self._expr_for_input(inputs[0])
            right = self._expr_for_input(inputs[1])
            expr = self._stack_addr_expr(left, right)
            self._assign(output, expr if expr else expr_unknown(opcode))
            return

        if opcode == "LOAD" and len(inputs) >= 2:
            addr_expr = self._expr_for_input(inputs[1])
            self._assign(output, self._load_expr(addr_expr))
            return

        if opcode == "STORE" and len(inputs) >= 3:
            addr_expr = self._expr_for_input(inputs[1])
            value_expr = self._expr_for_input(inputs[2])
            self._record_store(addr_expr, value_expr)
            return

        if output:
            input_exprs = [self._expr_for_input(inp) for inp in inputs]
            passthrough = [expr for expr in input_exprs if expr.get("kind") in {"arg", "source_ret", "global", "deref", "field"}]
            self._assign(output, passthrough[0] if len(passthrough) == 1 else expr_unknown(opcode))

    def build(self):
        for instr in self.data.get("instructions", []):
            if instr.get("mnemonic") == "CALL" or "CALL" in (instr.get("flow_type") or ""):
                self._process_call(instr)
            for pcode in instr.get("low_pcode", []):
                self._process_pcode(pcode)

        ret_expr = self.env.get(REG_EAX)
        if ret_expr and ret_expr.get("kind") not in {"unknown", "stack_pointer"}:
            append_unique(self.summary["returns"], {"value": ret_expr})
        return self.summary


def should_build_summary(path, data):
    name = data.get("function_name", "")
    if name.startswith("case_DFB"):
        return False
    if name.startswith("dfb_source_") or name.startswith("dfb_sink_"):
        return False
    return path.endswith("_low_pcode.json")


def build_all(input_dir):
    summaries = {}
    for name in sorted(os.listdir(input_dir)):
        path = os.path.join(input_dir, name)
        if not name.endswith("_low_pcode.json"):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        if not should_build_summary(path, data):
            continue
        summary = LowPcodeSummaryBuilder(path).build()
        summaries[summary["function"]] = summary
    return summaries


def main():
    parser = argparse.ArgumentParser(description="Build lightweight function summaries from Low-PCode helper JSON files.")
    parser.add_argument("input_dir", nargs="?", default="output\\low_pcode")
    parser.add_argument("output_json", nargs="?", default=None)
    args = parser.parse_args()

    output_json = args.output_json or os.path.join(args.input_dir, "function_summaries.json")
    summaries = build_all(args.input_dir)
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump({"schema_version": 1, "summaries": summaries}, f, indent=2, ensure_ascii=False, sort_keys=True)
    print("[+] function summaries: %d" % len(summaries))
    print("[+] output: %s" % output_json)


if __name__ == "__main__":
    main()