# -*- coding: utf-8 -*-
# @author: AI Assistant
# @category: Analysis
# @keybinding: 
# @menupath: 
# @toolbar: 
# @runtime Jython

import json
import os
from ghidra.util.task import TaskMonitor


DUMPER_SCHEMA_VERSION = 2
DUMPER_NAME = "lowpcode_json_dumper_v2_reachable_helpers"
REACHABLE_HELPER_MAX_DEPTH = 8


def safe_str(value):
    if value is None:
        return None
    try:
        return value.toString()
    except Exception:
        return str(value)


def safe_call(default_value, func, *args):
    try:
        return func(*args)
    except Exception:
        return default_value


def to_hex_offset(value):
    try:
        return hex(value)
    except Exception:
        return safe_str(value)


def get_varnode_type(vn):
    # Keep the legacy coarse type names for older Python analyzers.
    if vn.isRegister():
        return "Register"
    if vn.isUnique():
        return "Unique"
    if vn.isConstant():
        return "Constant"
    return "Address"


def get_varnode_info(vn, program):
    """
    Backward-compatible varnode serialization.

    Legacy fields preserved:
      type, offset, size

    New fields are hints only. They do not depend on High P-Code or the
    decompiler and can be ignored by v2/v3/v5 analyzers.
    """
    vn_addr = safe_call(None, vn.getAddress)
    info = {
        "type": get_varnode_type(vn),
        "offset": to_hex_offset(vn.getOffset()),
        "size": vn.getSize(),
        "space": safe_str(vn_addr.getAddressSpace()) if vn_addr else None,
        "address": safe_str(vn_addr),
        "is_register": bool(vn.isRegister()),
        "is_unique": bool(vn.isUnique()),
        "is_constant": bool(vn.isConstant()),
        "is_address": not bool(vn.isRegister() or vn.isUnique() or vn.isConstant()),
    }

    if vn.isRegister():
        reg = safe_call(None, program.getRegister, vn.getAddress(), vn.getSize())
        info["register_name"] = safe_str(reg.getName()) if reg else None

    return info


def get_address_ranges(addr_set):
    ranges = []
    try:
        it = addr_set.getAddressRanges(True)
        while it.hasNext():
            r = it.next()
            ranges.append({
                "min": safe_str(r.getMinAddress()),
                "max": safe_str(r.getMaxAddress())
            })
    except Exception:
        pass
    return ranges


def get_memory_block_info(program):
    blocks = []
    try:
        for block in program.getMemory().getBlocks():
            blocks.append({
                "name": safe_str(block.getName()),
                "start": safe_str(block.getStart()),
                "end": safe_str(block.getEnd()),
                "size": safe_call(None, block.getSize),
                "is_read": bool(safe_call(False, block.isRead)),
                "is_write": bool(safe_call(False, block.isWrite)),
                "is_execute": bool(safe_call(False, block.isExecute)),
                "is_volatile": bool(safe_call(False, block.isVolatile)),
                "is_external": bool(safe_call(False, block.isExternalBlock)),
            })
    except Exception:
        pass
    return blocks


def get_variable_info(var_obj):
    if var_obj is None:
        return None
    info = {
        "name": safe_str(safe_call(None, var_obj.getName)),
        "data_type": safe_str(safe_call(None, var_obj.getDataType)),
        "storage": safe_str(safe_call(None, var_obj.getVariableStorage)),
        "first_use_offset": safe_call(None, var_obj.getFirstUseOffset),
        "is_stack": bool(safe_call(False, var_obj.isStackVariable)),
        "is_register": bool(safe_call(False, var_obj.isRegisterVariable)),
        "is_memory": bool(safe_call(False, var_obj.isMemoryVariable)),
        "is_unique": bool(safe_call(False, var_obj.isUniqueVariable)),
    }
    if info["is_stack"]:
        info["stack_offset"] = safe_call(None, var_obj.getStackOffset)
    return info


def get_function_hints(func):
    hints = {
        "name": func.getName(),
        "entry": safe_str(func.getEntryPoint()),
        "body_ranges": get_address_ranges(func.getBody()),
        "calling_convention": safe_call(None, func.getCallingConventionName),
        "signature": safe_str(safe_call(None, func.getSignature)),
        "is_thunk": bool(safe_call(False, func.isThunk)),
        "thunked_function": None,
        "parameters": [],
        "local_variables": [],
        "stack_frame": {},
    }

    thunked = safe_call(None, func.getThunkedFunction, True)
    if thunked:
        hints["thunked_function"] = {
            "name": thunked.getName(),
            "entry": safe_str(thunked.getEntryPoint())
        }

    try:
        for param in func.getParameters():
            item = get_variable_info(param)
            item["ordinal"] = safe_call(None, param.getOrdinal)
            hints["parameters"].append(item)
    except Exception:
        pass

    try:
        for local_var in func.getLocalVariables():
            hints["local_variables"].append(get_variable_info(local_var))
    except Exception:
        pass

    frame = safe_call(None, func.getStackFrame)
    if frame:
        hints["stack_frame"] = {
            "frame_size": safe_call(None, frame.getFrameSize),
            "local_size": safe_call(None, frame.getLocalSize),
            "parameter_size": safe_call(None, frame.getParameterSize),
            "return_address_offset": safe_call(None, frame.getReturnAddressOffset),
            "grows_negative": bool(safe_call(False, frame.growsNegative)),
        }

    return hints


def get_program_hints(program):
    language = safe_call(None, program.getLanguage)
    compiler_spec = safe_call(None, program.getCompilerSpec)
    return {
        "name": safe_str(safe_call(None, program.getName)),
        "executable_path": safe_str(safe_call(None, program.getExecutablePath)),
        "image_base": safe_str(safe_call(None, program.getImageBase)),
        "language_id": safe_str(safe_call(None, language.getLanguageID)) if language else None,
        "processor": safe_str(safe_call(None, language.getProcessor)) if language else None,
        "compiler_spec_id": safe_str(safe_call(None, compiler_spec.getCompilerSpecID)) if compiler_spec else None,
        "default_pointer_size": safe_call(None, program.getDefaultPointerSize),
        "memory_blocks": get_memory_block_info(program),
    }


def get_ref_info(ref):
    ref_type = ref.getReferenceType()
    return {
        "from": safe_str(ref.getFromAddress()),
        "to": safe_str(ref.getToAddress()),
        "type": safe_str(ref_type),
        "is_flow": bool(safe_call(False, ref_type.isFlow)),
        "is_call": bool(safe_call(False, ref_type.isCall)),
        "is_jump": bool(safe_call(False, ref_type.isJump)),
        "is_data": bool(safe_call(False, ref_type.isData)),
        "is_read": bool(safe_call(False, ref_type.isRead)),
        "is_write": bool(safe_call(False, ref_type.isWrite)),
        "operand_index": safe_call(None, ref.getOperandIndex),
    }


def get_call_target_info(addr):
    target_func = getFunctionAt(addr)
    if not target_func:
        target_func = getFunctionContaining(addr)
    if not target_func:
        return {"address": safe_str(addr), "resolved": False}
    return {
        "address": safe_str(addr),
        "resolved": True,
        "function_name": target_func.getName(),
        "entry": safe_str(target_func.getEntryPoint()),
        "is_thunk": bool(safe_call(False, target_func.isThunk)),
        "calling_convention": safe_call(None, target_func.getCallingConventionName),
    }


def get_instruction_bytes(instr):
    values = []
    try:
        for b in instr.getBytes():
            try:
                values.append("%02x" % (int(b) & 0xff))
            except Exception:
                values.append("%02x" % (ord(b) & 0xff))
    except Exception:
        pass
    return values


def find_functions_by_prefix(prefix):
    functions = []
    try:
        fm = currentProgram.getFunctionManager()
        it = fm.getFunctions(True)
        while it.hasNext():
            func = it.next()
            if func.getName().startswith(prefix):
                functions.append(func)
    except Exception as e:
        print("[-] 함수 prefix 검색 실패: %s" % str(e))
    return functions


def function_key(func):
    if func is None:
        return None
    return safe_str(safe_call(None, func.getEntryPoint))


def function_record(func, depth=None, root=None):
    record = {
        "name": func.getName(),
        "entry": safe_str(func.getEntryPoint()),
        "is_external": bool(safe_call(False, func.isExternal)),
        "is_thunk": bool(safe_call(False, func.isThunk)),
    }
    if depth is not None:
        record["depth"] = depth
    if root is not None:
        record["root"] = root
    return record


def is_source_or_sink_function(func):
    name = func.getName()
    return name.startswith("dfb_source_") or name.startswith("dfb_sink_")


def is_followable_internal_function(func):
    if func is None:
        return False
    if bool(safe_call(False, func.isExternal)):
        return False
    if is_source_or_sink_function(func):
        return False
    body = safe_call(None, func.getBody)
    if body is None or bool(safe_call(True, body.isEmpty)):
        return False
    return True


def resolve_called_functions(func):
    called = []
    seen = set()
    try:
        listing = currentProgram.getListing()
        instructions = listing.getInstructions(func.getBody(), True)
        while instructions.hasNext():
            instr = instructions.next()
            for ref in instr.getReferencesFrom():
                if not ref.getReferenceType().isCall():
                    continue
                target_func = getFunctionAt(ref.getToAddress())
                if not target_func:
                    target_func = getFunctionContaining(ref.getToAddress())
                key = function_key(target_func)
                if target_func is not None and key not in seen:
                    seen.add(key)
                    called.append({
                        "from_addr": safe_str(instr.getAddress()),
                        "from_function": func.getName(),
                        "to_addr": safe_str(ref.getToAddress()),
                        "to_function": target_func,
                    })
    except Exception as e:
        print("[-] 호출 대상 수집 실패: %s: %s" % (func.getName(), str(e)))
    return called


def collect_reachable_internal_functions(seed_funcs, max_depth):
    ordered = []
    seen = set()
    queue = []
    edges = []
    skipped = []

    for func in seed_funcs:
        key = function_key(func)
        if key and key not in seen:
            seen.add(key)
            ordered.append(func)
            queue.append((func, 0, func.getName()))

    while queue:
        func, depth, root = queue.pop(0)
        if depth >= max_depth:
            continue
        for call in resolve_called_functions(func):
            target_func = call["to_function"]
            edge = {
                "from_function": call["from_function"],
                "from_addr": call["from_addr"],
                "to_addr": call["to_addr"],
                "to_function": target_func.getName(),
                "root": root,
                "depth": depth + 1,
            }
            edges.append(edge)

            if not is_followable_internal_function(target_func):
                skipped.append({
                    "name": target_func.getName(),
                    "entry": safe_str(target_func.getEntryPoint()),
                    "reason": "external_or_terminal_source_sink_or_empty_body",
                    "referenced_from": call["from_function"],
                    "from_addr": call["from_addr"],
                })
                continue

            key = function_key(target_func)
            if key and key not in seen:
                seen.add(key)
                ordered.append(target_func)
                queue.append((target_func, depth + 1, root))

    return ordered, edges, skipped


def write_manifest_file(base_path, seed_funcs, funcs, edges, skipped):
    manifest = {
        "schema_version": DUMPER_SCHEMA_VERSION,
        "dumper": DUMPER_NAME,
        "mode": "case_DFB_with_reachable_internal_helpers",
        "max_depth": REACHABLE_HELPER_MAX_DEPTH,
        "program": get_program_hints(currentProgram),
        "roots": [function_record(func) for func in seed_funcs],
        "functions": [function_record(func) for func in funcs],
        "call_edges": edges,
        "skipped_targets": skipped,
    }
    output_path = make_output_path(base_path, "low_pcode_extraction_manifest.json")
    with open(output_path, "w") as manifest_file:
        manifest_file.write(json.dumps(manifest, indent=2, ensure_ascii=False))
    return output_path


def write_json_file(base_path, func):
    result_json = dump_low_pcode_and_flow(func)
    output_path = make_output_path(base_path, func.getName() + "_low_pcode.json")
    with open(output_path, "w") as json_file:
        json_file.write(json.dumps(result_json, indent=2, ensure_ascii=False))
    return output_path


def normalize_output_dir(path):
    return os.path.abspath(str(path))


def make_output_path(base_path, filename):
    return os.path.join(base_path, filename)

def dump_low_pcode_and_flow(func):
    """
    지정한 함수의 모든 명령어 주소를 순회하며 
    Low P-Code와 원본 제어 흐름 정보를 추출하여 딕셔너리로 반환합니다.
    """
    program = currentProgram
    listing = program.getListing()
    
    # 함수의 시작과 끝 주소 범위 가져오기
    addr_set = func.getBody()
    instructions = listing.getInstructions(addr_set, True)
    
    func_data = {
        "schema_version": DUMPER_SCHEMA_VERSION,
        "dumper": DUMPER_NAME,
        "compatibility": {
            "legacy_v1_fields_preserved": True,
            "legacy_instruction_low_pcode_shape_preserved": True,
            "new_fields_are_optional_hints": True
        },
        "program": get_program_hints(program),
        "ghidra_hints": {
            "function": get_function_hints(func)
        },
        "function_name": func.getName(),
        "start_address": func.getEntryPoint().toString(),
        "instructions": []
    }
    
    for instr in instructions:
        addr_str = instr.getAddress().toString()
        mnemonic = instr.getMnemonicString()
        assembly = instr.toString()
        
        # 1. 분기 및 제어 흐름 정보 추출 (Flow Type & Targets)
        flow_type = instr.getFlowType().toString()
        flow_targets = []
        refs_from = []
        call_targets = []
        for ref in instr.getReferencesFrom():
            ref_info = get_ref_info(ref)
            refs_from.append(ref_info)
            if ref.getReferenceType().isFlow():
                flow_targets.append(ref.getToAddress().toString())
            if ref.getReferenceType().isCall():
                call_targets.append(get_call_target_info(ref.getToAddress()))
                
        # Fallthrough(조건 미충족 시 다음 줄로 넘어가는 주소) 추가
        fallthrough = instr.getFallThrough()
        fallthrough_str = fallthrough.toString() if fallthrough else None

        # 2. 로우 레벨 P-Code 연산 추출
        pcode_list = []
        try:
            raw_pcodes = instr.getPcode()
            for op in raw_pcodes:
                # P-Code 연산 이름 (e.g., INT_ADD, LOAD, STORE 등)
                op_name = op.getMnemonic()
                
                # 출력(Destination) Varnode 정보
                output_var = None
                if op.getOutput():
                    out = op.getOutput()
                    output_var = get_varnode_info(out, program)
                
                # 입력(Inputs) Varnodes 정보
                input_vars = []
                for inp in op.getInputs():
                    input_vars.append(get_varnode_info(inp, program))
                
                pcode_list.append({
                    "opcode": op_name,
                    "seqnum": safe_str(safe_call(None, op.getSeqnum)),
                    "output": output_var,
                    "inputs": input_vars
                })
        except Exception as e:
            # 기드라가 가끔 특정 지연 슬롯이나 특수 명령어를 해석하지 못할 때를 대비한 예외 처리
            pcode_list.append({"error": str(e)})

        # 데이터 조립
        instr_data = {
            "address": addr_str,
            "mnemonic": mnemonic,
            "assembly": assembly,
            "length": safe_call(None, instr.getLength),
            "bytes": get_instruction_bytes(instr),
            "flow_type": flow_type,
            "fallthrough": fallthrough_str,
            "flow_targets": flow_targets,
            "refs_from": refs_from,
            "call_targets": call_targets,
            "low_pcode": pcode_list
        }
        func_data["instructions"].append(instr_data)
        
    return func_data

# --- 스크립트 실행부 ---
import json

try:
    selected_dir = askDirectory("case_DFB* 및 reachable helper Low P-Code JSON 저장 폴더를 선택하세요", "저장")
    base_path = normalize_output_dir(selected_dir.getAbsolutePath())
except Exception as e:
    print("[-] 경로 선택이 취소되었습니다.")
    base_path = None

if base_path:
    seed_funcs = find_functions_by_prefix("case_DFB")

    if not seed_funcs:
        cursor_func = getFunctionContaining(currentAddress)
        if cursor_func is not None:
            seed_funcs = [cursor_func]
            print("[!] case_DFB* 함수를 찾지 못해 커서 함수만 추출합니다: %s" % cursor_func.getName())

    if not seed_funcs:
        print("[-] 추출할 함수가 없습니다. case_DFB* 함수가 존재하는지 확인하세요.")
    else:
        funcs, call_edges, skipped_targets = collect_reachable_internal_functions(seed_funcs, REACHABLE_HELPER_MAX_DEPTH)
        print("[*] case_DFB root 함수 수: %d" % len(seed_funcs))
        print("[*] reachable 내부 helper 포함 추출 대상 함수 수: %d" % len(funcs))
        print("[*] skipped external/source/sink/empty target 수: %d" % len(skipped_targets))
        success_count = 0
        fail_count = 0
        for func in funcs:
            try:
                output_path = write_json_file(base_path, func)
                success_count += 1
                print("[+] %s -> %s" % (func.getName(), output_path))
            except Exception as e:
                fail_count += 1
                print("[-] %s 추출 실패: %s" % (func.getName(), str(e)))

        try:
            manifest_path = write_manifest_file(base_path, seed_funcs, funcs, call_edges, skipped_targets)
            print("[+] manifest -> %s" % manifest_path)
        except Exception as e:
            print("[-] manifest 저장 실패: %s" % str(e))

        print("[*] 일괄 추출 완료: success=%d fail=%d" % (success_count, fail_count))
        print("[*] 이 경로의 JSON 파일들을 Python 3 NetworkX 엔진에 로드하여 분석하세요.")
