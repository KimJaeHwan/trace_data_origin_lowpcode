# -*- coding: utf-8 -*-
# @author: AI Assistant
# @category: Analysis
# @keybinding: 
# @menupath: 
# @toolbar: 
# @runtime Jython

import json
import os
import hashlib
from ghidra.util.task import TaskMonitor


DUMPER_SCHEMA_VERSION = 5
DUMPER_NAME = "lowpcode_json_dumper_v5_external_prototypes"
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


def safe_bool_method(obj, method_name):
    method = safe_call(None, getattr, obj, method_name)
    if method is None:
        return False
    return bool(safe_call(False, method))


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


def get_register_metadata(program):
    registers = []
    language = safe_call(None, program.getLanguage)
    if language is None:
        return registers

    try:
        register_iterable = language.getRegisters()
        for reg in register_iterable:
            base_register = safe_call(None, reg.getBaseRegister)
            parent_register = safe_call(None, reg.getParentRegister)
            child_registers = []
            try:
                children = reg.getChildRegisters()
                for child in children:
                    child_registers.append(safe_str(safe_call(None, child.getName)))
            except Exception:
                pass

            size_bytes = safe_call(None, reg.getMinimumByteSize)
            bit_length = safe_call(None, reg.getBitLength)
            registers.append({
                "name": safe_str(safe_call(None, reg.getName)),
                "offset": to_hex_offset(safe_call(None, reg.getOffset)),
                "size_bytes": size_bytes,
                "bit_length": bit_length,
                "least_significant_bit": safe_call(None, reg.getLeastSignificantBitInBaseRegister),
                "base_register": safe_str(safe_call(None, base_register.getName)) if base_register else None,
                "parent_register": safe_str(safe_call(None, parent_register.getName)) if parent_register else None,
                "child_registers": child_registers,
                "is_base_register": safe_bool_method(reg, "isBaseRegister"),
                "is_program_counter": safe_bool_method(reg, "isProgramCounter"),
                "is_context_register": safe_bool_method(reg, "isProcessorContext") or safe_bool_method(reg, "isContextRegister"),
                "is_zero": safe_bool_method(reg, "isZero"),
                "is_hidden": safe_bool_method(reg, "isHidden"),
            })
    except Exception as e:
        print("[-] register metadata 추출 실패: %s" % str(e))
    return registers


def get_register_alias_metadata(registers):
    aliases = []
    for reg in registers:
        offset = reg.get("offset")
        size_bytes = reg.get("size_bytes")
        name = reg.get("name")
        if offset is None or size_bytes is None or not name:
            continue
        aliases.append({
            "space": "register",
            "offset": offset,
            "size_bytes": size_bytes,
            "display": name,
            "canonical": reg.get("base_register") or name,
            "parent_register": reg.get("parent_register"),
            "least_significant_bit": reg.get("least_significant_bit"),
            "bit_length": reg.get("bit_length"),
            "source": "ghidra_language_register",
        })
    return aliases


def get_address_space_metadata(program):
    spaces = []
    factory = safe_call(None, program.getAddressFactory)
    if factory is None:
        return spaces

    try:
        for space in factory.getAddressSpaces():
            spaces.append({
                "name": safe_str(safe_call(None, space.getName)),
                "space_id": safe_call(None, space.getSpaceID),
                "type": safe_str(safe_call(None, space.getType)),
                "size": safe_call(None, space.getSize),
                "addressable_unit_size": safe_call(None, space.getAddressableUnitSize),
                "is_register_space": bool(safe_call(False, space.isRegisterSpace)),
                "is_memory_space": bool(safe_call(False, space.isMemorySpace)),
                "is_constant_space": bool(safe_call(False, space.isConstantSpace)),
                "is_unique_space": bool(safe_call(False, space.isUniqueSpace)),
                "is_overlay_space": bool(safe_call(False, space.isOverlaySpace)),
            })
    except Exception as e:
        print("[-] address space metadata 추출 실패: %s" % str(e))
    return spaces


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
    data_type = safe_call(None, var_obj.getDataType)
    symbol = safe_call(None, var_obj.getSymbol)
    info = {
        "name": safe_str(safe_call(None, var_obj.getName)),
        "data_type": safe_str(data_type),
        "data_type_info": get_data_type_info(data_type),
        "storage": safe_str(safe_call(None, var_obj.getVariableStorage)),
        "first_use_offset": safe_call(None, var_obj.getFirstUseOffset),
        "source": safe_str(safe_call(None, symbol.getSource)) if symbol else None,
        "is_stack": bool(safe_call(False, var_obj.isStackVariable)),
        "is_register": bool(safe_call(False, var_obj.isRegisterVariable)),
        "is_memory": bool(safe_call(False, var_obj.isMemoryVariable)),
        "is_unique": bool(safe_call(False, var_obj.isUniqueVariable)),
    }
    if info["is_stack"]:
        info["stack_offset"] = safe_call(None, var_obj.getStackOffset)
    return info


def get_data_type_info(data_type):
    if data_type is None:
        return None
    pointer_depth = 0
    current = data_type
    seen = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        class_name = safe_str(safe_call(None, current.getClass))
        name = safe_str(safe_call(None, current.getName)) or ""
        if "Pointer" not in str(class_name) and not name.endswith(" *"):
            break
        pointer_depth += 1
        current = safe_call(None, current.getDataType)
    source_archive = safe_call(None, data_type.getSourceArchive)
    return {
        "name": safe_str(safe_call(None, data_type.getName)),
        "display_name": safe_str(data_type),
        "length": safe_call(None, data_type.getLength),
        "category_path": safe_str(safe_call(None, data_type.getCategoryPath)),
        "universal_id": safe_str(safe_call(None, data_type.getUniversalID)),
        "source_archive": safe_str(safe_call(None, source_archive.getName)) if source_archive else None,
        "pointer_depth": pointer_depth,
    }


def get_function_output_info(func):
    output = {
        "data_type": safe_str(safe_call(None, func.getReturnType)),
        "data_type_info": get_data_type_info(safe_call(None, func.getReturnType)),
        "storage": None,
        "source": None,
    }
    return_var = safe_call(None, func.getReturn)
    if return_var:
        output["storage"] = safe_str(safe_call(None, return_var.getVariableStorage))
        symbol = safe_call(None, return_var.getSymbol)
        output["source"] = safe_str(safe_call(None, symbol.getSource)) if symbol else None
    return output


def get_external_location_info(func):
    location = safe_call(None, func.getExternalLocation)
    if location is None:
        return None
    return {
        "library_name": safe_str(safe_call(None, location.getLibraryName)),
        "label": safe_str(safe_call(None, location.getLabel)),
        "address": safe_str(safe_call(None, location.getAddress)),
        "external_space_address": safe_str(safe_call(None, location.getExternalSpaceAddress)),
        "source": safe_str(safe_call(None, location.getSource)),
    }


def normalize_external_name(name):
    if not name:
        return None
    normalized = str(name)
    if normalized.startswith("__imp_"):
        normalized = normalized[len("__imp_"):]
    while normalized.startswith("_") and len(normalized) > 1:
        normalized = normalized[1:]
    at_index = normalized.find("@")
    if at_index > 0:
        suffix = normalized[at_index + 1:]
        if suffix.isdigit():
            normalized = normalized[:at_index]
    return normalized


def get_external_prototype(func):
    if func is None:
        return None
    entry = safe_str(safe_call(None, func.getEntryPoint))
    location = get_external_location_info(func)
    library_name = location.get("library_name") if location else None
    name = safe_str(safe_call(None, func.getName))
    normalized_name = normalize_external_name(name)
    thunked = safe_call(None, func.getThunkedFunction, True)
    params = []
    try:
        for param in func.getParameters():
            item = get_variable_info(param)
            item["ordinal"] = safe_call(None, param.getOrdinal)
            params.append(item)
    except Exception:
        pass
    prototype = {
        "id": stable_hash({
            "source": "ghidra",
            "library": library_name,
            "entry": entry,
            "name": name,
            "signature": safe_str(safe_call(None, func.getSignature)),
        }),
        "source": "ghidra",
        "library": library_name,
        "name": name,
        "normalized_name": normalized_name,
        "entry": entry,
        "external_location": location,
        "thunk_target": {
            "name": thunked.getName(),
            "entry": safe_str(thunked.getEntryPoint()),
            "is_external": bool(safe_call(False, thunked.isExternal)),
        } if thunked else None,
        "signature": safe_str(safe_call(None, func.getSignature)),
        "prototype_string": safe_str(safe_call(None, func.getPrototypeString, True, True)),
        "signature_source": safe_str(safe_call(None, func.getSignatureSource)),
        "calling_convention_name": safe_str(safe_call(None, func.getCallingConventionName)),
        "parameters": params,
        "output": get_function_output_info(func),
        "flags": {
            "is_external": bool(safe_call(False, func.isExternal)),
            "is_thunk": bool(safe_call(False, func.isThunk)),
            "has_varargs": bool(safe_call(False, func.hasVarArgs)),
            "has_no_return": bool(safe_call(False, func.hasNoReturn)),
            "has_custom_variable_storage": bool(safe_call(False, func.hasCustomVariableStorage)),
            "is_inline": bool(safe_call(False, func.isInline)),
        },
        "stack_purge_size": safe_call(None, func.getStackPurgeSize),
        "confidence": "ghidra_function_metadata",
    }
    prototype["metadata_hash"] = stable_hash(prototype)
    return prototype


def get_function_hints(func):
    hints = {
        "name": func.getName(),
        "entry": safe_str(func.getEntryPoint()),
        "body_ranges": get_address_ranges(func.getBody()),
        "calling_convention": safe_call(None, func.getCallingConventionName),
        "signature": safe_str(safe_call(None, func.getSignature)),
        "signature_source": safe_str(safe_call(None, func.getSignatureSource)),
        "prototype_string": safe_str(safe_call(None, func.getPrototypeString, True, True)),
        "is_thunk": bool(safe_call(False, func.isThunk)),
        "is_external": bool(safe_call(False, func.isExternal)),
        "thunked_function": None,
        "external_location": get_external_location_info(func),
        "output": get_function_output_info(func),
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
    registers = get_register_metadata(program)
    address_spaces = get_address_space_metadata(program)
    language_id = safe_str(safe_call(None, language.getLanguageID)) if language else None
    compiler_spec_id = safe_str(safe_call(None, compiler_spec.getCompilerSpecID)) if compiler_spec else None
    processor = safe_str(safe_call(None, language.getProcessor)) if language else None
    pointer_size = safe_call(None, program.getDefaultPointerSize)
    endian = None
    if language:
        endian = "big" if bool(safe_call(False, language.isBigEndian)) else "little"
    return {
        "name": safe_str(safe_call(None, program.getName)),
        "executable_path": safe_str(safe_call(None, program.getExecutablePath)),
        "image_base": safe_str(safe_call(None, program.getImageBase)),
        "language_id": language_id,
        "processor": processor,
        "compiler_spec_id": compiler_spec_id,
        "default_pointer_size": pointer_size,
        "memory_blocks": get_memory_block_info(program),
        "registers": registers,
        "address_spaces": address_spaces,
        "architecture": {
            "language_id": language_id,
            "processor": processor,
            "compiler_spec_id": compiler_spec_id,
            "default_pointer_size": pointer_size,
            "endian": endian,
            "registers": registers,
            "register_aliases": get_register_alias_metadata(registers),
            "address_spaces": address_spaces,
        },
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
    thunked = safe_call(None, target_func.getThunkedFunction, True)
    return {
        "address": safe_str(addr),
        "resolved": True,
        "function_name": target_func.getName(),
        "entry": safe_str(target_func.getEntryPoint()),
        "is_thunk": bool(safe_call(False, target_func.isThunk)),
        "thunk_target_name": thunked.getName() if thunked else None,
        "thunk_target_entry": safe_str(thunked.getEntryPoint()) if thunked else None,
        "calling_convention": safe_str(safe_call(None, target_func.getCallingConventionName)),
        "signature": safe_str(safe_call(None, target_func.getSignature)),
        "signature_source": safe_str(safe_call(None, target_func.getSignatureSource)),
        "is_external": bool(safe_call(False, target_func.isExternal)),
        "external_prototype": get_external_prototype(target_func)
        if bool(safe_call(False, target_func.isExternal)) or bool(safe_call(False, target_func.isThunk)) else None,
    }


def stable_hash(value):
    try:
        text = json.dumps(value, sort_keys=True, ensure_ascii=False)
        if not isinstance(text, bytes):
            text = text.encode("utf-8")
        return hashlib.sha256(text).hexdigest()
    except Exception:
        return None


def get_symbol_record(symbol):
    if symbol is None:
        return None
    addr = safe_call(None, symbol.getAddress)
    namespace = safe_call(None, symbol.getParentNamespace)
    return {
        "name": safe_str(safe_call(None, symbol.getName)),
        "address": safe_str(addr),
        "symbol_type": safe_str(safe_call(None, symbol.getSymbolType)),
        "source": safe_str(safe_call(None, symbol.getSource)),
        "namespace": safe_str(namespace),
        "is_primary": safe_bool_method(symbol, "isPrimary"),
        "is_external": safe_bool_method(symbol, "isExternal"),
        "is_dynamic": safe_bool_method(symbol, "isDynamic"),
    }


def get_symbol_index(program):
    by_address = {}
    imports_by_address = {}
    try:
        symbol_table = program.getSymbolTable()
        symbols = symbol_table.getAllSymbols(True)
        while symbols.hasNext():
            symbol = symbols.next()
            record = get_symbol_record(symbol)
            if record is None or not record.get("address"):
                continue
            by_address.setdefault(record["address"], []).append(record)
            if record.get("is_external"):
                imports_by_address.setdefault(record["address"], []).append(record)
    except Exception as e:
        print("[-] symbol index 추출 실패: %s" % str(e))
    return by_address, imports_by_address


def get_function_index(program):
    by_entry = {}
    thunks_by_entry = {}
    imports_by_entry = {}
    external_prototypes_by_entry = {}
    external_prototypes_by_name = {}
    try:
        fm = program.getFunctionManager()
        funcs = fm.getFunctions(True)
        while funcs.hasNext():
            func = funcs.next()
            entry = safe_str(func.getEntryPoint())
            record = {
                "name": func.getName(),
                "entry": entry,
                "body_ranges": get_address_ranges(func.getBody()),
                "is_external": bool(safe_call(False, func.isExternal)),
                "is_thunk": bool(safe_call(False, func.isThunk)),
                "thunked_function": None,
                "signature": safe_str(safe_call(None, func.getSignature)),
                "signature_source": safe_str(safe_call(None, func.getSignatureSource)),
                "calling_convention": safe_str(safe_call(None, func.getCallingConventionName)),
            }
            thunked = safe_call(None, func.getThunkedFunction, True)
            if thunked:
                record["thunked_function"] = {
                    "name": thunked.getName(),
                    "entry": safe_str(thunked.getEntryPoint()),
                }
            if entry:
                by_entry[entry] = record
                if record["is_external"]:
                    imports_by_entry[entry] = record
                if record["is_thunk"]:
                    thunks_by_entry[entry] = record
                if record["is_external"] or record["is_thunk"]:
                    prototype = get_external_prototype(func)
                    if prototype:
                        external_prototypes_by_entry[entry] = prototype
                        for name_key in (prototype.get("name"), prototype.get("normalized_name")):
                            if name_key:
                                external_prototypes_by_name.setdefault(name_key, []).append(prototype)
    except Exception as e:
        print("[-] function index 추출 실패: %s" % str(e))
    return by_entry, imports_by_entry, thunks_by_entry, external_prototypes_by_entry, external_prototypes_by_name


def get_instruction_data_refs(instructions):
    by_from = {}
    for instr_data in instructions:
        addr = instr_data.get("address")
        refs = []
        for ref in instr_data.get("refs_from", []):
            if ref.get("is_data"):
                refs.append(ref)
        if refs and addr:
            by_from[addr] = refs
    return by_from


def build_indices(program, instructions):
    symbols_by_address, symbol_imports_by_address = get_symbol_index(program)
    (
        functions_by_entry,
        imports_by_entry,
        thunks_by_entry,
        external_prototypes_by_entry,
        external_prototypes_by_name,
    ) = get_function_index(program)
    return {
        "symbols_by_address": symbols_by_address,
        "functions_by_entry": functions_by_entry,
        "data_refs_by_from": get_instruction_data_refs(instructions),
        "imports_by_address": symbol_imports_by_address,
        "imports_by_entry": imports_by_entry,
        "thunks_by_entry": thunks_by_entry,
        "external_prototypes_by_entry": external_prototypes_by_entry,
        "external_prototypes_by_name": external_prototypes_by_name,
    }


def build_metadata_identity(program_hints, indices):
    identity = {
        "schema_version": DUMPER_SCHEMA_VERSION,
        "dumper": DUMPER_NAME,
        "program_name": program_hints.get("name"),
        "executable_path": program_hints.get("executable_path"),
        "image_base": program_hints.get("image_base"),
        "language_id": program_hints.get("language_id"),
        "compiler_spec_id": program_hints.get("compiler_spec_id"),
        "default_pointer_size": program_hints.get("default_pointer_size"),
        "architecture_hash": stable_hash(program_hints.get("architecture")),
        "indices_hash": stable_hash({
            "symbols_by_address": indices.get("symbols_by_address"),
            "functions_by_entry": indices.get("functions_by_entry"),
            "imports_by_address": indices.get("imports_by_address"),
            "imports_by_entry": indices.get("imports_by_entry"),
            "thunks_by_entry": indices.get("thunks_by_entry"),
            "external_prototypes_by_entry": indices.get("external_prototypes_by_entry"),
            "external_prototypes_by_name": indices.get("external_prototypes_by_name"),
        }),
    }
    identity["metadata_hash"] = stable_hash(identity)
    return identity


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
    program_hints = get_program_hints(currentProgram)
    (
        functions_by_entry,
        imports_by_entry,
        thunks_by_entry,
        external_prototypes_by_entry,
        external_prototypes_by_name,
    ) = get_function_index(currentProgram)
    manifest_indices = {
        "functions_by_entry": functions_by_entry,
        "imports_by_entry": imports_by_entry,
        "thunks_by_entry": thunks_by_entry,
        "external_prototypes_by_entry": external_prototypes_by_entry,
        "external_prototypes_by_name": external_prototypes_by_name,
    }
    manifest = {
        "schema_version": DUMPER_SCHEMA_VERSION,
        "dumper": DUMPER_NAME,
        "mode": "case_DFB_with_reachable_internal_helpers",
        "max_depth": REACHABLE_HELPER_MAX_DEPTH,
        "program": program_hints,
        "metadata_identity": build_metadata_identity(program_hints, manifest_indices),
        "indices": manifest_indices,
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
    if not os.path.isdir(base_path):
        os.makedirs(base_path)
    return os.path.join(base_path, filename)


def get_domain_folder_parts(program):
    domain_file = safe_call(None, program.getDomainFile)
    if domain_file is None:
        return []
    parent = safe_call(None, domain_file.getParent)
    pathname = safe_call(None, parent.getPathname) if parent else None
    if not pathname:
        return []
    parts = []
    for part in str(pathname).replace("\\", "/").split("/"):
        if part and part != ".":
            parts.append(part)
    return parts


def normalize_domain_folder_parts(parts):
    if not parts:
        return []
    normalized = list(parts)
    if normalized[0] == "arm64":
        normalized[0] = "linux_arm64"
    elif normalized[0] == "arm_v7":
        normalized[0] = "linux_arm_v7"
    return normalized


def get_program_output_category(program):
    name = safe_str(safe_call(None, program.getName)) or ""
    base_name = os.path.splitext(name)[0]
    if base_name.startswith("dfbench_"):
        base_name = base_name[len("dfbench_"):]
    for suffix in ("_arm64", "_arm_v7"):
        if base_name.endswith(suffix):
            base_name = base_name[:-len(suffix)]

    for category in ("cpp_exceptions", "posix_runtime", "win_core", "cpp"):
        if category in base_name:
            return category
    return None


def get_script_options():
    options = {
        "output_root": None,
        "output_dir": None,
        "use_project_path": True,
        "use_program_category": True,
        "root_prefix": "case_DFB",
        "max_depth": REACHABLE_HELPER_MAX_DEPTH,
    }
    args = []
    try:
        args = list(getScriptArgs())
    except Exception:
        args = []

    index = 0
    while index < len(args):
        arg = args[index]
        if arg in ("--output-root", "-o") and index + 1 < len(args):
            options["output_root"] = args[index + 1]
            index += 2
            continue
        if arg == "--output-dir" and index + 1 < len(args):
            options["output_dir"] = args[index + 1]
            options["use_project_path"] = False
            index += 2
            continue
        if arg == "--flat-output":
            options["use_project_path"] = False
            index += 1
            continue
        if arg == "--no-program-category":
            options["use_program_category"] = False
            index += 1
            continue
        if arg == "--root-prefix" and index + 1 < len(args):
            options["root_prefix"] = args[index + 1]
            index += 2
            continue
        if arg == "--max-depth" and index + 1 < len(args):
            try:
                options["max_depth"] = int(args[index + 1])
            except Exception:
                options["max_depth"] = REACHABLE_HELPER_MAX_DEPTH
            index += 2
            continue
        if options["output_root"] is None:
            options["output_root"] = arg
        index += 1
    return options


def resolve_output_dir(options):
    if options.get("output_dir"):
        return normalize_output_dir(options["output_dir"])
    output_root = options.get("output_root")
    if output_root:
        base = normalize_output_dir(output_root)
        if options.get("use_project_path"):
            parts = normalize_domain_folder_parts(get_domain_folder_parts(currentProgram))
            if options.get("use_program_category"):
                category = get_program_output_category(currentProgram)
                if category and (not parts or parts[-1] != category):
                    parts.append(category)
            if parts:
                return os.path.join(base, *parts)
        return base

    try:
        selected_dir = askDirectory("case_DFB* 및 reachable helper Low P-Code JSON 저장 폴더를 선택하세요", "저장")
        return normalize_output_dir(selected_dir.getAbsolutePath())
    except Exception:
        print("[-] 경로 선택이 취소되었습니다.")
        return None

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
    program_hints = get_program_hints(program)
    
    func_data = {
        "schema_version": DUMPER_SCHEMA_VERSION,
        "dumper": DUMPER_NAME,
        "compatibility": {
            "legacy_v1_fields_preserved": True,
            "legacy_instruction_low_pcode_shape_preserved": True,
            "new_fields_are_optional_hints": True
        },
        "program": program_hints,
        "ghidra_hints": {
            "function": get_function_hints(func),
            "metadata_policy": {
                "registers_and_address_spaces_are_storage_metadata": True,
                "calling_convention_signature_parameters_are_compatibility_hints_only": True,
                "external_prototypes_are_summary_resolution_metadata_only": True,
                "core_must_not_interpret_parameters_or_returns": True,
            }
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
        
    func_data["indices"] = build_indices(program, func_data["instructions"])
    func_data["metadata_identity"] = build_metadata_identity(program_hints, func_data["indices"])
    return func_data

def run():
    options = get_script_options()
    base_path = resolve_output_dir(options)

    if not base_path:
        return

    root_prefix = options.get("root_prefix") or "case_DFB"
    max_depth = options.get("max_depth") or REACHABLE_HELPER_MAX_DEPTH
    seed_funcs = find_functions_by_prefix(root_prefix)

    if not seed_funcs:
        cursor_func = getFunctionContaining(currentAddress)
        if cursor_func is not None:
            seed_funcs = [cursor_func]
            print("[!] %s* 함수를 찾지 못해 커서 함수만 추출합니다: %s" % (root_prefix, cursor_func.getName()))

    if not seed_funcs:
        print("[-] 추출할 함수가 없습니다. %s* 함수가 존재하는지 확인하세요." % root_prefix)
        return

    funcs, call_edges, skipped_targets = collect_reachable_internal_functions(seed_funcs, max_depth)
    print("[*] 출력 경로: %s" % base_path)
    print("[*] %s* root 함수 수: %d" % (root_prefix, len(seed_funcs)))
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


# --- 스크립트 실행부 ---
run()
