from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from core.architecture import ArchitectureSpec
from frontend.external_prototype import ExternalPrototype, load_external_prototypes


@dataclass(frozen=True)
class LowPcodeProgram:
    path: Path
    data: dict
    architecture: ArchitectureSpec

    @property
    def function_name(self) -> str:
        return self.data.get("function_name") or self.path.stem.replace("_low_pcode", "")

    @property
    def instructions(self) -> list[dict]:
        return list(self.data.get("instructions", []))

    @property
    def metadata_cache_key(self) -> str:
        identity = self.data.get("metadata_identity") or {}
        if identity.get("metadata_hash"):
            return str(identity["metadata_hash"])
        program = self.data.get("program") or {}
        fallback = {
            "schema_version": self.data.get("schema_version"),
            "dumper": self.data.get("dumper"),
            "language_id": program.get("language_id"),
            "compiler_spec_id": program.get("compiler_spec_id"),
            "default_pointer_size": program.get("default_pointer_size"),
            "architecture": program.get("architecture"),
        }
        encoded = json.dumps(fallback, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @property
    def external_prototypes(self) -> dict[str, ExternalPrototype]:
        return load_external_prototypes(self.data)


class LowPcodeLoader:
    def load(self, path: str | Path, arch_preset: str | None = None) -> LowPcodeProgram:
        json_path = Path(path)
        with json_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        self._annotate_flow_target_names(data)
        arch_name = arch_preset or self._infer_architecture(json_path, data)
        return LowPcodeProgram(json_path, data, ArchitectureSpec.from_metadata(arch_name, data.get("program") or {}))

    def _annotate_flow_target_names(self, data: dict) -> None:
        indices = data.get("indices") or {}
        symbols_by_address = indices.get("symbols_by_address") or {}
        functions_by_entry = indices.get("functions_by_entry") or {}

        names_by_address: dict[str, list[str]] = {}
        function_entry_by_name: dict[str, str] = {}
        for address, symbols in symbols_by_address.items():
            for symbol in symbols or []:
                name = symbol.get("name")
                if name and name not in names_by_address.setdefault(str(address), []):
                    names_by_address[str(address)].append(str(name))
        for address, function in functions_by_entry.items():
            name = function.get("name")
            if name and name not in names_by_address.setdefault(str(address), []):
                names_by_address[str(address)].append(str(name))
            if name:
                function_entry_by_name.setdefault(str(name), str(address))

        for instr in data.get("instructions", []):
            names: list[str] = []
            targets = list(instr.get("flow_targets") or [])
            for ref in instr.get("refs_from") or []:
                if ref.get("is_flow") or ref.get("is_jump"):
                    target = ref.get("to")
                    if target:
                        targets.append(str(target))
            for target in targets:
                for name in names_by_address.get(str(target), []):
                    if name not in names:
                        names.append(name)
            if names:
                instr["flow_target_names"] = names
            pointer_reads = self._function_pointer_reads(instr, symbols_by_address, function_entry_by_name)
            if pointer_reads:
                instr["function_pointer_reads"] = pointer_reads

    def _function_pointer_reads(
        self,
        instr: dict,
        symbols_by_address: dict,
        function_entry_by_name: dict[str, str],
    ) -> list[dict]:
        reads: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for ref in instr.get("refs_from") or []:
            if not ref.get("is_data") or not ref.get("is_read"):
                continue
            data_address = str(ref.get("to") or "")
            if not data_address:
                continue
            for symbol in symbols_by_address.get(data_address) or []:
                symbol_name = str(symbol.get("name") or "")
                target_name = self._function_name_from_pointer_symbol(symbol_name, data_address, function_entry_by_name)
                if not target_name:
                    continue
                target_entry = function_entry_by_name.get(target_name)
                if not target_entry:
                    continue
                key = (target_entry, target_name)
                if key in seen:
                    continue
                seen.add(key)
                reads.append(
                    {
                        "address": target_entry,
                        "name": target_name,
                        "data_address": data_address,
                        "source_symbol": symbol_name,
                        "confidence": "ghidra_data_pointer_symbol",
                    }
                )
        return reads

    def _function_name_from_pointer_symbol(
        self,
        symbol_name: str,
        data_address: str,
        function_entry_by_name: dict[str, str],
    ) -> str | None:
        if not symbol_name.startswith("PTR_"):
            return None
        candidate = symbol_name.removeprefix("PTR_")
        suffix = data_address.lower().lstrip("0") or "0"
        parts = candidate.rsplit("_", 1)
        if len(parts) == 2 and parts[1].lower().lstrip("0") == suffix:
            candidate = parts[0]
        if candidate in function_entry_by_name:
            return candidate
        return None

    def _infer_architecture(self, path: Path, data: dict | None = None) -> str:
        program = (data or {}).get("program") or {}
        inferred = self._infer_architecture_from_program(program)
        if inferred:
            return inferred
        parts = {part.lower() for part in path.parts}
        if "pe_x86" in parts or "linux_386" in parts:
            return "x86"
        if "pe_x64" in parts or "linux_amd64" in parts:
            return "x86_64"
        if "linux_arm64" in parts:
            return "aarch64"
        if "linux_arm_v7" in parts:
            return "armv7"
        return "x86"

    def _infer_architecture_from_program(self, program: dict) -> str | None:
        language_id = str(program.get("language_id") or "").lower()
        processor = str(program.get("processor") or "").lower()
        pointer_size = program.get("default_pointer_size")
        if "aarch64" in language_id or "aarch64" in processor:
            return "aarch64"
        if language_id.startswith("arm:") or processor == "arm":
            return "armv7"
        if language_id.startswith("x86:") or processor == "x86":
            if str(pointer_size) == "8" or ":64:" in language_id:
                return "x86_64"
            if str(pointer_size) == "4" or ":32:" in language_id:
                return "x86"
        return None
