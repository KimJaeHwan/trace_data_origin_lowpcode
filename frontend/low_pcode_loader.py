from __future__ import annotations

import hashlib
import json
import os
import pickle
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.architecture import ArchitectureSpec
from frontend.external_prototype import ExternalPrototype, load_external_prototypes


PARSED_CACHE_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class LowPcodeProgram:
    path: Path
    data: dict
    architecture: ArchitectureSpec

    @property
    def function_name(self) -> str:
        raw_name = self.data.get("function_name") or self.path.stem.replace("_low_pcode", "")
        entry = str(self.data.get("start_address") or "")
        if raw_name and entry:
            functions_by_entry = (self.data.get("indices") or {}).get("functions_by_entry") or {}
            duplicate_count = 0
            for function in functions_by_entry.values():
                if str((function or {}).get("name") or "") == raw_name:
                    duplicate_count += 1
            if duplicate_count > 1:
                return f"{raw_name}_{entry}"
        return raw_name

    @property
    def instructions(self) -> list[dict]:
        return self.data.get("instructions", [])

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
    def __init__(self, cache_dir: str | Path | None = None):
        self.cache_dir = Path(cache_dir) if cache_dir is not None else None
        self._memory_cache: dict[tuple[str, int, int, str], LowPcodeProgram] = {}
        self.cache_stats = {
            "memory_hits": 0,
            "disk_hits": 0,
            "misses": 0,
            "source_bytes": 0,
        }

    def load(self, path: str | Path, arch_preset: str | None = None) -> LowPcodeProgram:
        json_path = Path(path).resolve()
        stat = json_path.stat()
        memory_key = (str(json_path), stat.st_mtime_ns, stat.st_size, arch_preset or "")
        cached_program = self._memory_cache.get(memory_key)
        if cached_program is not None:
            self.cache_stats["memory_hits"] += 1
            return cached_program

        source_bytes = json_path.read_bytes()
        self.cache_stats["source_bytes"] += len(source_bytes)
        source_hash = hashlib.sha256(source_bytes).hexdigest()
        data = self._load_parsed_cache(source_hash)
        if data is None:
            data = json.loads(source_bytes)
            self._annotate_flow_target_names(data)
            self._save_parsed_cache(source_hash, data)
            self.cache_stats["misses"] += 1
        else:
            self.cache_stats["disk_hits"] += 1
        arch_name = arch_preset or self._infer_architecture(json_path, data)
        program = LowPcodeProgram(
            json_path,
            data,
            ArchitectureSpec.from_metadata(arch_name, data.get("program") or {}),
        )
        self._memory_cache[memory_key] = program
        return program

    def _load_parsed_cache(self, source_hash: str) -> dict | None:
        cache_path = self._parsed_cache_path(source_hash)
        if cache_path is None or not cache_path.is_file():
            return None
        try:
            with cache_path.open("rb") as f:
                payload = pickle.load(f)
            if not isinstance(payload, dict):
                return None
            if payload.get("schema_version") != PARSED_CACHE_SCHEMA_VERSION:
                return None
            if payload.get("source_hash") != source_hash:
                return None
            data = payload.get("data")
            return data if isinstance(data, dict) else None
        except (OSError, EOFError, pickle.PickleError, AttributeError, ValueError):
            return None

    def _save_parsed_cache(self, source_hash: str, data: dict) -> None:
        cache_path = self._parsed_cache_path(source_hash)
        if cache_path is None:
            return
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            payload: dict[str, Any] = {
                "schema_version": PARSED_CACHE_SCHEMA_VERSION,
                "source_hash": source_hash,
                "data": data,
            }
            fd, temporary_name = tempfile.mkstemp(
                prefix=f".{source_hash}.",
                suffix=".tmp",
                dir=cache_path.parent,
            )
            try:
                with os.fdopen(fd, "wb") as f:
                    pickle.dump(payload, f, protocol=pickle.HIGHEST_PROTOCOL)
                os.replace(temporary_name, cache_path)
            except Exception:
                try:
                    os.unlink(temporary_name)
                except OSError:
                    pass
                raise
        except (OSError, pickle.PickleError):
            return

    def _parsed_cache_path(self, source_hash: str) -> Path | None:
        if self.cache_dir is None:
            return None
        return self.cache_dir / f"v{PARSED_CACHE_SCHEMA_VERSION}" / source_hash[:2] / f"{source_hash}.pickle"

    def _annotate_flow_target_names(self, data: dict) -> None:
        indices = data.get("indices") or {}
        symbols_by_address = indices.get("symbols_by_address") or {}
        functions_by_entry = indices.get("functions_by_entry") or {}

        names_by_address: dict[str, list[str]] = {}
        function_entry_by_name: dict[str, str] = {}
        identity_by_entry = self._function_identity_by_entry(functions_by_entry)
        for address, symbols in symbols_by_address.items():
            for symbol in symbols or []:
                name = symbol.get("name")
                if name and name not in names_by_address.setdefault(str(address), []):
                    names_by_address[str(address)].append(str(name))
        for address, function in functions_by_entry.items():
            raw_name = str(function.get("name") or "")
            name = identity_by_entry.get(str(address), raw_name)
            if name and name not in names_by_address.setdefault(str(address), []):
                names_by_address[str(address)].append(str(name))
            if name:
                function_entry_by_name.setdefault(str(name), str(address))

        for instr in data.get("instructions", []):
            self._rewrite_call_target_names(instr, identity_by_entry)
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
            pointer_reads = self._function_pointer_reads(
                instr,
                symbols_by_address,
                functions_by_entry,
                function_entry_by_name,
            )
            if pointer_reads:
                instr["function_pointer_reads"] = pointer_reads

    def _function_identity_by_entry(self, functions_by_entry: dict) -> dict[str, str]:
        counts: dict[str, int] = {}
        for function in functions_by_entry.values():
            name = str((function or {}).get("name") or "")
            if name:
                counts[name] = counts.get(name, 0) + 1
        identities: dict[str, str] = {}
        for entry, function in functions_by_entry.items():
            name = str((function or {}).get("name") or "")
            if not name:
                continue
            entry_text = str(entry)
            identities[entry_text] = f"{name}_{entry_text}" if counts.get(name, 0) > 1 else name
        return identities

    def _rewrite_call_target_names(self, instr: dict, identity_by_entry: dict[str, str]) -> None:
        for key in ("call_targets", "inferred_call_targets"):
            for target in instr.get(key) or []:
                entry = str(target.get("entry") or target.get("address") or "")
                identity = identity_by_entry.get(entry)
                if not identity:
                    continue
                raw_name = target.get("function_name")
                if raw_name and raw_name != identity and not target.get("raw_function_name"):
                    target["raw_function_name"] = raw_name
                target["function_name"] = identity

    def _function_pointer_reads(
        self,
        instr: dict,
        symbols_by_address: dict,
        functions_by_entry: dict,
        function_entry_by_name: dict[str, str],
    ) -> list[dict]:
        reads: list[dict] = []
        seen: set[tuple[str, str]] = set()
        read_data_addresses = [
            str(ref.get("to") or "")
            for ref in instr.get("refs_from") or []
            if ref.get("is_data")
            and ref.get("is_read")
            and str(ref.get("to") or "")
            and not str(ref.get("to") or "").startswith("Stack")
        ]
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
        for ref in instr.get("refs_from") or []:
            if not ref.get("is_data") or str(ref.get("type") or "").upper() != "PARAM":
                continue
            target_entry = str(ref.get("to") or "")
            if not target_entry:
                continue
            function = functions_by_entry.get(target_entry) or {}
            target_name = str(function.get("name") or "")
            if not target_name:
                continue
            key = (target_entry, target_name)
            if key in seen:
                continue
            seen.add(key)
            reads.append(
                {
                    "address": target_entry,
                    "name": target_name,
                    "data_address": read_data_addresses[0] if len(read_data_addresses) == 1 else "",
                    "source_symbol": target_name,
                    "confidence": "ghidra_param_function_reference",
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
