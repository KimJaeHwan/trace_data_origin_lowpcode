from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ExternalParameter:
    ordinal: int | None
    name: str | None
    data_type: str | None
    storage: str | None
    source: str | None
    pointer_depth: int = 0
    data_type_size: int | None = None


@dataclass(frozen=True)
class ExternalOutput:
    data_type: str | None
    storage: str | None
    source: str | None
    pointer_depth: int = 0
    data_type_size: int | None = None


@dataclass(frozen=True)
class ExternalPrototype:
    prototype_id: str
    source: str
    library: str | None
    name: str
    normalized_name: str
    entry: str | None
    signature: str | None
    prototype_string: str | None
    signature_source: str | None
    calling_convention_name: str | None
    parameters: tuple[ExternalParameter, ...] = field(default_factory=tuple)
    output: ExternalOutput | None = None
    flags: dict = field(default_factory=dict)
    external_location: dict | None = None
    thunk_target: dict | None = None
    metadata_hash: str | None = None

    @property
    def canonical_names(self) -> tuple[str, ...]:
        names: list[str] = []
        for candidate in (self.name, self.normalized_name):
            if candidate and candidate not in names:
                names.append(candidate)
        if self.library:
            for candidate in (self.name, self.normalized_name):
                if candidate:
                    qualified = f"{self.library}!{candidate}"
                    if qualified not in names:
                        names.append(qualified)
        return tuple(names)


def load_external_prototypes(data: dict) -> dict[str, ExternalPrototype]:
    indices = data.get("indices") or {}
    raw_by_entry = indices.get("external_prototypes_by_entry") or {}
    prototypes: dict[str, ExternalPrototype] = {}
    for entry, raw in raw_by_entry.items():
        prototype = parse_external_prototype(raw)
        if prototype is not None:
            prototypes[str(entry)] = prototype

    if prototypes:
        return prototypes
    prototypes.update(_load_call_target_external_prototypes(data))
    if prototypes:
        return prototypes
    return _load_legacy_external_prototypes(indices)


def parse_external_prototype(raw: dict | None) -> ExternalPrototype | None:
    if not raw:
        return None
    name = str(raw.get("name") or raw.get("normalized_name") or "")
    if not name:
        return None
    normalized_name = str(raw.get("normalized_name") or _normalize_external_name(name))
    parameters = tuple(parse_external_parameter(item) for item in raw.get("parameters") or [])
    output = parse_external_output(raw.get("output") or {})
    prototype_id = str(raw.get("id") or _stable_hash(raw))
    return ExternalPrototype(
        prototype_id=prototype_id,
        source=str(raw.get("source") or "unknown"),
        library=raw.get("library"),
        name=name,
        normalized_name=normalized_name,
        entry=raw.get("entry"),
        signature=raw.get("signature"),
        prototype_string=raw.get("prototype_string"),
        signature_source=raw.get("signature_source"),
        calling_convention_name=raw.get("calling_convention_name"),
        parameters=parameters,
        output=output,
        flags=dict(raw.get("flags") or {}),
        external_location=raw.get("external_location"),
        thunk_target=raw.get("thunk_target"),
        metadata_hash=raw.get("metadata_hash"),
    )


def parse_external_parameter(raw: dict) -> ExternalParameter:
    data_type = raw.get("data_type_info") or {}
    return ExternalParameter(
        ordinal=_parse_int(raw.get("ordinal")),
        name=raw.get("name"),
        data_type=raw.get("data_type"),
        storage=raw.get("storage"),
        source=raw.get("source"),
        pointer_depth=_parse_int(data_type.get("pointer_depth")) or 0,
        data_type_size=_parse_int(data_type.get("length")),
    )


def parse_external_output(raw: dict) -> ExternalOutput:
    data_type = raw.get("data_type_info") or {}
    return ExternalOutput(
        data_type=raw.get("data_type"),
        storage=raw.get("storage"),
        source=raw.get("source"),
        pointer_depth=_parse_int(data_type.get("pointer_depth")) or 0,
        data_type_size=_parse_int(data_type.get("length")),
    )


def _load_legacy_external_prototypes(indices: dict) -> dict[str, ExternalPrototype]:
    raw_by_entry = indices.get("imports_by_entry") or {}
    prototypes: dict[str, ExternalPrototype] = {}
    for entry, raw in raw_by_entry.items():
        name = raw.get("name")
        if not name:
            continue
        normalized_name = _normalize_external_name(str(name))
        legacy = {
            "id": _stable_hash({"source": "ghidra_legacy_index", "entry": entry, "name": name}),
            "source": "ghidra_legacy_index",
            "name": name,
            "normalized_name": normalized_name,
            "entry": entry,
            "signature": raw.get("signature"),
            "signature_source": raw.get("signature_source"),
            "calling_convention_name": raw.get("calling_convention"),
            "flags": {
                "is_external": bool(raw.get("is_external")),
                "is_thunk": bool(raw.get("is_thunk")),
            },
            "thunk_target": raw.get("thunked_function"),
        }
        prototype = parse_external_prototype(legacy)
        if prototype is not None:
            prototypes[str(entry)] = prototype
    return prototypes


def _load_call_target_external_prototypes(data: dict) -> dict[str, ExternalPrototype]:
    prototypes: dict[str, ExternalPrototype] = {}
    for instr in data.get("instructions") or []:
        for target in instr.get("call_targets") or []:
            raw = target.get("external_prototype")
            if not raw:
                continue
            prototype = parse_external_prototype(raw)
            if prototype is None:
                continue
            entry = str(prototype.entry or target.get("entry") or target.get("address") or "")
            if entry:
                prototypes[entry] = prototype
    return prototypes


def _normalize_external_name(name: str) -> str:
    normalized = name
    if normalized.startswith("__imp_"):
        normalized = normalized[len("__imp_"):]
    while normalized.startswith("_") and len(normalized) > 1:
        normalized = normalized[1:]
    at_index = normalized.find("@")
    if at_index > 0 and normalized[at_index + 1:].isdigit():
        normalized = normalized[:at_index]
    return normalized


def _stable_hash(value: dict) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _parse_int(value) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
