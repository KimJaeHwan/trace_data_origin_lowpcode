from __future__ import annotations

from dataclasses import dataclass, field

from core.architecture import ArchitectureSpec
from core.value_id import ValueId


@dataclass(frozen=True)
class ObservedStorage:
    storage_key: str
    value: ValueId | None = None
    confidence: str = "candidate"


@dataclass
class CallContext:
    callsite_id: str
    caller_function: str
    callee_function: str | None
    caller_context: str
    callee_context: str | None
    continuation_storage: ObservedStorage | None
    target_confidence: str
    pre_call_observed_storages: list[ObservedStorage] = field(default_factory=list)
    post_call_observed_storages: list[ObservedStorage] = field(default_factory=list)
    callee_entry_observed_storages: list[ObservedStorage] = field(default_factory=list)
    callee_exit_observed_storages: list[ObservedStorage] = field(default_factory=list)


class CallBoundaryMapper:
    def collect_pre_call_observed_storages(self, state_current: dict[str, ValueId]) -> list[ObservedStorage]:
        observed = []
        for storage_key, value in sorted(state_current.items()):
            if storage_key.startswith("reg:"):
                observed.append(ObservedStorage(storage_key=storage_key, value=value, confidence="observed"))
        return observed

    def collect_post_call_observed_storages(self, architecture: ArchitectureSpec) -> list[ObservedStorage]:
        observed = []
        for storage_key in self.general_register_storage_keys(architecture):
            observed.append(ObservedStorage(storage_key=storage_key, confidence="candidate"))
        return observed

    def general_register_storage_keys(self, architecture: ArchitectureSpec) -> list[str]:
        keys = set()
        for alias in architecture.register_aliases.values():
            if alias.canonical in architecture.general_registers:
                keys.add(f"reg:{alias.canonical}:{alias.offset_bits}:{alias.size_bits}")
        return sorted(keys)
