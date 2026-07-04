from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ResolvedCallTarget:
    address: str | None
    name: str | None
    is_thunk: bool = False
    thunk_target_name: str | None = None
    confidence: str = "unresolved_indirect_call"


class CallResolver:
    def resolve(self, instr: dict) -> ResolvedCallTarget:
        for target in instr.get("call_targets", []):
            if target.get("resolved") and target.get("function_name"):
                return ResolvedCallTarget(
                    address=target.get("address"),
                    name=target.get("function_name"),
                    is_thunk=bool(target.get("is_thunk")),
                    thunk_target_name=target.get("thunk_target_name"),
                    confidence="ghidra_symbol_verified",
                )
        for target in instr.get("inferred_call_targets", []):
            if target.get("resolved") and target.get("function_name"):
                return ResolvedCallTarget(
                    address=target.get("address"),
                    name=target.get("function_name"),
                    is_thunk=bool(target.get("is_thunk")),
                    thunk_target_name=target.get("thunk_target_name"),
                    confidence=target.get("confidence") or "inferred_call_target",
                )
        flow_targets = instr.get("flow_targets", [])
        if flow_targets:
            return ResolvedCallTarget(
                address=flow_targets[0],
                name=None,
                confidence="low_pcode_direct_target",
            )
        return ResolvedCallTarget(address=None, name=None)
