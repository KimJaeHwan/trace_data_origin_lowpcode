from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from frontend.low_pcode_loader import LowPcodeProgram


PROGRAM_CLOSURE_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ProgramClosurePlan:
    programs: tuple[LowPcodeProgram, ...]
    mode: str
    trusted: bool
    fallback_reason: str = ""


class ConservativeProgramClosurePlanner:
    """Select a root-reachable function closure or conservatively keep all input."""

    def plan(
        self,
        programs: list[LowPcodeProgram],
        target: LowPcodeProgram | None,
    ) -> ProgramClosurePlan:
        ordered = tuple(sorted(programs, key=lambda item: (item.function_name, str(item.path))))
        if target is None:
            return ProgramClosurePlan(ordered, "full", False, "target_not_found")

        programs_by_name = {program.function_name: program for program in ordered}
        aliases = self._name_aliases(ordered)
        root_name = target.function_name
        if root_name not in programs_by_name:
            return ProgramClosurePlan(ordered, "full", False, "target_identity_not_found")

        selected: set[str] = set()
        queue = deque([root_name])
        while queue:
            function_name = queue.popleft()
            if function_name in selected:
                continue
            program = programs_by_name.get(function_name)
            if program is None:
                return ProgramClosurePlan(ordered, "full", False, f"missing_internal_target:{function_name}")
            selected.add(function_name)
            candidates, unresolved_computed = self._candidate_callees(program, aliases, programs_by_name)
            if unresolved_computed:
                return ProgramClosurePlan(
                    ordered,
                    "full",
                    False,
                    f"unresolved_computed_flow:{function_name}",
                )
            for candidate in sorted(candidates):
                if candidate not in selected:
                    queue.append(candidate)

        selected_programs = tuple(program for program in ordered if program.function_name in selected)
        if not selected_programs or len(selected_programs) == len(ordered):
            return ProgramClosurePlan(ordered, "full", True, "")
        return ProgramClosurePlan(selected_programs, "demand", True, "")

    def _name_aliases(self, programs: tuple[LowPcodeProgram, ...]) -> dict[str, set[str]]:
        aliases: dict[str, set[str]] = {}
        for program in programs:
            aliases.setdefault(program.function_name, set()).add(program.function_name)
            raw_name = str(program.data.get("function_name") or "")
            if raw_name:
                aliases.setdefault(raw_name, set()).add(program.function_name)
        return aliases

    def _candidate_callees(
        self,
        program: LowPcodeProgram,
        aliases: dict[str, set[str]],
        programs_by_name: dict[str, LowPcodeProgram],
    ) -> tuple[set[str], bool]:
        candidates: set[str] = set()
        unresolved_computed = False
        for instr in program.instructions:
            names = self._instruction_target_names(instr)
            internal_names = {
                identity
                for name in names
                for identity in aliases.get(name, set())
                if identity in programs_by_name
            }
            candidates.update(internal_names)
            opcodes = {
                str(pcode.get("opcode") or "").upper()
                for pcode in (instr.get("low_pcode") or [])
            }
            if opcodes & {"CALLIND", "BRANCHIND"} and not internal_names:
                unresolved_computed = True

        function_hints = ((program.data.get("ghidra_hints") or {}).get("function") or {})
        if isinstance(function_hints, dict):
            thunked = function_hints.get("thunked_function") or {}
            thunked_name = str(thunked.get("name") or "") if isinstance(thunked, dict) else ""
            candidates.update(aliases.get(thunked_name, set()))
        return candidates, unresolved_computed

    def _instruction_target_names(self, instr: dict) -> set[str]:
        names = {
            str(name)
            for name in (instr.get("flow_target_names") or [])
            if name
        }
        for key in ("call_targets", "inferred_call_targets"):
            for target in instr.get(key) or []:
                name = target.get("function_name") or target.get("name")
                if name:
                    names.add(str(name))
        for pointer_read in instr.get("function_pointer_reads") or []:
            name = pointer_read.get("name") or pointer_read.get("function_name")
            if name:
                names.add(str(name))
        return names
