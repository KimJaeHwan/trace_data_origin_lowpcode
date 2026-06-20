from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from core.architecture import ArchitectureSpec


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


class LowPcodeLoader:
    def load(self, path: str | Path, arch_preset: str | None = None) -> LowPcodeProgram:
        json_path = Path(path)
        with json_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        arch_name = arch_preset or self._infer_architecture(json_path)
        return LowPcodeProgram(json_path, data, ArchitectureSpec.from_preset(arch_name))

    def _infer_architecture(self, path: Path) -> str:
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
