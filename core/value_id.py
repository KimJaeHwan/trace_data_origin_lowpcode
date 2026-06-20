from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class ValueId:
    function: str
    context: str
    space: str
    key: str
    version: int | None = None

    def stable_id(self) -> str:
        suffix = "" if self.version is None else f":{self.version}"
        return f"{self.function}:{self.context}:{self.space}:{self.key}{suffix}"

    def __str__(self) -> str:
        return self.stable_id()
