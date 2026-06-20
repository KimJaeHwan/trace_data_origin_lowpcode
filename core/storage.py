from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StackStorage:
    function: str
    context: str
    base: str
    offset: int
    size: int | None
    relation: str = "observed"

    def key(self) -> str:
        return f"{self.function}:{self.context}:stack:{self.base}:{self.offset}:{self.size or '*'}"


@dataclass(frozen=True)
class MemoryStorage:
    space: str
    key_value: str
    size: int | None = None

    def key(self) -> str:
        return f"{self.space}:{self.key_value}:{self.size or '*'}"
