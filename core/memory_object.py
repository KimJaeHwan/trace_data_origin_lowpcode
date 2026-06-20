from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StackObject:
    function: str
    context: str
    base: str
    offset: int
    size: int | None = None

    def key(self) -> str:
        return f"{self.function}:{self.context}:stack:{self.base}:{self.offset}:{self.size or '*'}"


@dataclass(frozen=True)
class GlobalObject:
    module: str | None
    address: str
    symbol: str | None = None
    section: str | None = None
    size: int | None = None

    def key(self) -> str:
        if self.symbol:
            return f"global:symbol:{self.symbol}:{self.size or '*'}"
        return f"global:{self.address}:{self.size or '*'}"


@dataclass(frozen=True)
class HeapObject:
    allocation_site: str
    offset: int = 0
    size: int | None = None

    def key(self) -> str:
        return f"heap:allocsite:{self.allocation_site}:offset:{self.offset}:{self.size or '*'}"


@dataclass(frozen=True)
class UnknownExternalObject:
    reason: str
    size: int | None = None

    def key(self) -> str:
        return f"unknown:{self.reason}:{self.size or '*'}"
