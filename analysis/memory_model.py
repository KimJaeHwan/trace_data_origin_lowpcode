from __future__ import annotations

from core.memory_object import GlobalObject, HeapObject, StackObject, UnknownExternalObject


class MemoryModel:
    def stack_key(self, function: str, context: str, base: str, offset: int, size: int | None) -> str:
        return StackObject(function=function, context=context, base=base, offset=offset, size=size).key()

    def global_key(self, address: str, size: int | None) -> str:
        return GlobalObject(module=None, address=address, size=size).key()

    def heap_key(self, allocation_site: str, offset: int, size: int | None) -> str:
        return HeapObject(allocation_site=allocation_site, offset=offset, size=size).key()

    def unknown_key(self, reason: str, size: int | None) -> str:
        return UnknownExternalObject(reason=reason, size=size).key()
