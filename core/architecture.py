from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RegisterAlias:
    display: str
    canonical: str
    offset_bits: int
    size_bits: int


@dataclass(frozen=True)
class RegisterStorage:
    arch: str
    canonical: str
    offset_bits: int
    size_bits: int
    display: str

    def key(self) -> str:
        return f"{self.canonical}:{self.offset_bits}:{self.size_bits}"


@dataclass(frozen=True)
class ArchitectureSpec:
    name: str
    pointer_size: int
    endian: str
    stack_pointer_regs: set[str]
    frame_pointer_regs: set[str]
    link_registers: set[str]
    general_registers: set[str]
    register_aliases: dict[tuple[int, int], RegisterAlias]

    @classmethod
    def from_preset(cls, name: str) -> "ArchitectureSpec":
        normalized = name.lower()
        if normalized in {"x86", "i386", "linux_386", "pe_x86"}:
            aliases = {
                (0x0, 4): RegisterAlias("EAX", "EAX", 0, 32),
                (0x4, 4): RegisterAlias("ECX", "ECX", 0, 32),
                (0x8, 4): RegisterAlias("EDX", "EDX", 0, 32),
                (0xC, 4): RegisterAlias("EBX", "EBX", 0, 32),
                (0x10, 4): RegisterAlias("ESP", "ESP", 0, 32),
                (0x14, 4): RegisterAlias("EBP", "EBP", 0, 32),
                (0x18, 4): RegisterAlias("ESI", "ESI", 0, 32),
                (0x1C, 4): RegisterAlias("EDI", "EDI", 0, 32),
                (0x284, 4): RegisterAlias("EIP", "EIP", 0, 32),
            }
            return cls(
                name="x86",
                pointer_size=4,
                endian="little",
                stack_pointer_regs={"ESP"},
                frame_pointer_regs={"EBP"},
                link_registers=set(),
                general_registers={"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"},
                register_aliases=aliases,
            )
        if normalized in {"x86_64", "x64", "amd64", "pe_x64", "linux_amd64"}:
            aliases = {
                (0x0, 8): RegisterAlias("RAX", "RAX", 0, 64),
                (0x0, 4): RegisterAlias("EAX", "RAX", 0, 32),
                (0x8, 8): RegisterAlias("RCX", "RCX", 0, 64),
                (0x8, 4): RegisterAlias("ECX", "RCX", 0, 32),
                (0x20, 8): RegisterAlias("RSP", "RSP", 0, 64),
                (0x28, 8): RegisterAlias("RBP", "RBP", 0, 64),
                (0x38, 8): RegisterAlias("RDI", "RDI", 0, 64),
                (0x38, 4): RegisterAlias("EDI", "RDI", 0, 32),
                (0x288, 8): RegisterAlias("RIP", "RIP", 0, 64),
            }
            return cls(
                name="x86_64",
                pointer_size=8,
                endian="little",
                stack_pointer_regs={"RSP"},
                frame_pointer_regs={"RBP"},
                link_registers=set(),
                general_registers={"RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI"},
                register_aliases=aliases,
            )
        if normalized in {"aarch64", "arm64", "linux_arm64"}:
            aliases = {
                (0x4000, 8): RegisterAlias("x0", "x0", 0, 64),
                (0x4000, 4): RegisterAlias("w0", "x0", 0, 32),
                (0x4008, 8): RegisterAlias("x1", "x1", 0, 64),
                (0x4008, 4): RegisterAlias("w1", "x1", 0, 32),
                (0x4010, 8): RegisterAlias("x2", "x2", 0, 64),
                (0x4010, 4): RegisterAlias("w2", "x2", 0, 32),
                (0x4018, 8): RegisterAlias("x3", "x3", 0, 64),
                (0x4018, 4): RegisterAlias("w3", "x3", 0, 32),
                (0x8, 8): RegisterAlias("sp", "sp", 0, 64),
                (0x40E8, 8): RegisterAlias("x29", "x29", 0, 64),
                (0x40F0, 8): RegisterAlias("x30", "x30", 0, 64),
            }
            return cls(
                name="aarch64",
                pointer_size=8,
                endian="little",
                stack_pointer_regs={"sp"},
                frame_pointer_regs={"x29"},
                link_registers={"x30"},
                general_registers={"x0", "x1", "x2", "x3", "x29", "x30", "sp"},
                register_aliases=aliases,
            )
        if normalized in {"armv7", "arm", "linux_arm_v7"}:
            aliases = {
                (0x20, 4): RegisterAlias("r0", "r0", 0, 32),
                (0x54, 4): RegisterAlias("sp", "sp", 0, 32),
                (0x58, 4): RegisterAlias("lr", "lr", 0, 32),
                (0x5C, 4): RegisterAlias("pc", "pc", 0, 32),
            }
            return cls(
                name="armv7",
                pointer_size=4,
                endian="little",
                stack_pointer_regs={"sp"},
                frame_pointer_regs={"r7"},
                link_registers={"lr"},
                general_registers={"r0", "r1", "r2", "r3", "sp", "lr"},
                register_aliases=aliases,
            )
        return cls.from_preset("x86")

    def canonicalize_register(
        self,
        offset: int,
        size_bytes: int,
        display_hint: str | None = None,
    ) -> RegisterStorage:
        alias = self.register_aliases.get((offset, size_bytes))
        if alias is None and display_hint:
            canonical = display_hint.upper() if self.name.startswith("x86") else display_hint
            return RegisterStorage(
                arch=self.name,
                canonical=canonical,
                offset_bits=0,
                size_bits=size_bytes * 8,
                display=display_hint,
            )
        if alias is None:
            display = f"reg_{offset:x}_{size_bytes}"
            alias = RegisterAlias(display, display, 0, size_bytes * 8)
        return RegisterStorage(
            arch=self.name,
            canonical=alias.canonical,
            offset_bits=alias.offset_bits,
            size_bits=alias.size_bits,
            display=alias.display,
        )
