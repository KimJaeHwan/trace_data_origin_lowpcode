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
    program_counter_regs: set[str] | None = None
    context_registers: set[str] | None = None
    zero_registers: set[str] | None = None
    hidden_registers: set[str] | None = None
    address_spaces: dict[str, dict] | None = None

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
                (0x10, 8): RegisterAlias("RDX", "RDX", 0, 64),
                (0x10, 4): RegisterAlias("EDX", "RDX", 0, 32),
                (0x20, 8): RegisterAlias("RSP", "RSP", 0, 64),
                (0x28, 8): RegisterAlias("RBP", "RBP", 0, 64),
                (0x30, 8): RegisterAlias("RSI", "RSI", 0, 64),
                (0x30, 4): RegisterAlias("ESI", "RSI", 0, 32),
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

    @classmethod
    def from_metadata(cls, name: str, program_metadata: dict | None) -> "ArchitectureSpec":
        base = cls.from_preset(name)
        if not program_metadata:
            return base

        architecture_metadata = program_metadata.get("architecture") or {}
        aliases: dict[tuple[int, int], RegisterAlias] = dict(base.register_aliases)
        general_registers: set[str] = set(base.general_registers)
        stack_pointer_regs: set[str] = set(base.stack_pointer_regs)
        frame_pointer_regs: set[str] = set(base.frame_pointer_regs)
        link_registers: set[str] = set(base.link_registers)
        program_counter_regs: set[str] = set(base.program_counter_regs or set())
        context_registers: set[str] = set(base.context_registers or set())
        zero_registers: set[str] = set(base.zero_registers or set())
        hidden_registers: set[str] = set(base.hidden_registers or set())

        register_items = architecture_metadata.get("registers") or program_metadata.get("registers", [])
        for item in register_items:
            name_text = str(item.get("name") or "")
            if not name_text:
                continue
            offset = _parse_int(item.get("offset"))
            size_bytes = item.get("size_bytes")
            bit_length = item.get("bit_length")
            if offset is None or size_bytes is None:
                continue
            try:
                size_bytes = int(size_bytes)
                bit_length = int(bit_length or size_bytes * 8)
            except (TypeError, ValueError):
                continue
            base_register = str(item.get("base_register") or name_text)
            canonical = base_register.upper() if base.name.startswith("x86") else base_register
            display = name_text.upper() if base.name.startswith("x86") else name_text
            offset_bits = int(item.get("least_significant_bit") or 0)
            aliases[(offset, size_bytes)] = RegisterAlias(display, canonical, offset_bits, bit_length)

            if item.get("is_program_counter"):
                program_counter_regs.add(canonical)
            if item.get("is_context_register"):
                context_registers.add(canonical)
            if item.get("is_zero"):
                zero_registers.add(canonical)
            if item.get("is_hidden"):
                hidden_registers.add(canonical)

            if (
                _looks_like_general_register(canonical, base.name)
                and not any(
                    item.get(flag)
                    for flag in ("is_program_counter", "is_context_register", "is_zero", "is_hidden")
                )
            ):
                general_registers.add(canonical)

        for item in architecture_metadata.get("register_aliases", []):
            offset = _parse_int(item.get("offset"))
            size_bytes = item.get("size_bytes")
            canonical_text = str(item.get("canonical") or item.get("display") or "")
            display_text = str(item.get("display") or canonical_text)
            if offset is None or size_bytes is None or not canonical_text:
                continue
            try:
                size_bytes = int(size_bytes)
                bit_length = int(item.get("bit_length") or size_bytes * 8)
                offset_bits = int(item.get("least_significant_bit") or 0)
            except (TypeError, ValueError):
                continue
            canonical = canonical_text.upper() if base.name.startswith("x86") else canonical_text
            display = display_text.upper() if base.name.startswith("x86") else display_text
            aliases[(offset, size_bytes)] = RegisterAlias(display, canonical, offset_bits, bit_length)
            if _looks_like_general_register(canonical, base.name):
                general_registers.add(canonical)

        address_spaces = {
            str(item.get("name")): dict(item)
            for item in (architecture_metadata.get("address_spaces") or program_metadata.get("address_spaces", []))
            if item.get("name")
        }

        return cls(
            name=base.name,
            pointer_size=int(architecture_metadata.get("default_pointer_size") or base.pointer_size),
            endian=str(architecture_metadata.get("endian") or base.endian),
            stack_pointer_regs=stack_pointer_regs,
            frame_pointer_regs=frame_pointer_regs,
            link_registers=link_registers,
            general_registers=general_registers,
            register_aliases=aliases,
            program_counter_regs=program_counter_regs,
            context_registers=context_registers,
            zero_registers=zero_registers,
            hidden_registers=hidden_registers,
            address_spaces=address_spaces,
        )

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

    def is_special_register(self, canonical: str) -> bool:
        return canonical in (
            set(self.stack_pointer_regs)
            | set(self.frame_pointer_regs)
            | set(self.link_registers)
            | set(self.program_counter_regs or set())
            | set(self.context_registers or set())
            | set(self.zero_registers or set())
            | set(self.hidden_registers or set())
        )

    def is_general_register(self, canonical: str) -> bool:
        return canonical in self.general_registers and not self.is_special_register(canonical)


def _parse_int(value) -> int | None:
    if value is None:
        return None
    text = str(value).replace("L", "")
    try:
        return int(text, 16)
    except ValueError:
        try:
            return int(text)
        except ValueError:
            return None


def _looks_like_general_register(canonical: str, arch_name: str) -> bool:
    text = canonical.upper() if arch_name.startswith("x86") else canonical
    if arch_name == "x86":
        return text in {"EAX", "ECX", "EDX", "EBX", "ESI", "EDI", "ESP", "EBP"}
    if arch_name == "x86_64":
        if text in {"RAX", "RCX", "RDX", "RBX", "RSI", "RDI", "RSP", "RBP"}:
            return True
        if text.startswith("R"):
            suffix = text[1:]
            return suffix.isdigit() and 8 <= int(suffix) <= 15
        return False
    if arch_name == "aarch64":
        if canonical in {"sp"}:
            return True
        if canonical.startswith("x") and canonical[1:].isdigit():
            return 0 <= int(canonical[1:]) <= 30
        return False
    if arch_name == "armv7":
        if canonical in {"sp", "lr", "pc"}:
            return True
        if canonical.startswith("r") and canonical[1:].isdigit():
            return 0 <= int(canonical[1:]) <= 15
        return False
    return False
