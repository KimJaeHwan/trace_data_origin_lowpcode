from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from frontend.external_prototype import ExternalParameter, ExternalPrototype


@dataclass(frozen=True)
class KnownExternalEffect:
    effect_id: str
    names: tuple[str, ...]
    libraries: tuple[str, ...]
    effect: str
    roles: dict[str, int | str] = field(default_factory=dict)
    trust: str = "trusted_external_name_only"
    source_file: str | None = None

    def matches(self, prototype: ExternalPrototype) -> bool:
        if not _matches_any_name(prototype, self.names):
            return False
        if not self.libraries:
            return True
        library = (prototype.library or "").lower()
        return any(fnmatch.fnmatch(library, pattern.lower()) for pattern in self.libraries)


@dataclass(frozen=True)
class ExternalRoleResolution:
    role: str
    binding: int | str
    parameter: ExternalParameter | None
    confidence: str


@dataclass(frozen=True)
class ResolvedExternalSummary:
    prototype: ExternalPrototype
    effect: KnownExternalEffect
    role_resolution: dict[str, ExternalRoleResolution]
    trust_level: str
    provenance: dict
    cache_key: str


class KnownExternalEffectRegistry:
    def __init__(self, effects: list[KnownExternalEffect]):
        self.effects = effects
        self.registry_hash = _stable_hash([effect_to_dict(effect) for effect in effects])

    @classmethod
    def load_default(cls, root: Path | None = None) -> "KnownExternalEffectRegistry":
        base = root or Path(__file__).resolve().parents[1] / "summaries" / "external"
        return cls.load_directory(base)

    @classmethod
    def load_directory(cls, directory: Path) -> "KnownExternalEffectRegistry":
        effects: list[KnownExternalEffect] = []
        if not directory.exists():
            return cls(effects)
        for path in sorted(directory.glob("*.json")):
            effects.extend(load_effect_file(path))
        return cls(effects)

    def match(self, prototype: ExternalPrototype) -> KnownExternalEffect | None:
        for effect in self.effects:
            if effect.matches(prototype):
                return effect
        return None


class ExternalSummaryResolver:
    def __init__(self, registry: KnownExternalEffectRegistry | None = None):
        self.registry = registry or KnownExternalEffectRegistry.load_default()

    def resolve(self, prototypes: dict[str, ExternalPrototype]) -> dict[str, ResolvedExternalSummary]:
        resolved: dict[str, ResolvedExternalSummary] = {}
        for entry, prototype in prototypes.items():
            effect = self.registry.match(prototype)
            if effect is None:
                continue
            summary = self._resolve_one(prototype, effect)
            resolved[entry] = summary
        return resolved

    def _resolve_one(self, prototype: ExternalPrototype, effect: KnownExternalEffect) -> ResolvedExternalSummary:
        roles: dict[str, ExternalRoleResolution] = {}
        all_roles_bound = True
        for role, binding in effect.roles.items():
            parameter = _bind_parameter(prototype, binding)
            if parameter is None and isinstance(binding, int):
                all_roles_bound = False
            roles[role] = ExternalRoleResolution(
                role=role,
                binding=binding,
                parameter=parameter,
                confidence="prototype_parameter_bound" if parameter is not None else "unbound",
            )
        trust_level = effect.trust if all_roles_bound else "trusted_external_name_only"
        provenance = {
            "provider": "external",
            "prototype_source": prototype.source,
            "effect_source": effect.source_file or "curated_registry",
            "matched_name": prototype.normalized_name,
            "library": prototype.library,
            "effect": effect.effect,
            "trust": trust_level,
            "registry_hash": self.registry.registry_hash,
            "prototype_hash": prototype.metadata_hash,
        }
        cache_key = _stable_hash({
            "prototype_id": prototype.prototype_id,
            "prototype_hash": prototype.metadata_hash,
            "effect": effect_to_dict(effect),
            "trust": trust_level,
            "registry_hash": self.registry.registry_hash,
        })
        return ResolvedExternalSummary(
            prototype=prototype,
            effect=effect,
            role_resolution=roles,
            trust_level=trust_level,
            provenance=provenance,
            cache_key=cache_key,
        )


def load_effect_file(path: Path) -> list[KnownExternalEffect]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    effects: list[KnownExternalEffect] = []
    for item in data.get("functions") or []:
        match = item.get("match") or {}
        names = tuple(str(name) for name in match.get("names") or [])
        libraries = tuple(str(library) for library in match.get("libraries") or [])
        effect_id = str(item.get("id") or _stable_hash({"path": str(path), "names": names, "effect": item.get("effect")}))
        effects.append(KnownExternalEffect(
            effect_id=effect_id,
            names=names,
            libraries=libraries,
            effect=str(item.get("effect") or ""),
            roles=dict(item.get("roles") or {}),
            trust=str(item.get("trust") or "trusted_external_name_only"),
            source_file=str(path),
        ))
    return effects


def effect_to_dict(effect: KnownExternalEffect) -> dict:
    return {
        "id": effect.effect_id,
        "names": list(effect.names),
        "libraries": list(effect.libraries),
        "effect": effect.effect,
        "roles": effect.roles,
        "trust": effect.trust,
        "source_file": effect.source_file,
    }


def _matches_any_name(prototype: ExternalPrototype, patterns: tuple[str, ...]) -> bool:
    names = tuple(name.lower() for name in prototype.canonical_names)
    for pattern in patterns:
        lowered = pattern.lower()
        if any(fnmatch.fnmatch(name, lowered) for name in names):
            return True
    return False


def _bind_parameter(prototype: ExternalPrototype, binding: int | str) -> ExternalParameter | None:
    if isinstance(binding, int):
        for parameter in prototype.parameters:
            if parameter.ordinal == binding:
                return parameter
        if 0 <= binding < len(prototype.parameters):
            return prototype.parameters[binding]
        return None
    lowered = str(binding).lower()
    for parameter in prototype.parameters:
        if parameter.name and parameter.name.lower() == lowered:
            return parameter
    return None


def _stable_hash(value) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
