from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from core.architecture import ArchitectureSpec
from core.value_id import ValueId


@dataclass
class FunctionGraph:
    function_name: str
    context_id: str
    architecture: ArchitectureSpec
    cfg: nx.DiGraph = field(default_factory=nx.DiGraph)
    slice_graph: nx.DiGraph = field(default_factory=nx.DiGraph)
    sink_index: dict[str, ValueId] = field(default_factory=dict)
    source_index: dict[str, ValueId] = field(default_factory=dict)
    call_pre_storage_index: dict[str, ValueId] = field(default_factory=dict)
    call_post_storage_index: dict[str, ValueId] = field(default_factory=dict)
    callsite_index: dict[str, ValueId] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


@dataclass
class ProgramSliceGraph:
    functions: dict[str, FunctionGraph] = field(default_factory=dict)
    callsites: dict[str, dict] = field(default_factory=dict)
    boundary_edges: list[dict] = field(default_factory=list)
    call_graph: nx.DiGraph = field(default_factory=nx.DiGraph)
    scc_map: dict[str, int] = field(default_factory=dict)
