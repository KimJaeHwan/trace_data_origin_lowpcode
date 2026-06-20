from __future__ import annotations

from dataclasses import dataclass, field

from core.edge import DATA_SLICE_EDGES
from core.graph import FunctionGraph
from core.value_id import ValueId


@dataclass
class SliceResult:
    target: ValueId
    mode: str = "data"
    visited: set[ValueId] = field(default_factory=set)
    edges: list[tuple[ValueId, ValueId, str]] = field(default_factory=list)
    source_labels: set[str] = field(default_factory=set)


class BackwardSliceQuery:
    def __init__(self, function_graph: FunctionGraph, edge_policy: set[str] | None = None, mode: str = "data"):
        self.function_graph = function_graph
        self.edge_policy = edge_policy or DATA_SLICE_EDGES
        self.mode = mode

    def run(self, target: ValueId) -> SliceResult:
        result = SliceResult(target=target, mode=self.mode)
        stack = [target]
        graph = self.function_graph.slice_graph
        while stack:
            node = stack.pop()
            if node in result.visited:
                continue
            result.visited.add(node)
            attrs = graph.nodes[node]
            if attrs.get("kind") == "source_boundary" and attrs.get("source_label"):
                result.source_labels.add(attrs["source_label"])
            for pred in graph.predecessors(node):
                edge_attrs = graph.edges[pred, node]
                kind = edge_attrs.get("kind")
                if kind not in self.edge_policy:
                    continue
                result.edges.append((pred, node, kind))
                stack.append(pred)
        return result
