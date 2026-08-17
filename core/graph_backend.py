from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any, Protocol
from weakref import WeakKeyDictionary

import networkx as nx


SUPPORTED_GRAPH_BACKENDS = ("networkx", "rustworkx")


class DirectedTraversal(Protocol):
    def node_attributes(self, node: Any) -> dict:
        ...

    def predecessor_edges(self, node: Any) -> list[tuple[Any, dict]]:
        ...


@dataclass
class NetworkXTraversal:
    graph: nx.DiGraph

    def node_attributes(self, node: Any) -> dict:
        return self.graph.nodes[node]

    def predecessor_edges(self, node: Any) -> list[tuple[Any, dict]]:
        return [
            (pred, self.graph.edges[pred, node])
            for pred in self.graph.predecessors(node)
        ]


class RustworkxTraversal:
    def __init__(self, graph: nx.DiGraph):
        try:
            import rustworkx as rx
        except ImportError as exc:
            raise RuntimeError(
                "rustworkx graph backend requested but rustworkx is not installed"
            ) from exc

        self.source_graph = graph
        self.graph = rx.PyDiGraph(multigraph=False)
        self.node_to_index: dict[Any, int] = {}
        self.index_to_node: dict[int, Any] = {}
        for node in graph.nodes:
            index = self.graph.add_node(node)
            self.node_to_index[node] = index
            self.index_to_node[index] = node
        for source, target, attrs in graph.edges(data=True):
            self.graph.add_edge(
                self.node_to_index[source],
                self.node_to_index[target],
                dict(attrs),
            )

    def node_attributes(self, node: Any) -> dict:
        return self.source_graph.nodes[node]

    def predecessor_edges(self, node: Any) -> list[tuple[Any, dict]]:
        target_index = self.node_to_index[node]
        rows = [
            (self.index_to_node[source_index], attrs)
            for source_index, _, attrs in self.graph.in_edges(target_index)
        ]
        rows.sort(key=lambda item: str(item[0]))
        return rows


_RUSTWORKX_CACHE: WeakKeyDictionary = WeakKeyDictionary()
_RUSTWORKX_CACHE_LOCK = RLock()


def traversal_for(graph: nx.DiGraph, backend: str) -> DirectedTraversal:
    normalized = normalize_graph_backend(backend)
    if normalized == "networkx":
        return NetworkXTraversal(graph)
    signature = (graph.number_of_nodes(), graph.number_of_edges())
    with _RUSTWORKX_CACHE_LOCK:
        cached = _RUSTWORKX_CACHE.get(graph)
        if cached is None or cached[0] != signature:
            cached = (signature, RustworkxTraversal(graph))
            _RUSTWORKX_CACHE[graph] = cached
        return cached[1]


def normalize_graph_backend(backend: str | None) -> str:
    normalized = str(backend or "networkx").strip().lower()
    if normalized not in SUPPORTED_GRAPH_BACKENDS:
        supported = ", ".join(SUPPORTED_GRAPH_BACKENDS)
        raise ValueError(f"unsupported graph backend {backend!r}; expected one of: {supported}")
    return normalized
