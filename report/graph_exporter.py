from __future__ import annotations

import json
from pathlib import Path

import networkx as nx


class GraphExporter:
    def export_json(self, graph: nx.DiGraph, path: str | Path) -> None:
        output = {
            "nodes": [
                {"id": str(node), **self._json_attrs(attrs)}
                for node, attrs in graph.nodes(data=True)
            ],
            "edges": [
                {"source": str(source), "target": str(target), **self._json_attrs(attrs)}
                for source, target, attrs in graph.edges(data=True)
            ],
        }
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")

    def export_graphml(self, graph: nx.DiGraph, path: str | Path) -> None:
        nx.write_graphml(self._string_graph(graph), path)

    def export_dot(self, graph: nx.DiGraph, path: str | Path) -> None:
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        lines = ["digraph slice_graph {"]
        for node, attrs in graph.nodes(data=True):
            label = attrs.get("display") or str(node)
            lines.append(f'  "{str(node)}" [label="{self._escape(label)}"];')
        for source, target, attrs in graph.edges(data=True):
            label = attrs.get("kind") or ""
            lines.append(f'  "{str(source)}" -> "{str(target)}" [label="{self._escape(label)}"];')
        lines.append("}")
        out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _string_graph(self, graph: nx.DiGraph) -> nx.DiGraph:
        converted = nx.DiGraph()
        for node, attrs in graph.nodes(data=True):
            converted.add_node(str(node), **self._json_attrs(attrs))
        for source, target, attrs in graph.edges(data=True):
            converted.add_edge(str(source), str(target), **self._json_attrs(attrs))
        return converted

    def _json_attrs(self, attrs: dict) -> dict:
        clean = {}
        for key, value in attrs.items():
            if value is None:
                continue
            if isinstance(value, (str, int, float, bool)):
                clean[key] = value
            else:
                clean[key] = str(value)
        return clean

    def _escape(self, value: str) -> str:
        return str(value).replace("\\", "\\\\").replace('"', '\\"')
