"""
Graph exporters.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

import networkx as nx
from pyvis.network import Network

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

logger = logging.getLogger(__name__)


class GraphExporter:
    """Exports a NetworkX DiGraph to Pyvis HTML and JSON."""

    def __init__(self, G: nx.DiGraph, target: str, output_dir: Path):
        self.G          = G
        self.target     = target
        self.output_dir = output_dir
        self._ts        = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


    def export_pyvis(self) -> Path:
        """Generate an interactive Pyvis HTML graph (mind-map style)."""
        net = Network(
            height=config.GRAPH_HEIGHT,
            width=config.GRAPH_WIDTH,
            directed=True,
            bgcolor="#0d1117",
            font_color="#e6edf3",
        )

        # Physics: repulsion layout for mind-map feel
        net.set_options("""
        {
          "physics": {
            "enabled": true,
            "solver": "forceAtlas2Based",
            "forceAtlas2Based": {
              "gravitationalConstant": -80,
              "centralGravity": 0.01,
              "springLength": 140,
              "springConstant": 0.06,
              "damping": 0.4,
              "avoidOverlap": 0.8
            },
            "stabilization": {
              "enabled": true,
              "iterations": 250,
              "updateInterval": 25
            }
          },
          "interaction": {
            "hover": true,
            "tooltipDelay": 150,
            "navigationButtons": true,
            "keyboard": true
          },
          "edges": {
            "smooth": {
              "type": "curvedCW",
              "roundness": 0.15
            },
            "arrows": {
              "to": { "enabled": true, "scaleFactor": 0.6 }
            },
            "color": { "inherit": "from", "opacity": 0.5 }
          }
        }
        """)

        # Add nodes
        for node_id, data in self.G.nodes(data=True):
            ntype  = data.get("node_type", "unknown")
            label  = data.get("label", node_id)
            color  = config.NODE_COLORS.get(ntype, config.NODE_COLORS["unknown"])
            size   = config.NODE_SIZES.get(ntype, 12)
            shape  = config.NODE_SHAPES.get(ntype, "ellipse")
            srcs   = data.get("sources", [])
            srcs_str = ", ".join(srcs) if isinstance(srcs, list) else str(srcs)

            # Build tooltip
            tooltip_lines = [
                f"<b>{label}</b>",
                f"Type: {ntype}",
                f"Sources: {srcs_str}",
            ]
            for k, v in data.items():
                if k not in ("label", "node_type", "sources", "source_count") and v:
                    tooltip_lines.append(f"{k}: {v}")
            tooltip = "<br>".join(tooltip_lines)

            # Root domain gets special styling
            if ntype == "domain":
                size  = 50
                color = "#FF6B6B"
                shape = "star"

            net.add_node(
                node_id,
                label=label if len(label) < 40 else label[:37] + "…",
                title=tooltip,
                color=color,
                size=size,
                shape=shape,
                font={"size": 11, "color": "#e6edf3"},
            )

        # Add edges
        edge_colors = {
            "HAS_SUBDOMAIN": "#4ECDC4",
            "RESOLVES_TO":   "#FFE66D",
            "HAS_URL":       "#A8E6CF",
            "BELONGS_TO":    "#A8E6CF",
            "HAS_EMAIL":     "#C3A6FF",
            "COVERS":        "#FF8B94",
        }

        for src, tgt, data in self.G.edges(data=True):
            relation = data.get("relation", "RELATED")
            color    = edge_colors.get(relation, "#555555")
            net.add_edge(src, tgt, title=relation, color=color, width=1.5)

        out_path = self.output_dir / "graph.html"
        net.save_graph(str(out_path))
        logger.info("[exporter] Pyvis graph saved: %s", out_path)
        return out_path


    def export_json(self) -> Path:
        """Export graph as D3.js-compatible JSON (nodes + links arrays)."""
        nodes_list = []
        for node_id, data in self.G.nodes(data=True):
            srcs = data.get("sources", [])
            nodes_list.append({
                "id":      node_id,
                "label":   data.get("label", node_id),
                "type":    data.get("node_type", "unknown"),
                "sources": srcs if isinstance(srcs, list) else [str(srcs)],
                "metadata": {
                    k: v for k, v in data.items()
                    if k not in ("label", "node_type", "sources", "source_count")
                },
            })

        links_list = []
        for src, tgt, data in self.G.edges(data=True):
            links_list.append({
                "source":   src,
                "target":   tgt,
                "relation": data.get("relation", "RELATED"),
            })

        export = {
            "meta": {
                "target":    self.target,
                "generated": self._ts,
                "node_count": len(nodes_list),
                "edge_count": len(links_list),
            },
            "nodes": nodes_list,
            "links": links_list,
        }

        out_path = self.output_dir / "graph.json"
        out_path.write_text(json.dumps(export, indent=2), encoding="utf-8")
        logger.info("[exporter] JSON graph saved: %s", out_path)
        return out_path
