import json
import random
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path

import networkx as nx
import numpy as np
import pandas as pd


def sample_days(value_range: tuple[int, int]) -> int:
    lo, hi = value_range
    if lo > hi:
        raise ValueError(f"Invalid range: {value_range}")
    return random.randint(lo, hi)


def parse_date(date_str: str) -> datetime.date:
    return datetime.strptime(date_str, "%Y-%m-%d").date()


def resolve_range(cfg: dict, key: str, node_id: str, default_key: str = "default") -> tuple[int, int]:
    values = cfg.get(key, {})
    if node_id in values:
        return tuple(values[node_id])
    if default_key in values:
        return tuple(values[default_key])
    raise KeyError(f"Missing range for '{key}' and node '{node_id}'")


def resolve_duration(node_id: str, node_type: str, durations_cfg: dict) -> tuple[int, int]:
    integration = durations_cfg["integration_assembly_duration_days"]
    staging = durations_cfg["material_input_staging_duration_days"]

    if node_type == "raw_material":
        if node_id in staging:
            return tuple(staging[node_id])
        return tuple(staging["RAW::default"])

    if node_id in integration:
        return tuple(integration[node_id])
    return tuple(integration["default"])


def resolve_buffer_range(node_id: str, node_type: str, buffers_cfg: dict) -> tuple[int, int]:
    if node_type == "component":
        return resolve_range(
            buffers_cfg, "component_integration_buffer_days", node_id, default_key="default"
        )
    if node_type in {"part", "raw_material"}:
        return resolve_range(
            buffers_cfg, "part_integration_buffer_days", node_id, default_key="default"
        )
    return resolve_range(
        buffers_cfg, "system_integration_buffer_days", node_id, default_key="default"
    )


def sample_duration_days(node_id: str, node_type: str, durations_cfg: dict) -> int:
    """Sample internal processing/integration time for a node.

    Rule: use node-type-aware config buckets with optional node-level override.
    """
    return sample_days(resolve_duration(node_id, node_type, durations_cfg))


def sample_buffer_days(
    *,
    node_id: str,
    node_type: str,
    duration_days: int,
    buffers_cfg: dict,
) -> int:
    """Sample slack/protection margin (buffer_days) for procurement timing.

    Rule: start from type-specific configured buffer range, apply a modest
    type-based reduction factor, then align with duration_days via ratio bounds
    so buffer is not arbitrarily disconnected from node processing duration.
    """
    base_lo, base_hi = resolve_buffer_range(node_id, node_type, buffers_cfg)
    reduction_factors = {
        "system": 0.60,
        "component": 0.55,
        "part": 0.50,
        "raw_material": 0.45,
    }
    factor = reduction_factors.get(node_type, 0.50)
    base_lo = max(0, int(round(base_lo * factor)))
    base_hi = max(base_lo, int(round(base_hi * factor)))

    ratio_bounds = {
        "system": (0.5, 1.5),
        "component": (0.4, 1.2),
        "part": (0.25, 1.0),
        "raw_material": (0.25, 1.0),
    }
    ratio_lo, ratio_hi = ratio_bounds.get(node_type, (0.3, 1.0))
    rel_lo = int(round(duration_days * ratio_lo))
    rel_hi = int(round(duration_days * ratio_hi))

    lo = max(base_lo, rel_lo)
    hi = min(base_hi, rel_hi)
    if lo <= hi:
        return sample_days((lo, hi))

    # Fallback when configured range and ratio band do not overlap.
    sampled = sample_days((base_lo, base_hi))
    return max(min(sampled, rel_hi), rel_lo)


def build_physical_graph(nodes_df: pd.DataFrame, edges_df: pd.DataFrame) -> nx.DiGraph:
    allowed_types = {"system", "component", "part", "raw_material"}
    physical_nodes_df = nodes_df[nodes_df["node_type"].isin(allowed_types)].copy()
    physical_ids = set(physical_nodes_df["node_id"])
    physical_edges_df = edges_df[
        edges_df["src"].isin(physical_ids) & edges_df["dst"].isin(physical_ids)
    ].copy()

    G = nx.DiGraph()
    for row in physical_nodes_df.to_dict("records"):
        node_id = row.pop("node_id")
        G.add_node(node_id, **row)
    for row in physical_edges_df.to_dict("records"):
        src = row.pop("src")
        dst = row.pop("dst")
        G.add_edge(src, dst, **row)
    return G


def build_schedule_tree(physical_graph: nx.DiGraph) -> nx.DiGraph:
    # Tree is oriented parent->child as: system -> component -> part -> raw_material
    tree = nx.DiGraph()
    for node_id, data in physical_graph.nodes(data=True):
        tree.add_node(node_id, **data)

    for src, dst, data in physical_graph.edges(data=True):
        edge_type = data.get("edge_type")
        if edge_type in {"material_input", "assembly_dependency"}:
            parent, child = dst, src
        elif edge_type == "integrates":
            parent, child = src, dst
        else:
            continue
        tree.add_edge(parent, child, **data)

    roots = [n for n, d in tree.in_degree() if d == 0]
    if len(roots) != 1:
        raise ValueError(f"Expected one tree root, found {len(roots)}: {roots}")

    root = roots[0]
    if tree.nodes[root].get("node_type") != "system":
        raise ValueError(f"Root must be system node, found {root} ({tree.nodes[root].get('node_type')})")

    # Ensure connectivity from root.
    seen = set([root])
    q = deque([root])
    while q:
        node = q.popleft()
        for child in tree.successors(node):
            if child in seen:
                continue
            seen.add(child)
            q.append(child)
    if len(seen) != tree.number_of_nodes():
        missing = sorted(set(tree.nodes()) - seen)
        raise ValueError(f"Schedule tree disconnected from system root; missing nodes: {missing}")
    return tree


def _json_compatible(value):
    if value is None:
        return None
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, float) and np.isnan(value):
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def write_schedule_tree_dump(schedule_tree: nx.DiGraph, output_path: Path) -> None:
    tree_dump = {
        "node_count": schedule_tree.number_of_nodes(),
        "edge_count": schedule_tree.number_of_edges(),
        "nodes": [
            {
                "id": str(node_id),
                "data": {k: _json_compatible(v) for k, v in data.items()},
            }
            for node_id, data in schedule_tree.nodes(data=True)
        ],
        "edges": [
            {
                "src": str(src),
                "dst": str(dst),
                "data": {k: _json_compatible(v) for k, v in data.items()},
            }
            for src, dst, data in schedule_tree.edges(data=True)
        ],
    }
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(tree_dump, f, indent=2)
    print(f"Saved schedule tree dump to {output_path.resolve()}")


def build_selected_lead_times(edges_df: pd.DataFrame) -> dict[str, int]:
    selected = edges_df[edges_df["edge_type"] == "supply_selected"][["dst", "lead_time_days"]].copy()
    selected = selected.dropna(subset=["dst", "lead_time_days"])
    
    # One selected supplier per physical node is expected; keep the first in case of duplicates.
    selected = selected.drop_duplicates(subset=["dst"], keep="first")
    return {
        str(row["dst"]): int(round(float(row["lead_time_days"])))
        for _, row in selected.iterrows()
    }


def load_generator_inputs(
    nodes_path: Path, edges_path: Path, config_path: Path
) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    nodes_df = pd.read_csv(nodes_path)
    edges_df = pd.read_csv(edges_path)
    with config_path.open("r", encoding="utf-8") as f:
        config = json.load(f)
    return nodes_df, edges_df, config


def generate_schedule(
    tree: nx.DiGraph,
    config: dict,
    selected_lead_times: dict[str, int],
    seed: int = 42,
) -> dict[str, dict]:
    """Generate baseline schedule fields.

    - duration_days: node internal processing/integration time.
    - lead_time_days: supplier lead time from selected supplier edge.
    - buffer_days: slack/protection margin before parent integration start.
    """
    random.seed(seed)
    ddl_date = parse_date(config["ddl_date"])
    buffers = config["buffers"]
    durations = config["durations"]

    root = [n for n, d in tree.in_degree() if d == 0][0]

    records: dict[str, dict] = {}
    root_type = tree.nodes[root]["node_type"]
    root_duration = sample_duration_days(root, root_type, durations)
    root_integration_start = ddl_date - timedelta(days=root_duration)
    records[root] = {
        "node_id": root,
        "node_type": root_type,
        "need_by_date": ddl_date,
        "integration_start": root_integration_start,
        "procurement_start_date": None,
        "duration_days": root_duration,
        "sampled_buffer_days": None,
        "used_lead_time_days": None,
        "sampled_integration_duration_days": root_duration,
        "layer_id": 0,
    }

    q = deque([root])
    while q:
        parent = q.popleft()
        parent_rec = records[parent]
        parent_integration_start = parent_rec["integration_start"]
        if parent_integration_start is None:
            raise ValueError(f"Missing integration_start for parent node '{parent}'")

        for child in sorted(tree.successors(parent)):
            child_type = tree.nodes[child]["node_type"]

            need_by = parent_integration_start
            duration_days = sample_duration_days(child, child_type, durations)
            buffer_days = sample_buffer_days(
                node_id=child,
                node_type=child_type,
                duration_days=duration_days,
                buffers_cfg=buffers,
            )
            integration_start = need_by - timedelta(days=duration_days)
            lead_time_days = selected_lead_times.get(child)
            if lead_time_days is None:
                raise KeyError(
                    f"Missing selected supplier lead_time_days for node '{child}'"
                )
            procurement_start = need_by - timedelta(days=lead_time_days + buffer_days)
            layer_id = parent_rec["layer_id"] + 1

            records[child] = {
                "node_id": child,
                "node_type": child_type,
                "need_by_date": need_by,
                "integration_start": integration_start,
                "procurement_start_date": procurement_start,
                "duration_days": duration_days,
                "sampled_buffer_days": buffer_days,
                "used_lead_time_days": lead_time_days,
                "sampled_integration_duration_days": duration_days,
                "layer_id": layer_id,
            }
            q.append(child)

    return records


def generate_baseline_data(
    nodes_df: pd.DataFrame,
    edges_df: pd.DataFrame,
    config: dict,
    seed: int = 42,
) -> tuple[nx.DiGraph, nx.DiGraph, dict[str, dict]]:
    physical_graph = build_physical_graph(nodes_df, edges_df)
    schedule_tree = build_schedule_tree(physical_graph)
    dump_path = Path(__file__).resolve().parent / "schedule_tree_dump.json"
    write_schedule_tree_dump(schedule_tree, dump_path)
    selected_lead_times = build_selected_lead_times(edges_df)
    schedule = generate_schedule(schedule_tree, config, selected_lead_times, seed=seed)
    return physical_graph, schedule_tree, schedule


def build_schedule_output_table(schedule: dict[str, dict]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "node_id": rec["node_id"],
                "node_type": rec["node_type"],
                "layer_id": rec["layer_id"],
                "need_by_date": rec["need_by_date"].isoformat(),
                "integration_start": rec["integration_start"].isoformat()
                if rec["integration_start"] is not None
                else "",
                "procurement_start_date": rec["procurement_start_date"].isoformat()
                if rec["procurement_start_date"] is not None
                else "",
                "duration_days": rec["duration_days"],
                "sampled_buffer_days": rec["sampled_buffer_days"]
                if rec["sampled_buffer_days"] is not None
                else np.nan,
                "sampled_integration_duration_days": rec["sampled_integration_duration_days"],
                "used_lead_time_days": rec["used_lead_time_days"]
                if rec["used_lead_time_days"] is not None
                else np.nan,
            }
            for rec in sorted(schedule.values(), key=lambda x: (x["layer_id"], x["node_id"]))
        ]
    )


def write_vis_html(
    *,
    tree: nx.DiGraph,
    schedule: dict[str, dict],
    output_path: Path,
    title: str,
) -> None:
    color_map = {
        "system": "#1D4ED8",
        "component": "#264653",
        "part": "#2A9D8F",
        "raw_material": "#E76F51",
    }

    nodes = []
    for node_id, data in tree.nodes(data=True):
        rec = schedule[node_id]
        node_type = data.get("node_type", "unknown")
        need_by = rec["need_by_date"].isoformat()
        proc_start = (
            rec["procurement_start_date"].isoformat()
            if rec["procurement_start_date"] is not None
            else "-"
        )
        integration_start = (
            rec["integration_start"].isoformat() if rec["integration_start"] is not None else "-"
        )
        label = f"{data.get('name', node_id)}\\nneed_by: {need_by}\\nproc_start: {proc_start}"
        if node_type == "system":
            label += f"\\nintegration_start: {integration_start}"

        nodes.append(
            {
                "id": node_id,
                "label": label,
                "level": rec["layer_id"],
                "color": color_map.get(node_type, "#6B7280"),
                "size": 18 if node_type == "system" else 13,
                "title": (
                    f"<b>{data.get('name', node_id)}</b><br>"
                    f"type: {node_type}<br>"
                    f"need_by_date: {need_by}<br>"
                    f"procurement_start_date: {proc_start}<br>"
                    f"integration_start: {integration_start}<br>"
                    f"duration_days: {rec['duration_days']}"
                ),
            }
        )

    edges = []
    for src, dst, data in tree.edges(data=True):
        edges.append(
            {
                "from": src,
                "to": dst,
                "label": str(data.get("edge_type", "")),
                "color": "#6B7280",
                "width": 1.6,
            }
        )

    legend_html = (
        '<span class="legend-item"><span class="dot" style="background:#1D4ED8"></span>System</span>'
        '<span class="legend-item"><span class="dot" style="background:#264653"></span>Component</span>'
        '<span class="legend-item"><span class="dot" style="background:#2A9D8F"></span>Part</span>'
        '<span class="legend-item"><span class="dot" style="background:#E76F51"></span>Raw material</span>'
        '<span class="legend-item">Node labels show need-by/procurement start dates.</span>'
    )

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <script src="https://unpkg.com/vis-network@9.1.9/dist/vis-network.min.js"></script>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: #f8f9fa; color: #1f2937; }}
    .wrap {{ padding: 16px; }}
    h1 {{ margin: 0 0 8px; font-size: 20px; }}
    .legend {{ display: flex; flex-wrap: wrap; gap: 8px 14px; margin-bottom: 10px; font-size: 12px; }}
    .legend-item {{ display: inline-flex; align-items: center; gap: 6px; }}
    .dot {{ width: 10px; height: 10px; border-radius: 999px; display: inline-block; }}
    #graph {{ width: 100%; height: 82vh; border: 1px solid #d1d5db; border-radius: 10px; background: white; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>{title}</h1>
    <div class="legend">{legend_html}</div>
    <div id="graph"></div>
  </div>
  <script>
    const nodes = new vis.DataSet({json.dumps(nodes)});
    const edges = new vis.DataSet({json.dumps(edges)});
    const network = new vis.Network(
      document.getElementById("graph"),
      {{ nodes, edges }},
      {{
        interaction: {{ hover: true, navigationButtons: true, keyboard: true }},
        physics: {{ enabled: false }},
        layout: {{
          improvedLayout: true,
          hierarchical: {{
            enabled: true,
            direction: "LR",
            sortMethod: "directed",
            nodeSpacing: 220,
            levelSeparation: 260
          }}
        }},
        nodes: {{
          shape: "dot",
          borderWidth: 1.2,
          font: {{ size: 12, color: "#111827", strokeWidth: 3, strokeColor: "#ffffff" }}
        }},
        edges: {{
          arrows: {{ to: {{ enabled: true, scaleFactor: 0.6 }} }},
          smooth: {{ enabled: true, type: "cubicBezier" }},
          color: {{ opacity: 0.75 }}
        }}
      }}
    );
  </script>
</body>
</html>
"""
    output_path.write_text(html, encoding="utf-8")


def trace_path_to_root(tree: nx.DiGraph, node_id: str) -> list[str]:
    if node_id not in tree:
        raise KeyError(f"Node '{node_id}' not found in schedule tree")

    path = [node_id]
    current = node_id
    while True:
        parents = list(tree.predecessors(current))
        if not parents:
            break
        if len(parents) != 1:
            raise ValueError(f"Expected exactly one parent for node '{current}', found {parents}")
        parent = parents[0]
        path.append(parent)
        current = parent
    return path


def simulate_disruption_to_root(
    *,
    tree: nx.DiGraph,
    schedule: dict[str, dict],
    disrupted_node_id: str,
    delay_days: int,
) -> pd.DataFrame:
    """Propagate an injected external disruption delay along node->root path.

    disruption delay: external injected lateness, separate from baseline
    duration/lead-time/buffer parameters.
    """
    if delay_days < 0:
        raise ValueError(f"delay_days must be non-negative, got {delay_days}")

    path = trace_path_to_root(tree, disrupted_node_id)
    simulated_finish: dict[str, datetime.date] = {}
    simulated_start: dict[str, datetime.date | None] = {}
    rows: list[dict] = []

    for idx, node_id in enumerate(path):
        rec = schedule[node_id]
        baseline_finish = rec["need_by_date"]
        baseline_start = rec["integration_start"]
        node_buffer_days = int(rec.get("sampled_buffer_days") or 0)

        if idx == 0:
            incoming_delay_days = delay_days
        else:
            child_id = path[idx - 1]
            parent_baseline_start = baseline_start
            if parent_baseline_start is None:
                raise ValueError(
                    f"Missing baseline integration_start for parent node '{node_id}'"
                )
            inherited_lateness = (
                simulated_finish[child_id] - parent_baseline_start
            ).days
            incoming_delay_days = max(0, inherited_lateness)

        absorbed_by_buffer_days = min(node_buffer_days, incoming_delay_days)
        finish_delay_days = max(0, incoming_delay_days - node_buffer_days)

        sim_finish = baseline_finish + timedelta(days=finish_delay_days)
        sim_start = (
            baseline_start + timedelta(days=finish_delay_days)
            if baseline_start is not None
            else None
        )
        simulated_finish[node_id] = sim_finish
        simulated_start[node_id] = sim_start

        parent_node_id = path[idx + 1] if idx + 1 < len(path) else ""
        mode_to_parent = ""
        edge_type_to_parent = ""
        if parent_node_id:
            edge_data = tree.get_edge_data(parent_node_id, node_id) or {}
            mode_to_parent = str(edge_data.get("mode", ""))
            edge_type_to_parent = str(edge_data.get("edge_type", ""))

        rows.append(
            {
                "path_step_from_disrupted": idx,
                "injected_disruption_node": disrupted_node_id,
                "injected_delay_days": delay_days,
                "node_id": node_id,
                "node_type": rec["node_type"],
                "parent_node_id": parent_node_id,
                "mode_to_parent": mode_to_parent,
                "edge_type_to_parent": edge_type_to_parent,
                "baseline_integration_start": baseline_start.isoformat()
                if baseline_start is not None
                else "",
                "simulated_integration_start": sim_start.isoformat()
                if sim_start is not None
                else "",
                "sampled_buffer_days": node_buffer_days,
                "incoming_delay_days": incoming_delay_days,
                "absorbed_by_buffer_days": absorbed_by_buffer_days,
                "residual_delay_after_buffer_days": finish_delay_days,
                "baseline_finish_date": baseline_finish.isoformat(),
                "simulated_finish_date": sim_finish.isoformat(),
                "finish_delay_days": finish_delay_days,
            }
        )

    return pd.DataFrame(rows)


def simulate_network_disruption(
    *,
    tree: nx.DiGraph,
    schedule: dict[str, dict],
    disrupted_node_id: str,
    delay_days: int,
) -> pd.DataFrame:
    """Propagate a single injected disruption through the full schedule tree.

    Rules:
    - One disrupted non-root node receives an external injected delay.
    - Parent timing depends on all children; parent start can shift by the
      latest delayed child relative to parent baseline start.
    - Each node applies its own buffer first and only propagates residual delay.
    """
    if delay_days < 0:
        raise ValueError(f"delay_days must be non-negative, got {delay_days}")
    if disrupted_node_id not in tree:
        raise KeyError(f"Node '{disrupted_node_id}' not found in schedule tree")

    root = [n for n, d in tree.in_degree() if d == 0][0]
    if disrupted_node_id == root:
        raise ValueError("Network disruption simulation expects a non-root disrupted node")

    simulated_finish: dict[str, datetime.date] = {}
    simulated_start: dict[str, datetime.date | None] = {}
    incoming_delay_by_node: dict[str, int] = {}
    absorbed_by_buffer_by_node: dict[str, int] = {}
    finish_delay_by_node: dict[str, int] = {}

    # Bottom-up traversal ensures child simulated_finish values are available
    # before computing parent delays.
    for node_id in reversed(list(nx.topological_sort(tree))):
        rec = schedule[node_id]
        baseline_start = rec["integration_start"]
        baseline_finish = rec["need_by_date"]
        node_buffer_days = int(rec.get("sampled_buffer_days") or 0)

        child_induced_delay = 0
        if baseline_start is not None:
            for child_id in tree.successors(node_id):
                child_lateness = (simulated_finish[child_id] - baseline_start).days
                child_induced_delay = max(child_induced_delay, max(0, child_lateness))

        injected_delay = delay_days if node_id == disrupted_node_id else 0
        incoming_delay_days = max(injected_delay, child_induced_delay)
        absorbed_by_buffer_days = min(node_buffer_days, incoming_delay_days)
        finish_delay_days = max(0, incoming_delay_days - node_buffer_days)

        sim_finish = baseline_finish + timedelta(days=finish_delay_days)
        sim_start = (
            baseline_start + timedelta(days=finish_delay_days)
            if baseline_start is not None
            else None
        )

        simulated_finish[node_id] = sim_finish
        simulated_start[node_id] = sim_start
        incoming_delay_by_node[node_id] = incoming_delay_days
        absorbed_by_buffer_by_node[node_id] = absorbed_by_buffer_days
        finish_delay_by_node[node_id] = finish_delay_days

    rows: list[dict] = []
    ordered_node_ids = sorted(tree.nodes(), key=lambda n: (schedule[n]["layer_id"], n))
    for node_id in ordered_node_ids:
        rec = schedule[node_id]
        baseline_start = rec["integration_start"]
        baseline_finish = rec["need_by_date"]
        sim_start = simulated_start[node_id]
        sim_finish = simulated_finish[node_id]
        start_delay_days = (
            (sim_start - baseline_start).days
            if baseline_start is not None and sim_start is not None
            else 0
        )
        finish_delay_days = (sim_finish - baseline_finish).days

        rows.append(
            {
                "node_id": node_id,
                "node_type": rec["node_type"],
                "layer_id": rec["layer_id"],
                "original_start_date": baseline_start.isoformat() if baseline_start is not None else "",
                "original_finish_date": baseline_finish.isoformat(),
                "simulated_start_date": sim_start.isoformat() if sim_start is not None else "",
                "simulated_finish_date": sim_finish.isoformat(),
                "start_delay_days": start_delay_days,
                "finish_delay_days": finish_delay_days,
                "incoming_delay_days": incoming_delay_by_node[node_id],
                "absorbed_by_buffer_days": absorbed_by_buffer_by_node[node_id],
                "sampled_buffer_days": int(rec.get("sampled_buffer_days") or 0),
                "impacted": bool(finish_delay_days > 0),
                "is_disrupted_node": bool(node_id == disrupted_node_id),
                "injected_delay_days": delay_days if node_id == disrupted_node_id else 0,
            }
        )

    return pd.DataFrame(rows)


def generate_node_sensitivity_summary(
    *,
    tree: nx.DiGraph,
    schedule: dict[str, dict],
    delay_scenarios: tuple[int, ...] = (1, 3, 7),
) -> pd.DataFrame:
    rows: list[dict] = []
    for node_id in sorted(tree.nodes()):
        for delay_days in delay_scenarios:
            sim_df = simulate_disruption_to_root(
                tree=tree,
                schedule=schedule,
                disrupted_node_id=node_id,
                delay_days=delay_days,
            )

            impacted_count = int((sim_df["finish_delay_days"] > 0).sum())
            impacted_path = " -> ".join(sim_df["node_id"].tolist())
            root_delay_days = int(sim_df.iloc[-1]["finish_delay_days"])

            rows.append(
                {
                    "disrupted_node_id": node_id,
                    "delay_days": delay_days,
                    "root_delay_days": root_delay_days,
                    "number_of_impacted_nodes": impacted_count,
                    "impacted_path": impacted_path,
                    "root_impacted": bool(root_delay_days > 0),
                }
            )

    return pd.DataFrame(rows)


def build_disruption_scenarios(
    config: dict,
    schedule_tree: nx.DiGraph,
) -> list[dict]:
    """Scenario definition layer.

    Current behavior: single disrupted node with fixed delay from config.
    Returned as list so future random/multi-node extensions can append more.
    """
    simulation_cfg = config.get("simulation", {})
    root = [n for n, d in schedule_tree.in_degree() if d == 0][0]
    non_root_nodes = sorted(n for n in schedule_tree.nodes() if n != root)
    default_disruption_node = sorted(
        n for n in schedule_tree.nodes() if schedule_tree.out_degree(n) == 0
    )[0]
    disrupted_node_id = simulation_cfg.get("disrupted_node_id")
    if disrupted_node_id is None and simulation_cfg.get("sample_disrupted_node_non_root", False):
        disrupted_node_id = random.choice(non_root_nodes)
    if disrupted_node_id is None:
        disrupted_node_id = default_disruption_node

    return [
        {
            "disrupted_node_id": disrupted_node_id,
            "delay_days": int(simulation_cfg.get("delay_days", 14)),
            "delay_days_range": simulation_cfg.get("delay_days_range"),
            "output_csv": simulation_cfg.get(
                "output_csv",
                "vessel_case_study_disruption_to_root_simulation.csv",
            ),
        }
    ]


def run_disruption_scenario(
    *,
    tree: nx.DiGraph,
    schedule: dict[str, dict],
    scenario: dict,
) -> pd.DataFrame:
    """Run one disruption scenario.

    Current default behavior is fixed injected delay_days.
    If delay_days_range is present, this is ready to sample a random delay.
    """
    delay_days = resolve_disruption_delay_days(scenario)
    return simulate_disruption_to_root(
        tree=tree,
        schedule=schedule,
        disrupted_node_id=scenario["disrupted_node_id"],
        delay_days=delay_days,
    )


def resolve_disruption_delay_days(scenario: dict) -> int:
    """Resolve external injected disruption delay in days.

    - fixed mode: use scenario["delay_days"] (current default behavior)
    - future-ready mode: sample uniformly from scenario["delay_days_range"]
    """
    if scenario.get("delay_days") is not None:
        return int(scenario["delay_days"])

    delay_range = scenario.get("delay_days_range")
    if delay_range is not None:
        lo, hi = int(delay_range[0]), int(delay_range[1])
        return sample_days((lo, hi))

    return 14


def write_schedule_output(schedule_df: pd.DataFrame, output_csv: Path) -> None:
    schedule_df.to_csv(output_csv, index=False)
    print(f"Saved schedule table to {output_csv.resolve()}")


def write_disruption_output(disruption_sim_df: pd.DataFrame, output_path: Path, scenario: dict) -> None:
    disruption_sim_df.to_csv(output_path, index=False)
    root_row = disruption_sim_df.iloc[-1]
    print(
        f"Saved disruption simulation to {output_path.resolve()} "
        f"(disrupted_node={scenario['disrupted_node_id']}, delay_days={scenario['delay_days']}, "
        f"root_simulated_finish={root_row['simulated_finish_date']})"
    )


def write_network_disruption_output(
    network_disruption_df: pd.DataFrame,
    output_path: Path,
    scenario: dict,
) -> None:
    network_disruption_df.to_csv(output_path, index=False)
    impacted_nodes = int(network_disruption_df["impacted"].sum())
    root_row = network_disruption_df[network_disruption_df["layer_id"] == 0].iloc[0]
    print(
        f"Saved network disruption simulation to {output_path.resolve()} "
        f"(disrupted_node={scenario['disrupted_node_id']}, delay_days={scenario['delay_days']}, "
        f"root_finish_delay_days={int(root_row['finish_delay_days'])}, impacted_nodes={impacted_nodes})"
    )


def build_network_disruption_analysis_report(
    *,
    network_disruption_df: pd.DataFrame,
    tree: nx.DiGraph,
    scenario: dict,
) -> str:
    disrupted_node_id = scenario["disrupted_node_id"]
    injected_delay_days = int(scenario["delay_days"])
    total_nodes = int(len(network_disruption_df))
    total_impacted_nodes = int(network_disruption_df["impacted"].sum())
    root_row = network_disruption_df[network_disruption_df["layer_id"] == 0].iloc[0]
    root_impacted = bool(root_row["finish_delay_days"] > 0)
    root_delay_days = int(root_row["finish_delay_days"])

    by_node = network_disruption_df.set_index("node_id")
    disrupted_row = by_node.loc[disrupted_node_id]
    disrupted_absorbed = int(disrupted_row["absorbed_by_buffer_days"])
    disrupted_residual = int(disrupted_row["finish_delay_days"])

    path_to_root = trace_path_to_root(tree, disrupted_node_id)
    upstream_absorber = None
    for node_id in path_to_root[1:]:
        row = by_node.loc[node_id]
        incoming = int(row["incoming_delay_days"])
        absorbed = int(row["absorbed_by_buffer_days"])
        finish_delay = int(row["finish_delay_days"])
        if incoming > 0 and absorbed > 0 and finish_delay == 0:
            upstream_absorber = node_id
            break

    if root_impacted:
        reached_text = (
            "Yes. Delay reached root along path: "
            + " -> ".join(path_to_root)
            + f". Root finish delay = {root_delay_days} days."
        )
    else:
        reached_text = "No. Delay was fully absorbed before reaching root."

    top5 = (
        network_disruption_df.sort_values(
            by=["finish_delay_days", "absorbed_by_buffer_days", "node_id"],
            ascending=[False, False, True],
        )
        .head(5)
        .loc[:, ["node_id", "node_type", "finish_delay_days", "absorbed_by_buffer_days"]]
    )

    if disrupted_residual == 0:
        bottleneck_text = f"Disruption was stopped at disrupted node `{disrupted_node_id}`."
    elif upstream_absorber is not None:
        bottleneck_text = f"Main stopping point was upstream node `{upstream_absorber}`."
    elif root_impacted:
        bottleneck_text = "No upstream stop point existed before root; bottleneck propagated to root."
    else:
        bottleneck_text = "Delay faded through network timing gaps before root without a single clear stop node."

    interpretation = (
        f"A {injected_delay_days}-day external delay was injected at `{disrupted_node_id}`. "
        f"{total_impacted_nodes} of {total_nodes} nodes saw positive finish delay. "
        f"The disrupted node absorbed {disrupted_absorbed} days via its local buffer."
    )
    if root_impacted:
        interpretation += f" Remaining delay propagated to the root (delay={root_delay_days} days). "
    else:
        interpretation += " Remaining delay was contained before the root. "
    interpretation += bottleneck_text

    report_lines = [
        "# Vessel Case Study Analysis Report",
        "",
        "## 1. Scenario",
        f"- disrupted_node_id: `{disrupted_node_id}`",
        f"- injected_delay_days: `{injected_delay_days}`",
        f"- total nodes: `{total_nodes}`",
        f"- total impacted nodes: `{total_impacted_nodes}`",
        f"- root impacted: `{root_impacted}`",
        f"- root delay days: `{root_delay_days}`",
        "",
        "## 2. Delay Absorption and Propagation",
        f"- disrupted node absorbed delay: `{disrupted_absorbed}` days",
        f"- disrupted node residual delay after buffer: `{disrupted_residual}` days",
        "- upstream absorber of remaining delay: "
        + (f"`{upstream_absorber}`" if upstream_absorber is not None else "`None identified`"),
        f"- stopped before root: `{not root_impacted}`",
        f"- reached root details: {reached_text}",
        "",
        "## 3. Most Affected Nodes",
        "| node_id | node_type | finish_delay_days | absorbed_by_buffer_days |",
        "|---|---|---:|---:|",
    ]
    for row in top5.to_dict("records"):
        report_lines.append(
            f"| {row['node_id']} | {row['node_type']} | {int(row['finish_delay_days'])} | {int(row['absorbed_by_buffer_days'])} |"
        )

    report_lines.extend(
        [
            "",
            "## 4. Interpretation",
            interpretation,
            "",
        ]
    )
    return "\n".join(report_lines)


def write_network_disruption_analysis_report(
    *,
    network_disruption_df: pd.DataFrame,
    tree: nx.DiGraph,
    scenario: dict,
    output_path: Path,
) -> None:
    report_md = build_network_disruption_analysis_report(
        network_disruption_df=network_disruption_df,
        tree=tree,
        scenario=scenario,
    )
    output_path.write_text(report_md, encoding="utf-8")
    print(f"Saved deterministic analysis report to {output_path.resolve()}")


def run_network_disruption_monte_carlo(
    *,
    tree: nx.DiGraph,
    schedule: dict[str, dict],
    num_runs: int = 500,
    delay_range: tuple[int, int] = (1, 14),
    seed: int = 42,
) -> pd.DataFrame:
    """Run random single-node disruption simulations using network propagation."""
    if num_runs <= 0:
        raise ValueError(f"num_runs must be positive, got {num_runs}")

    rng = random.Random(seed)
    root = [n for n, d in tree.in_degree() if d == 0][0]
    candidate_nodes = sorted(n for n in tree.nodes() if n != root)
    if not candidate_nodes:
        raise ValueError("No non-root nodes available for Monte Carlo disruption sampling")

    rows: list[dict] = []
    for run_id in range(1, num_runs + 1):
        disrupted_node_id = rng.choice(candidate_nodes)
        injected_delay_days = rng.randint(int(delay_range[0]), int(delay_range[1]))
        sim_df = simulate_network_disruption(
            tree=tree,
            schedule=schedule,
            disrupted_node_id=disrupted_node_id,
            delay_days=injected_delay_days,
        )
        root_row = sim_df[sim_df["layer_id"] == 0].iloc[0]
        root_delay_days = int(root_row["finish_delay_days"])
        number_of_impacted_nodes = int(sim_df["impacted"].sum())
        rows.append(
            {
                "run_id": run_id,
                "disrupted_node_id": disrupted_node_id,
                "injected_delay_days": injected_delay_days,
                "root_delay_days": root_delay_days,
                "number_of_impacted_nodes": number_of_impacted_nodes,
                "root_impacted": bool(root_delay_days > 0),
            }
        )
    return pd.DataFrame(rows)


def build_mc_summary(mc_results_df: pd.DataFrame) -> pd.DataFrame:
    root_delays = mc_results_df["root_delay_days"]
    summary = {
        "total_runs": int(len(mc_results_df)),
        "probability_root_impacted": float(mc_results_df["root_impacted"].mean()),
        "mean_root_delay": float(root_delays.mean()),
        "median_root_delay": float(root_delays.median()),
        "p90_root_delay": float(root_delays.quantile(0.90)),
        "max_root_delay": int(root_delays.max()),
        "mean_impacted_nodes": float(mc_results_df["number_of_impacted_nodes"].mean()),
    }
    return pd.DataFrame([summary])


def build_mc_node_ranking(mc_results_df: pd.DataFrame) -> pd.DataFrame:
    ranking = (
        mc_results_df.groupby("disrupted_node_id", as_index=False)
        .agg(
            times_sampled=("run_id", "count"),
            mean_root_delay=("root_delay_days", "mean"),
            probability_root_impacted=("root_impacted", "mean"),
            mean_impacted_nodes=("number_of_impacted_nodes", "mean"),
        )
        .sort_values(
            by=["mean_root_delay", "probability_root_impacted", "times_sampled", "disrupted_node_id"],
            ascending=[False, False, False, True],
        )
    )
    ranking["risk_bucket"] = ranking["probability_root_impacted"].apply(classify_risk_bucket)
    return ranking


def classify_risk_bucket(probability_root_impacted: float) -> str:
    if probability_root_impacted >= 0.4:
        return "High"
    if probability_root_impacted >= 0.15:
        return "Medium"
    return "Low"


def build_mc_type_summary(
    mc_node_ranking_df: pd.DataFrame,
    schedule: dict[str, dict],
) -> pd.DataFrame:
    rows = []
    for row in mc_node_ranking_df.to_dict("records"):
        node_id = row["disrupted_node_id"]
        rec = schedule[node_id]
        rows.append(
            {
                "node_id": node_id,
                "node_type": rec["node_type"],
                "layer_id": int(rec["layer_id"]),
                "probability_root_impacted": float(row["probability_root_impacted"]),
                "mean_root_delay": float(row["mean_root_delay"]),
                "mean_impacted_nodes": float(row["mean_impacted_nodes"]),
            }
        )

    per_node_df = pd.DataFrame(rows)
    return (
        per_node_df.groupby("node_type", as_index=False)
        .agg(
            count_nodes=("node_id", "count"),
            mean_probability_root_impacted=("probability_root_impacted", "mean"),
            mean_root_delay=("mean_root_delay", "mean"),
            mean_impacted_nodes=("mean_impacted_nodes", "mean"),
        )
        .sort_values(
            by=["mean_probability_root_impacted", "mean_root_delay", "node_type"],
            ascending=[False, False, True],
        )
    )


def build_mc_report(
    *,
    mc_summary_df: pd.DataFrame,
    mc_node_ranking_df: pd.DataFrame,
    mc_type_summary_df: pd.DataFrame,
    schedule: dict[str, dict],
    top_k: int = 5,
) -> str:
    s = mc_summary_df.iloc[0]
    top_nodes = mc_node_ranking_df.head(top_k).to_dict("records")
    high_nodes = mc_node_ranking_df[mc_node_ranking_df["risk_bucket"] == "High"]["disrupted_node_id"].tolist()
    medium_nodes = mc_node_ranking_df[mc_node_ranking_df["risk_bucket"] == "Medium"][
        "disrupted_node_id"
    ].tolist()
    low_nodes = mc_node_ranking_df[mc_node_ranking_df["risk_bucket"] == "Low"]["disrupted_node_id"].tolist()
    top_types = mc_type_summary_df.head(3).to_dict("records")

    layer_rows = []
    for row in mc_node_ranking_df.to_dict("records"):
        node_id = row["disrupted_node_id"]
        layer_rows.append(
            {
                "layer_id": int(schedule[node_id]["layer_id"]),
                "probability_root_impacted": float(row["probability_root_impacted"]),
            }
        )
    layer_df = pd.DataFrame(layer_rows)
    layer_summary = (
        layer_df.groupby("layer_id", as_index=False)["probability_root_impacted"].mean()
        .sort_values("layer_id")
    )
    top_layer = int(layer_summary.sort_values("probability_root_impacted", ascending=False).iloc[0]["layer_id"])
    bottom_layer = int(layer_summary["layer_id"].max())
    top_layer_risk = float(
        layer_summary[layer_summary["layer_id"] == top_layer]["probability_root_impacted"].iloc[0]
    )
    bottom_layer_risk = float(
        layer_summary[layer_summary["layer_id"] == bottom_layer]["probability_root_impacted"].iloc[0]
    )
    concentration_text = (
        f"Risk appears concentrated near higher-level nodes (layer {top_layer})"
        if top_layer < bottom_layer and top_layer_risk >= bottom_layer_risk
        else "Risk is not strongly concentrated at the top layer"
    )

    lines = [
        "# Vessel Case Study Monte Carlo Report",
        "",
        "## Overview",
        f"- Runs: `{int(s['total_runs'])}`",
        f"- Root impacted frequency: `{float(s['probability_root_impacted']):.2%}`",
        f"- Mean root delay (days): `{float(s['mean_root_delay']):.2f}`",
        f"- Median root delay (days): `{float(s['median_root_delay']):.2f}`",
        f"- P90 root delay (days): `{float(s['p90_root_delay']):.2f}`",
        f"- Max root delay (days): `{int(s['max_root_delay'])}`",
        f"- Mean impacted nodes: `{float(s['mean_impacted_nodes']):.2f}`",
        "",
        "## Most Risky Disrupted Nodes",
        "| disrupted_node_id | times_sampled | mean_root_delay | probability_root_impacted | mean_impacted_nodes |",
        "|---|---:|---:|---:|---:|",
    ]
    for row in top_nodes:
        lines.append(
            f"| {row['disrupted_node_id']} | {int(row['times_sampled'])} | "
            f"{float(row['mean_root_delay']):.2f} | {float(row['probability_root_impacted']):.2%} | "
            f"{float(row['mean_impacted_nodes']):.2f} |"
        )
    lines.extend(
        [
            "",
            "## Risk Buckets",
            f"- High: {', '.join(high_nodes) if high_nodes else 'None'}",
            f"- Medium: {', '.join(medium_nodes) if medium_nodes else 'None'}",
            f"- Low: {', '.join(low_nodes) if low_nodes else 'None'}",
            "",
            "## Node Type Risk",
            "| node_type | count_nodes | mean_probability_root_impacted | mean_root_delay | mean_impacted_nodes |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for row in top_types:
        lines.append(
            f"| {row['node_type']} | {int(row['count_nodes'])} | "
            f"{float(row['mean_probability_root_impacted']):.2%} | {float(row['mean_root_delay']):.2f} | "
            f"{float(row['mean_impacted_nodes']):.2f} |"
        )
    lines.extend(
        [
            "",
            "## Layer Concentration",
            f"- {concentration_text}.",
            f"- Highest mean root-impact probability layer: `{top_layer}` ({top_layer_risk:.2%})",
            f"- Deepest layer probability: `{bottom_layer}` ({bottom_layer_risk:.2%})",
        ]
    )
    lines.append("")
    return "\n".join(lines)


def write_mc_outputs(
    *,
    mc_results_df: pd.DataFrame,
    mc_summary_df: pd.DataFrame,
    mc_node_ranking_df: pd.DataFrame,
    mc_type_summary_df: pd.DataFrame,
    results_path: Path,
    summary_path: Path,
    ranking_path: Path,
    type_summary_path: Path,
    report_path: Path,
    schedule: dict[str, dict],
) -> None:
    mc_results_df.to_csv(results_path, index=False)
    mc_summary_df.to_csv(summary_path, index=False)
    mc_node_ranking_df.to_csv(ranking_path, index=False)
    mc_type_summary_df.to_csv(type_summary_path, index=False)
    report_md = build_mc_report(
        mc_summary_df=mc_summary_df,
        mc_node_ranking_df=mc_node_ranking_df,
        mc_type_summary_df=mc_type_summary_df,
        schedule=schedule,
        top_k=5,
    )
    report_path.write_text(report_md, encoding="utf-8")
    print(f"Saved Monte Carlo results to {results_path.resolve()}")
    print(f"Saved Monte Carlo summary to {summary_path.resolve()}")
    print(f"Saved Monte Carlo node ranking to {ranking_path.resolve()}")
    print(f"Saved Monte Carlo node type summary to {type_summary_path.resolve()}")
    print(f"Saved Monte Carlo report to {report_path.resolve()}")


def write_node_sensitivity_output(tree: nx.DiGraph, schedule: dict[str, dict], output_path: Path) -> None:
    sensitivity_df = generate_node_sensitivity_summary(
        tree=tree,
        schedule=schedule,
        delay_scenarios=(1, 3, 7),
    )
    sensitivity_df.to_csv(output_path, index=False)
    print(f"Saved node sensitivity summary to {output_path.resolve()}")


def write_enriched_nodes_output(
    nodes_df: pd.DataFrame, schedule_df: pd.DataFrame, output_path: Path
) -> None:
    nodes_out_df = nodes_df.copy()
    idx = nodes_out_df["node_id"].isin(schedule_df["node_id"])
    by_id = schedule_df.set_index("node_id")
    nodes_out_df.loc[idx, "need_by_date"] = nodes_out_df.loc[idx, "node_id"].map(by_id["need_by_date"])
    nodes_out_df.loc[idx, "procurement_start_date"] = nodes_out_df.loc[idx, "node_id"].map(
        by_id["procurement_start_date"]
    )
    nodes_out_df.loc[idx, "integration_start"] = nodes_out_df.loc[idx, "node_id"].map(
        by_id["integration_start"]
    )
    nodes_out_df.loc[idx, "sampled_buffer_days"] = pd.to_numeric(
        nodes_out_df.loc[idx, "node_id"].map(by_id["sampled_buffer_days"]),
        errors="coerce",
    )
    nodes_out_df.loc[idx, "sampled_integration_duration_days"] = nodes_out_df.loc[idx, "node_id"].map(
        by_id["sampled_integration_duration_days"]
    )
    nodes_out_df.loc[idx, "used_lead_time_days"] = pd.to_numeric(
        nodes_out_df.loc[idx, "node_id"].map(by_id["used_lead_time_days"]),
        errors="coerce",
    )
    nodes_out_df.to_csv(output_path, index=False)
    print(f"Saved enriched nodes to {output_path.resolve()}")


def write_schedule_graph_output(
    schedule_tree: nx.DiGraph, schedule: dict[str, dict], output_path: Path
) -> None:
    write_vis_html(
        tree=schedule_tree,
        schedule=schedule,
        output_path=output_path,
        title="Vessel Physical Graph with Need-By and Procurement Start Dates",
    )
    print(f"Saved schedule graph to {output_path.resolve()}")


def main() -> None:
    nodes_path = Path("__vessel_nodes_realistic_case_study_with_dates.csv")
    edges_path = Path("__vessel_edges_case_study.csv")
    config_path = Path("config.json")
    schedule_output_csv = Path("vessel_case_study_schedule_dates.csv")
    sensitivity_output_csv = Path("vessel_case_study_node_sensitivity_summary.csv")
    enriched_nodes_output_csv = Path("__vessel_nodes_realistic_case_study_with_dates.csv")
    graph_output_html = Path("vessel_case_study_due_dates_graph.html")
    network_disruption_output_csv = Path("vessel_case_study_network_disruption_simulation.csv")
    analysis_report_md = Path("vessel_case_study_analysis_report.md")
    mc_results_csv = Path("vessel_case_study_mc_results.csv")
    mc_summary_csv = Path("vessel_case_study_mc_summary.csv")
    mc_node_ranking_csv = Path("vessel_case_study_mc_node_ranking.csv")
    mc_type_summary_csv = Path("vessel_case_study_mc_type_summary.csv")
    mc_report_md = Path("vessel_case_study_mc_report.md")

    nodes_df, edges_df, config = load_generator_inputs(nodes_path, edges_path, config_path)
    physical_graph, schedule_tree, schedule = generate_baseline_data(nodes_df, edges_df, config, seed=42)

    print(
        f"Built physical graph with {physical_graph.number_of_nodes()} nodes and "
        f"{physical_graph.number_of_edges()} edges"
    )

    print(
        f"Physical graph: {physical_graph.number_of_nodes()} nodes, "
        f"{physical_graph.number_of_edges()} edges"
    )
    print(
        f"Schedule tree: {schedule_tree.number_of_nodes()} nodes, "
        f"{schedule_tree.number_of_edges()} edges"
    )

    schedule_df = build_schedule_output_table(schedule)
    write_schedule_output(schedule_df, schedule_output_csv)

    disruption_scenarios = build_disruption_scenarios(config, schedule_tree)
    primary_scenario = disruption_scenarios[0]
    disruption_output = Path(primary_scenario["output_csv"])
    disruption_sim_df = run_disruption_scenario(
        tree=schedule_tree,
        schedule=schedule,
        scenario=primary_scenario,
    )
    write_disruption_output(disruption_sim_df, disruption_output, primary_scenario)
    network_disruption_df = simulate_network_disruption(
        tree=schedule_tree,
        schedule=schedule,
        disrupted_node_id=primary_scenario["disrupted_node_id"],
        delay_days=int(primary_scenario["delay_days"]),
    )
    write_network_disruption_output(
        network_disruption_df,
        network_disruption_output_csv,
        primary_scenario,
    )
    write_network_disruption_analysis_report(
        network_disruption_df=network_disruption_df,
        tree=schedule_tree,
        scenario=primary_scenario,
        output_path=analysis_report_md,
    )
    mc_cfg = config.get("monte_carlo", {})
    mc_runs = int(mc_cfg.get("num_runs", 500))
    mc_seed = int(mc_cfg.get("seed", 42))
    mc_delay_range_raw = mc_cfg.get("delay_days_range", [7, 45])
    mc_delay_range = (int(mc_delay_range_raw[0]), int(mc_delay_range_raw[1]))
    mc_results_df = run_network_disruption_monte_carlo(
        tree=schedule_tree,
        schedule=schedule,
        num_runs=mc_runs,
        delay_range=mc_delay_range,
        seed=mc_seed,
    )
    mc_summary_df = build_mc_summary(mc_results_df)
    mc_node_ranking_df = build_mc_node_ranking(mc_results_df)
    mc_type_summary_df = build_mc_type_summary(mc_node_ranking_df, schedule)
    write_mc_outputs(
        mc_results_df=mc_results_df,
        mc_summary_df=mc_summary_df,
        mc_node_ranking_df=mc_node_ranking_df,
        mc_type_summary_df=mc_type_summary_df,
        results_path=mc_results_csv,
        summary_path=mc_summary_csv,
        ranking_path=mc_node_ranking_csv,
        type_summary_path=mc_type_summary_csv,
        report_path=mc_report_md,
        schedule=schedule,
    )

    write_node_sensitivity_output(schedule_tree, schedule, sensitivity_output_csv)
    write_enriched_nodes_output(nodes_df, schedule_df, enriched_nodes_output_csv)
    write_schedule_graph_output(schedule_tree, schedule, graph_output_html)


if __name__ == "__main__":
    main()
