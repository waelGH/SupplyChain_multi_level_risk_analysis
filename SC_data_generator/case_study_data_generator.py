import json
import random
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path

import networkx as nx
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


def build_selected_lead_times(edges_df: pd.DataFrame) -> dict[str, int]:
    selected = edges_df[edges_df["edge_type"] == "supply_selected"][["dst", "lead_time_days"]].copy()
    selected = selected.dropna(subset=["dst", "lead_time_days"])
    # One selected supplier per physical node is expected; keep the first in case of duplicates.
    selected = selected.drop_duplicates(subset=["dst"], keep="first")
    return {
        str(row["dst"]): int(round(float(row["lead_time_days"])))
        for _, row in selected.iterrows()
    }


def generate_schedule(
    tree: nx.DiGraph,
    config: dict,
    selected_lead_times: dict[str, int],
    seed: int = 42,
) -> dict[str, dict]:
    random.seed(seed)
    ddl_date = parse_date(config["ddl_date"])
    buffers = config["buffers"]
    durations = config["durations"]

    root = [n for n, d in tree.in_degree() if d == 0][0]

    records: dict[str, dict] = {}
    root_type = tree.nodes[root]["node_type"]
    root_duration = sample_days(resolve_duration(root, root_type, durations))
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

            if child_type == "component":
                buffer_days = sample_days(
                    resolve_range(
                        buffers, "component_integration_buffer_days", child, default_key="default"
                    )
                )
            elif child_type in {"part", "raw_material"}:
                buffer_days = sample_days(
                    resolve_range(
                        buffers, "part_integration_buffer_days", child, default_key="default"
                    )
                )
            else:
                buffer_days = sample_days(
                    resolve_range(
                        buffers, "system_integration_buffer_days", child, default_key="default"
                    )
                )

            need_by = parent_integration_start
            duration_days = sample_days(resolve_duration(child, child_type, durations))
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


def main() -> None:
    nodes_path = Path("__vessel_nodes_realistic_case_study.csv")
    edges_path = Path("__vessel_edges_case_study.csv")
    config_path = Path("config.json")

    nodes_df = pd.read_csv(nodes_path)
    edges_df = pd.read_csv(edges_path)
    with config_path.open("r", encoding="utf-8") as f:
        config = json.load(f)

    physical_graph = build_physical_graph(nodes_df, edges_df)
    print(f"Built physical graph with {physical_graph.number_of_nodes()} nodes and {physical_graph.number_of_edges()} edges")

    schedule_tree = build_schedule_tree(physical_graph)
    selected_lead_times = build_selected_lead_times(edges_df)
    schedule = generate_schedule(schedule_tree, config, selected_lead_times, seed=42)

    print(
        f"Physical graph: {physical_graph.number_of_nodes()} nodes, "
        f"{physical_graph.number_of_edges()} edges"
    )
    print(
        f"Schedule tree: {schedule_tree.number_of_nodes()} nodes, "
        f"{schedule_tree.number_of_edges()} edges"
    )

    schedule_df = pd.DataFrame(
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
                else "",
                "sampled_integration_duration_days": rec["sampled_integration_duration_days"],
                "used_lead_time_days": rec["used_lead_time_days"]
                if rec["used_lead_time_days"] is not None
                else "",
            }
            for rec in sorted(schedule.values(), key=lambda x: (x["layer_id"], x["node_id"]))
        ]
    )

    output_csv = Path("vessel_case_study_schedule_dates.csv")
    schedule_df.to_csv(output_csv, index=False)
    print(f"Saved schedule table to {output_csv.resolve()}")

    simulation_cfg = config.get("simulation", {})
    default_disruption_node = sorted(
        n for n in schedule_tree.nodes() if schedule_tree.out_degree(n) == 0
    )[0]
    disrupted_node_id = simulation_cfg.get("disrupted_node_id", default_disruption_node)
    delay_days = int(simulation_cfg.get("delay_days", 14))
    disruption_sim_df = simulate_disruption_to_root(
        tree=schedule_tree,
        schedule=schedule,
        disrupted_node_id=disrupted_node_id,
        delay_days=delay_days,
    )
    disruption_output = Path(
        simulation_cfg.get(
            "output_csv",
            "vessel_case_study_disruption_to_root_simulation.csv",
        )
    )
    disruption_sim_df.to_csv(disruption_output, index=False)
    root_row = disruption_sim_df.iloc[-1]
    print(
        f"Saved disruption simulation to {disruption_output.resolve()} "
        f"(disrupted_node={disrupted_node_id}, delay_days={delay_days}, "
        f"root_simulated_finish={root_row['simulated_finish_date']})"
    )

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
    nodes_out_df.loc[idx, "sampled_buffer_days"] = nodes_out_df.loc[idx, "node_id"].map(
        by_id["sampled_buffer_days"]
    )
    nodes_out_df.loc[idx, "sampled_integration_duration_days"] = nodes_out_df.loc[idx, "node_id"].map(
        by_id["sampled_integration_duration_days"]
    )
    nodes_out_df.loc[idx, "used_lead_time_days"] = nodes_out_df.loc[idx, "node_id"].map(
        by_id["used_lead_time_days"]
    )
    nodes_out = Path("__vessel_nodes_realistic_case_study_with_dates.csv")
    nodes_out_df.to_csv(nodes_out, index=False)
    print(f"Saved enriched nodes to {nodes_out.resolve()}")

    plot_path = Path("vessel_case_study_due_dates_graph.html")
    write_vis_html(
        tree=schedule_tree,
        schedule=schedule,
        output_path=plot_path,
        title="Vessel Physical Graph with Need-By and Procurement Start Dates",
    )
    print(f"Saved schedule graph to {plot_path.resolve()}")


if __name__ == "__main__":
    main()
