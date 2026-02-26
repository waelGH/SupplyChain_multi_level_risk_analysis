from __future__ import annotations

import random
from collections import deque
from pathlib import Path

import pandas as pd

try:
    import networkx as nx
except ModuleNotFoundError:  # pragma: no cover - handled at runtime.
    nx = None


PHYSICAL_NODE_TYPES = {"system", "component", "part", "raw_material"}


def _require_networkx():
    if nx is None:
        raise ImportError("networkx is required for graph modeling. Install dependencies from requirements.txt.")
    return nx


def build_physical_graph(nodes_df: pd.DataFrame, edges_df: pd.DataFrame) -> nx.DiGraph:
    nx_module = _require_networkx()
    physical_nodes_df = nodes_df[nodes_df["node_type"].isin(PHYSICAL_NODE_TYPES)].copy()
    physical_ids = set(physical_nodes_df["node_id"])
    physical_edges_df = edges_df[
        edges_df["src"].isin(physical_ids) & edges_df["dst"].isin(physical_ids)
    ].copy()

    graph = nx_module.DiGraph()
    for row in physical_nodes_df.to_dict("records"):
        node_id = str(row.pop("node_id"))
        graph.add_node(node_id, **row)

    for row in physical_edges_df.to_dict("records"):
        src = str(row.pop("src"))
        dst = str(row.pop("dst"))
        graph.add_edge(src, dst, **row)

    return graph

############################################################################################################
### Builds a tree following the structure: system -> components -> parts -> raw_materials, with edges ######
### directed from parent to child. #########################################################################
############################################################################################################
def build_schedule_tree(physical_graph: nx.DiGraph) -> nx.DiGraph:
    nx_module = _require_networkx()
    tree = nx_module.DiGraph()
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

    roots = [node for node, degree in tree.in_degree() if degree == 0]
    if len(roots) != 1:
        raise ValueError(f"Expected one schedule-tree root, found {len(roots)}: {roots}")

    root = roots[0]
    if tree.nodes[root].get("node_type") != "system":
        raise ValueError(
            f"Schedule-tree root must be a system node; got {root} ({tree.nodes[root].get('node_type')})"
        )

    seen = {root}
    queue = deque([root])
    while queue:
        node = queue.popleft()
        for child in tree.successors(node):
            if child in seen:
                continue
            seen.add(child)
            queue.append(child)
    if len(seen) != tree.number_of_nodes():
        missing = sorted(set(tree.nodes()) - seen)
        raise ValueError(f"Schedule tree disconnected from root '{root}'. Missing nodes: {missing}")

    return tree


def get_tree_root(tree: nx.DiGraph) -> str:
    roots = [node for node, degree in tree.in_degree() if degree == 0]
    if len(roots) != 1:
        raise ValueError(f"Expected one tree root, found {roots}")
    return roots[0]


def _safe_float(value, default: float = 0.0) -> float:
    if pd.isna(value):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value, default: int = 0) -> int:
    if pd.isna(value):
        return default
    try:
        return int(round(float(value)))
    except (TypeError, ValueError):
        return default


def _safe_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if pd.isna(value):
        return False
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def build_supplier_options(
    nodes_df: pd.DataFrame, edges_df: pd.DataFrame
) -> dict[str, list[dict]]:
    supply_edges = edges_df[
        edges_df["edge_type"].isin(["supply_selected", "supply_offer"])
    ].copy()
    if supply_edges.empty:
        return {}

    node_lookup = (
        nodes_df[["node_id", "name", "country", "latitude", "longitude"]]
        .drop_duplicates(subset=["node_id"])
        .set_index("node_id")
        .to_dict("index")
    )

    options: dict[str, list[dict]] = {}
    for row in supply_edges.to_dict("records"):
        supplier_node_id = str(row.get("src", "")).strip()
        item_node_id = str(row.get("dst", "")).strip()
        if not supplier_node_id or not item_node_id:
            continue

        supplier_node = node_lookup.get(supplier_node_id, {})
        lead_time_days = _safe_int(row.get("lead_time_days"), 0)
        transit_time_days = _safe_int(row.get("transit_time_days"), 0)

        supplier = {
            "supplier_name": str(supplier_node.get("name") or supplier_node_id),
            "supplier_node_id": supplier_node_id,
            "Lat": _safe_float(supplier_node.get("latitude")),
            "Lon": _safe_float(supplier_node.get("longitude")),
            "country": str(supplier_node.get("country") or ""),
            "production_time_days": max(0, lead_time_days - transit_time_days),
            "shipping_time_days": max(0, transit_time_days),
            "delay_risk": _safe_int(_safe_float(row.get("edge_exposure"), 0.0) * 100, 0),
            "edge_type": str(row.get("edge_type") or ""),
            "is_selected": _safe_bool(row.get("is_selected"))
            or str(row.get("edge_type")) == "supply_selected",
        }
        options.setdefault(item_node_id, []).append(supplier)

    for item_node_id, suppliers in options.items():
        suppliers.sort(key=lambda item: (not item["is_selected"], item["supplier_name"]))
        options[item_node_id] = suppliers

    return options


def select_suppliers_for_tree(
    tree: nx.DiGraph,
    supplier_options: dict[str, list[dict]],
    seed: int | None = None,
) -> dict[str, tuple[str, dict]]:
    rng = random.Random(seed)
    selected: dict[str, tuple[str, dict]] = {}

    for node_id in tree.nodes():
        options = supplier_options.get(node_id, [])
        if not options:
            continue
        preferred = [item for item in options if item.get("is_selected")]
        candidates = preferred or options
        chosen = rng.choice(candidates)
        supplier_name = chosen.get("supplier_name") or chosen.get("supplier_node_id") or "Unknown"
        selected[str(tree.nodes[node_id].get("name") or node_id)] = (
            str(supplier_name),
            {
                "Lat": chosen.get("Lat", 0.0),
                "Lon": chosen.get("Lon", 0.0),
                "country": chosen.get("country", ""),
                "production_time_days": chosen.get("production_time_days", 0),
                "shipping_time_days": chosen.get("shipping_time_days", 0),
                "delay_risk": chosen.get("delay_risk", 0),
                "supplier_node_id": chosen.get("supplier_node_id", ""),
                "edge_type": chosen.get("edge_type", ""),
                "is_selected": bool(chosen.get("is_selected", False)),
            },
        )

    return selected


def build_selected_plan_tree(
    tree: nx.DiGraph,
    selected_chain: dict[str, tuple[str, dict]],
) -> dict:
    root = get_tree_root(tree)

    def _node_to_tree(node_id: str) -> dict:
        node_name = str(tree.nodes[node_id].get("name") or node_id)
        selected_entry = selected_chain.get(node_name)
        selected_supplier = selected_entry[0] if selected_entry else None
        supplier_info = selected_entry[1] if selected_entry else None
        return {
            "name": node_name,
            "tier": str(tree.nodes[node_id].get("node_type", "unknown")),
            "selected_supplier": selected_supplier,
            "supplier_info": supplier_info,
            "children": [
                _node_to_tree(child_node_id)
                for child_node_id in sorted(
                    tree.successors(node_id),
                    key=lambda child_id: str(tree.nodes[child_id].get("name") or child_id),
                )
            ],
        }

    return _node_to_tree(root)


def load_case_study_csvs(
    base_dir: Path,
    nodes_filename: str = "__vessel_nodes_realistic_case_study_with_dates.csv",
    edges_filename: str = "__vessel_edges_case_study.csv",
) -> tuple[pd.DataFrame, pd.DataFrame]:
    nodes_path = base_dir / "SC_data_generator" / nodes_filename
    edges_path = base_dir / "SC_data_generator" / edges_filename
    nodes_df = pd.read_csv(nodes_path)
    edges_df = pd.read_csv(edges_path)
    return nodes_df, edges_df
