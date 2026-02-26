from datetime import datetime, timedelta
import random
import json


def sample_lognormal_int(min_v, max_v, mu=1.0, sigma=0.6):
    """Sample a long-tail integer and clip it to [min_v, max_v]."""
    sampled = random.lognormvariate(mu, sigma)
    sampled_int = int(round(sampled))
    return max(min_v, min(max_v, sampled_int))


def generate_fixed_tree_samples(
    ddl_date,
    tree_spec,
    load_days_range=(1, 4),
    transit_days_range=(1, 7),
    window_days_range=(1, 5),
):
    """Generate day-level shipment windows for a fixed parent-list tree.

    Args:
        ddl_date: Destination deadline date string in YYYY-MM-DD format.
        tree_spec: Dict like {"nodes": [{"id": "D0", "parent": None}, ...]}.
        load_days_range: Tuple (min_days, max_days).
        transit_days_range: Tuple (min_days, max_days).
        window_days_range: Tuple (min_days, max_days).

    Returns:
        List of node records with id, parent, layer_id, start_day, end_day,
        load_days, transit_days.
    """
    _validate_range(load_days_range, "load_days_range")
    _validate_range(transit_days_range, "transit_days_range")
    _validate_range(window_days_range, "window_days_range")

    deadline = datetime.strptime(ddl_date, "%Y-%m-%d").date()
    raw_nodes = tree_spec.get("nodes", [])
    if not raw_nodes:
        raise ValueError("tree_spec['nodes'] must not be empty")

    # Build a map for quick node and parent validation.
    node_map = {}
    for node in raw_nodes:
        node_id = node.get("id")
        if not node_id:
            raise ValueError("Each node must include a non-empty 'id'")
        if node_id in node_map:
            raise ValueError(f"Duplicate node id found: {node_id}")
        node_map[node_id] = {"id": node_id, "parent": node.get("parent")}

    # Validate that there is exactly one root (destination node).
    roots = [n["id"] for n in node_map.values() if n["parent"] is None]
    if len(roots) != 1:
        raise ValueError("Tree must contain exactly one root node (parent == null)")
    root_id = roots[0]

    # Validate parent references.
    for node in node_map.values():
        parent_id = node["parent"]
        if parent_id is not None and parent_id not in node_map:
            raise ValueError(f"Parent '{parent_id}' for node '{node['id']}' does not exist")

    # Validate acyclic graph using DFS states: 0=unvisited, 1=visiting, 2=done.
    states = {node_id: 0 for node_id in node_map}

    def dfs_cycle_check(node_id):
        state = states[node_id]
        if state == 1:
            raise ValueError("Tree contains a cycle")
        if state == 2:
            return

        states[node_id] = 1
        parent_id = node_map[node_id]["parent"]
        if parent_id is not None:
            dfs_cycle_check(parent_id)
        states[node_id] = 2

    for node_id in node_map:
        dfs_cycle_check(node_id)

    # Build children lists to traverse downstream->upstream by layers.
    children = {node_id: [] for node_id in node_map}
    for node in node_map.values():
        parent_id = node["parent"]
        if parent_id is not None:
            children[parent_id].append(node["id"])

    # Compute layer IDs with a BFS from the root.
    layer_id_map = {root_id: 0}
    queue = [root_id]
    index = 0
    while index < len(queue):
        current = queue[index]
        index += 1
        for child_id in children[current]:
            layer_id_map[child_id] = layer_id_map[current] + 1
            queue.append(child_id)

    if len(layer_id_map) != len(node_map):
        raise ValueError("Tree must be connected to the single root")

    # Generate windows from downstream to upstream using BFS order.
    records_by_id = {
        root_id: {
            "id": root_id,
            "parent": None,
            "layer_id": 0,
            "start_day": deadline,
            "end_day": deadline,
            "load_days": 0,
            "transit_days": 0,
        }
    }

    for parent_id in queue:
        parent_record = records_by_id[parent_id]
        parent_deadline = parent_record["end_day"]

        for child_id in children[parent_id]:
            load_days = sample_lognormal_int(load_days_range[0], load_days_range[1])
            transit_days = sample_lognormal_int(
                transit_days_range[0], transit_days_range[1]
            )
            window_days = random.randint(window_days_range[0], window_days_range[1])

            # Latest departure day that can still satisfy the parent deadline.
            end_day = parent_deadline - timedelta(days=load_days + transit_days)
            # Earliest departure day for the same feasible window.
            start_day = end_day - timedelta(days=window_days)

            assert start_day <= end_day
            assert end_day + timedelta(days=load_days + transit_days) <= parent_deadline

            records_by_id[child_id] = {
                "id": child_id,
                "parent": parent_id,
                "layer_id": layer_id_map[child_id],
                "start_day": start_day,
                "end_day": end_day,
                "load_days": load_days,
                "transit_days": transit_days,
            }

    # Return records sorted by layer then id for stable output.
    return sorted(records_by_id.values(), key=lambda x: (x["layer_id"], x["id"]))


def _validate_range(value_range, name):
    if not isinstance(value_range, tuple) or len(value_range) != 2:
        raise ValueError(f"{name} must be a tuple: (min_days, max_days)")
    min_v, max_v = value_range
    if min_v < 0 or max_v < min_v:
        raise ValueError(f"{name} must satisfy 0 <= min_days <= max_days")


def demo_fixed_tree_generation():
    """Small demo that loads a sample tree JSON and prints generated records."""
    random.seed(42)

    sample_tree_json = '''
    {
      "nodes": [
        {"id": "D0", "parent": null},
        {"id": "A1", "parent": "D0"},
        {"id": "A2", "parent": "D0"},
        {"id": "B1", "parent": "A1"},
        {"id": "B2", "parent": "A1"},
        {"id": "B3", "parent": "A2"}
      ]
    }
    '''
    tree_spec = json.loads(sample_tree_json)

    records = generate_fixed_tree_samples(
        ddl_date="2026-03-31",
        tree_spec=tree_spec,
        load_days_range=(1, 3),
        transit_days_range=(2, 5),
        window_days_range=(1, 4),
    )

    print("Generated fixed-tree shipment sample:")
    for rec in records:
        print(rec)


if __name__ == "__main__":
    demo_fixed_tree_generation()
