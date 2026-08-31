from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pandas as pd


THIS_DIR = Path(__file__).resolve().parent
GENERATOR_DIR = THIS_DIR.parent
GENERATOR_FILE = GENERATOR_DIR / "case_study_data_generator.py"

spec = importlib.util.spec_from_file_location(
    "case_study_data_generator",
    GENERATOR_FILE,
)
if spec is None or spec.loader is None:
    raise ImportError(f"Could not load generator module from {GENERATOR_FILE}")

generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)

generate_baseline_data = generator.generate_baseline_data
load_generator_inputs = generator.load_generator_inputs
simulate_network_disruption = generator.simulate_network_disruption


BASELINE_SEED = 42
MIN_DISRUPTION_DAYS = 1
MAX_DISRUPTION_DAYS = 45


def run_sensitivity_v2() -> None:
    """
    Deterministic node-by-magnitude sensitivity sweep for the vessel case study.

    Design
    ------
    - One fixed baseline schedule generated with seed 42.
    - All non-root physical nodes are disrupted one at a time.
    - Disruption magnitude is swept from 1 through 45 days.
    - The same full-network propagation engine used by MC V2 is called for
      every deterministic sensitivity scenario.
    """
    nodes_path = GENERATOR_DIR / "__vessel_nodes_realistic_case_study_with_dates.csv"
    edges_path = GENERATOR_DIR / "__vessel_edges_case_study.csv"
    config_path = GENERATOR_DIR / "config.json"

    results_path = THIS_DIR / "vessel_case_study_sensitivity_v2_results.csv"
    summary_path = THIS_DIR / "vessel_case_study_sensitivity_v2_summary.csv"
    heatmap_path = THIS_DIR / "vessel_case_study_sensitivity_v2_heatmap.csv"
    metadata_path = THIS_DIR / "vessel_case_study_sensitivity_v2_metadata.json"

    nodes_df, edges_df, config = load_generator_inputs(
        nodes_path, edges_path, config_path
    )

    _, schedule_tree, schedule = generate_baseline_data(
        nodes_df,
        edges_df,
        config,
        seed=BASELINE_SEED,
    )

    roots = [node_id for node_id, indegree in schedule_tree.in_degree() if indegree == 0]
    if len(roots) != 1:
        raise ValueError(f"Expected exactly one system root, found: {roots}")

    root = roots[0]
    candidate_nodes = sorted(node_id for node_id in schedule_tree.nodes() if node_id != root)
    delay_scenarios = range(MIN_DISRUPTION_DAYS, MAX_DISRUPTION_DAYS + 1)

    rows: list[dict] = []
    run_id = 0

    for node_id in candidate_nodes:
        rec = schedule[node_id]
        local_buffer_days = int(rec.get("sampled_buffer_days") or 0)

        for disruption_days in delay_scenarios:
            run_id += 1

            sim_df = simulate_network_disruption(
                tree=schedule_tree,
                schedule=schedule,
                disrupted_node_id=node_id,
                delay_days=disruption_days,
            )

            root_row = sim_df.loc[sim_df["node_id"] == root].iloc[0]

            rows.append(
                {
                    "run_id": run_id,
                    "disrupted_node_id": node_id,
                    "node_type": rec["node_type"],
                    "layer_id": int(rec["layer_id"]),
                    "disruption_days": int(disruption_days),
                    "local_buffer_days": local_buffer_days,
                    "root_delay_days": int(root_row["finish_delay_days"]),
                    "root_impacted": bool(root_row["finish_delay_days"] > 0),
                    "number_of_impacted_nodes": int(sim_df["impacted"].sum()),
                }
            )

    results_df = pd.DataFrame(rows)

    expected_runs = len(candidate_nodes) * (
        MAX_DISRUPTION_DAYS - MIN_DISRUPTION_DAYS + 1
    )
    if len(results_df) != expected_runs:
        raise RuntimeError(
            f"Expected {expected_runs} sensitivity runs, got {len(results_df)}"
        )
    if (results_df["disrupted_node_id"] == root).any():
        raise RuntimeError("Root node was incorrectly included as a disruption candidate")

    summary_rows: list[dict] = []

    for node_id, group in results_df.groupby("disrupted_node_id", sort=True):
        group = group.sort_values("disruption_days")
        positive = group.loc[group["root_delay_days"] > 0]

        critical_disruption_days = (
            int(positive["disruption_days"].iloc[0]) if not positive.empty else None
        )

        at_max = group.loc[
            group["disruption_days"] == MAX_DISRUPTION_DAYS
        ].iloc[0]

        summary_rows.append(
            {
                "disrupted_node_id": node_id,
                "node_type": str(group["node_type"].iloc[0]),
                "layer_id": int(group["layer_id"].iloc[0]),
                "local_buffer_days": int(group["local_buffer_days"].iloc[0]),
                "critical_disruption_days": critical_disruption_days,
                "critical_disruption_exceeds_45_days": critical_disruption_days is None,
                "root_delay_at_45_days": int(at_max["root_delay_days"]),
                "max_root_delay_days": int(group["root_delay_days"].max()),
                "max_impacted_nodes": int(group["number_of_impacted_nodes"].max()),
                "num_magnitudes_causing_root_delay": int(
                    (group["root_delay_days"] > 0).sum()
                ),
            }
        )

    summary_df = pd.DataFrame(summary_rows)

    # Preserve missing threshold values as nullable integers rather than floats.
    summary_df["critical_disruption_days"] = summary_df[
        "critical_disruption_days"
    ].astype("Int64")

    # Sort most sensitive nodes first. Nodes with no root impact up to 45 days
    # are placed last.
    summary_df["_threshold_sort"] = summary_df[
        "critical_disruption_days"
    ].fillna(MAX_DISRUPTION_DAYS + 1)
    summary_df = (
        summary_df.sort_values(
            by=[
                "_threshold_sort",
                "root_delay_at_45_days",
                "max_impacted_nodes",
                "disrupted_node_id",
            ],
            ascending=[True, False, False, True],
        )
        .drop(columns=["_threshold_sort"])
        .reset_index(drop=True)
    )

    heatmap_df = results_df.pivot(
        index="disrupted_node_id",
        columns="disruption_days",
        values="root_delay_days",
    )

    # Use the same node ordering as the sensitivity ranking.
    heatmap_df = heatmap_df.reindex(summary_df["disrupted_node_id"].tolist())

    results_df.to_csv(results_path, index=False)
    summary_df.to_csv(summary_path, index=False)
    heatmap_df.to_csv(heatmap_path)

    metadata = {
        "baseline_seed": BASELINE_SEED,
        "root_node_id": root,
        "number_of_non_root_nodes": len(candidate_nodes),
        "minimum_disruption_days": MIN_DISRUPTION_DAYS,
        "maximum_disruption_days": MAX_DISRUPTION_DAYS,
        "number_of_disruption_magnitudes": (
            MAX_DISRUPTION_DAYS - MIN_DISRUPTION_DAYS + 1
        ),
        "total_deterministic_runs": len(results_df),
        "propagation_function": "simulate_network_disruption",
        "schedule_resampled_between_runs": False,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print("Sensitivity V2 completed successfully.")
    print(f"Baseline seed: {BASELINE_SEED}")
    print(f"Root node: {root}")
    print(f"Non-root disruption candidates: {len(candidate_nodes)}")
    print(
        f"Disruption sweep: {MIN_DISRUPTION_DAYS}-{MAX_DISRUPTION_DAYS} days"
    )
    print(f"Total deterministic runs: {len(results_df)}")
    print()
    print(f"Saved raw results: {results_path}")
    print(f"Saved node summary: {summary_path}")
    print(f"Saved heatmap matrix: {heatmap_path}")
    print(f"Saved metadata: {metadata_path}")


if __name__ == "__main__":
    run_sensitivity_v2()
