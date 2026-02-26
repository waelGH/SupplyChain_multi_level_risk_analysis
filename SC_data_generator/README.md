# Supply Chain Sample Generator

A simple Python tool for generating **day-level shipment time windows** on a supply chain tree.

## Purpose

This project generates feasible shipment windows by backtracking from a final destination deadline.
It is useful for creating synthetic scheduling samples for testing, demos, and prototyping.

The current primary workflow uses a **fixed tree structure** provided in `config.json`.

## Project Structure

- `fixed_tree_sample_generator.py`: Core generator for fixed parent-list trees.
- `demo.py`: Main runnable script that reads `config.json` and writes `sample.json`.
- `config.json`: Input configuration (deadline date, tree, and sampling ranges).
- `sample.json`: Generated output records.
- `sample_generator.py`: Separate branching-layer random generator (alternative/legacy module).

## Configuration (`config.json`)

`demo.py` expects this structure:

```json
{
  "ddl_date": "2026-03-15",
  "tree": {
    "nodes": [
      {"id": "D0", "parent": null},
      {"id": "A1", "parent": "D0"}
    ]
  },
  "params": {
    "load_days_range": [0, 2],
    "transit_days_range": [1, 5],
    "window_days_range": [2, 6]
  }
}
```

### Field details

- `ddl_date`: Destination deadline date in `YYYY-MM-DD` format.
- `tree.nodes`: Parent-list representation of a tree.
- `id`: Unique node ID.
- `parent`: Parent node ID; root must use `null`.
- `load_days_range`: `[min, max]` days for load time sampling.
- `transit_days_range`: `[min, max]` days for transit time sampling.
- `window_days_range`: `[min, max]` days for departure window width.

## Time Sampling

In `fixed_tree_sample_generator.py`:

- `load_days`: sampled with a **lognormal long-tail** distribution using `random.lognormvariate`, then rounded and clipped to `load_days_range`.
- `transit_days`: sampled the same way (lognormal + round + clip) within `transit_days_range`.
- `window_days`: sampled with uniform integer sampling `random.randint(min, max)`.

This gives heavier probability to smaller values with occasional larger values for load/transit durations.

## How Generation Works

1. Parse `ddl_date`.
2. Validate the tree:
- exactly one root (`parent == null`)
- all parent IDs exist
- acyclic
- connected to root
3. Compute `layer_id` from root (destination is layer `0`).
4. Generate node windows from downstream to upstream:
- Root has `start_day = end_day = ddl_date` and zero load/transit.
- For each non-root node `u` with parent `p`:
  - `parent_deadline = p.end_day`
  - `end_day_u = parent_deadline - (load_days_u + transit_days_u)`
  - `start_day_u = end_day_u - window_days_u`

Assertions enforce basic feasibility during generation.

## Run

From the project root:

```bash
python3 demo.py
```

Expected console output:

```text
Sample successfully written to sample.json
```

## Output (`sample.json`)

`sample.json` is a JSON array of node records, for example:

- `id`: node ID
- `parent`: parent node ID (`null` for root)
- `layer_id`: computed distance from destination root
- `start_day`: earliest feasible departure day (ISO date string)
- `end_day`: latest feasible departure day (ISO date string)
- `load_days`: sampled load duration (days)
- `transit_days`: sampled transit duration (days)

## Constraints, Assumptions, and Guarantees

- Uses only Python standard library modules.
- Tree input must be a valid single-root tree.
- Dates are handled at **day granularity** (no hour/minute modeling).
- Root node is the destination deadline anchor.
- Non-root nodes are generated to satisfy:
  - `start_day <= end_day`
  - `end_day + load_days + transit_days <= parent_deadline`
- Output order is stable: sorted by `(layer_id, id)`.
