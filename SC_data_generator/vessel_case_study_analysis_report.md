# Vessel Case Study Analysis Report

## 1. Scenario
- disrupted_node_id: `RAW::Alloy Steel Gear Blank`
- injected_delay_days: `14`
- total nodes: `22`
- total impacted nodes: `1`
- root impacted: `False`
- root delay days: `0`

## 2. Delay Absorption and Propagation
- disrupted node absorbed delay: `5` days
- disrupted node residual delay after buffer: `9` days
- upstream absorber of remaining delay: `PART::Reduction Gearbox`
- stopped before root: `True`
- reached root details: No. Delay was fully absorbed before reaching root.

## 3. Most Affected Nodes
| node_id | node_type | finish_delay_days | absorbed_by_buffer_days |
|---|---|---:|---:|
| RAW::Alloy Steel Gear Blank | raw_material | 9 | 5 |
| PART::Reduction Gearbox | part | 0 | 9 |
| COMP::Hull & Structural | component | 0 | 0 |
| COMP::Navigation & Sensors | component | 0 | 0 |
| COMP::Propulsion System | component | 0 | 0 |

## 4. Interpretation
A 14-day external delay was injected at `RAW::Alloy Steel Gear Blank`. 1 of 22 nodes saw positive finish delay. The disrupted node absorbed 5 days via its local buffer. Remaining delay was contained before the root. Main stopping point was upstream node `PART::Reduction Gearbox`.
