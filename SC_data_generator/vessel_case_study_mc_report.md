# Vessel Case Study Monte Carlo Report

## Overview
- Runs: `500`
- Root impacted frequency: `19.00%`
- Mean root delay (days): `1.20`
- Median root delay (days): `0.00`
- P90 root delay (days): `4.10`
- Max root delay (days): `19`
- Mean impacted nodes: `1.60`

## Most Risky Disrupted Nodes
| disrupted_node_id | times_sampled | mean_root_delay | probability_root_impacted | mean_impacted_nodes |
|---|---:|---:|---:|---:|
| COMP::Hull & Structural | 23 | 6.26 | 56.52% | 1.13 |
| COMP::Navigation & Sensors | 19 | 5.32 | 52.63% | 1.05 |
| COMP::Propulsion System | 29 | 3.62 | 41.38% | 0.83 |
| PART::Hull Plate Section | 23 | 2.00 | 43.48% | 1.87 |
| PART::Radar Antenna | 37 | 1.78 | 27.03% | 1.54 |

## Risk Buckets
- High: COMP::Hull & Structural, COMP::Navigation & Sensors, COMP::Propulsion System, PART::Hull Plate Section
- Medium: PART::Radar Antenna, RAW::RF-grade Copper, PART::Ballast Pump, RAW::Elastomer Seals (Nitrile), PART::Reduction Gearbox, PART::Inertial Navigation Unit, RAW::Quartz Crystal
- Low: RAW::Weld Wire (Flux-Cored), RAW::Stainless Steel 316, PART::Gas Turbine Engine, RAW::Rare-earth Magnets (NdFeB), RAW::Marine-grade Steel (AH36), RAW::Composite Epoxy Prepreg, RAW::Nickel-based Superalloy, RAW::Alloy Steel Gear Blank, RAW::Titanium Alloy Bar, RAW::High-Strength Bearing Steel

## Node Type Risk
| node_type | count_nodes | mean_probability_root_impacted | mean_root_delay | mean_impacted_nodes |
|---|---:|---:|---:|---:|
| component | 3 | 50.18% | 5.07 | 1.00 |
| part | 6 | 23.26% | 1.09 | 1.40 |
| raw_material | 12 | 8.72% | 0.29 | 1.92 |

## Layer Concentration
- Risk appears concentrated near higher-level nodes (layer 1).
- Highest mean root-impact probability layer: `1` (50.18%)
- Deepest layer probability: `3` (8.72%)
