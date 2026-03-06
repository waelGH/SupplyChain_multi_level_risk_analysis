# Supply-Chain Simulation Generator: What the Current Analyses Mean

## 1. Deterministic analysis: what question does it answer?

The deterministic analysis answers the following question:

**If one specific node experiences one specific delay, how does that delay propagate through the network?**

In this setting, we specify:
- which node is disrupted,
- how many days of delay are injected,
- and then trace how the disruption moves through the supply-chain structure.

This analysis is designed to explain **one concrete scenario**. It helps answer questions such as:
- Which downstream and upstream nodes are affected?
- How much delay is absorbed by buffer at each node?
- Where does the propagation stop?
- Does the delay reach the root/system node?
- Why is the root impacted, or why is it protected?

Therefore, deterministic analysis is best understood as a **single-scenario propagation analysis** or a **mechanism-level explanation tool**. It is useful when we want to understand **how** a disruption travels through the network in one specific case.

## 2. MC-A analysis: what question does it answer?

The current Monte Carlo analysis (MC-A) answers a different question:

**Given a fixed baseline schedule and fixed node parameters, how vulnerable is the system to many random single-node disruptions?**

In this setting:
- the baseline schedule is fixed,
- node-level parameters such as duration, lead time, and buffer are fixed,
- and each Monte Carlo run randomly selects:
  - one non-root disrupted node,
  - and one injected delay value.

The simulation then repeats this many times and summarizes:
- how often the root is impacted,
- how severe the root delay tends to be,
- which nodes are most risky when disrupted,
- and whether risk is concentrated near the top of the supply tree.

Therefore, MC-A is best understood as a **system-level robustness analysis under random single-node disruptions**. It does not explain one specific case in detail; instead, it characterizes the **overall risk profile** of the current static system configuration.

## 3. Core difference between deterministic analysis and MC-A

The most important difference is:

- **Deterministic analysis** explains **one event**.
- **MC-A analysis** summarizes **many random events**.

More specifically:

### Deterministic analysis

Focuses on:
- one chosen disrupted node,
- one chosen injected delay,
- one specific propagation path through the network.

It is useful for:
- mechanism interpretation,
- path tracing,
- explaining buffer absorption,
- and validating propagation logic.

### MC-A analysis

Focuses on:
- repeated random single-node disruption scenarios,
- aggregate system outcomes,
- node risk ranking,
- and root-level impact statistics.

It is useful for:
- measuring system resilience,
- identifying critical nodes,
- comparing risk across node types or layers,
- and quantifying overall disruption sensitivity.

## 4. Intuitive interpretation

A simple way to understand the two analyses is:

### Deterministic analysis is like a microscope

It examines one disruption scenario closely and asks:

**What exactly happened in this case?**

### MC-A analysis is like a system stress-test report

It repeats many random disruption scenarios and asks:

**How fragile or resilient is the overall system under this fixed baseline configuration?**

## 5. What deterministic analysis is used for in this project

In the current supply-chain simulation generator, deterministic analysis is mainly used to:
- test whether the propagation logic behaves as intended,
- show how delay moves through the network,
- explain where buffer absorbs delay,
- and produce a clear single-scenario analysis report.

In other words, it is mainly a **scenario explanation and mechanism validation tool**.

## 6. What MC-A analysis is used for in this project

In the current generator, MC-A is mainly used to:
- estimate how often random disruptions reach the root,
- measure root-level risk under the current baseline schedule,
- identify which nodes are structurally most risky,
- group nodes into high/medium/low risk buckets,
- and summarize how risk is distributed across node types and layers.

In other words, MC-A is mainly a **risk ranking and static resilience assessment tool**.

## 7. What the current MC-A does not represent

It is important to clarify that the current MC-A does **not** model full real-world uncertainty.

Specifically, it does **not** yet include:
- random variation in baseline duration for each Monte Carlo run,
- random variation in buffer for each Monte Carlo run,
- random variation in lead time for each Monte Carlo run,
- multiple simultaneous disrupted nodes,
- or time-evolving operational dynamics.

Instead, it keeps the baseline schedule fixed and only randomizes the external disruption scenario.

So the current MC-A should be interpreted as:

**A disruption sensitivity study on a fixed supply-chain baseline**, not as a full dynamic real-world simulation.

## 8. Why MC-A is still the right choice for now

Although a richer Monte Carlo design could randomize both the baseline and the disruptions, the current MC-A is still the right choice at this stage for three reasons.

First, it is more consistent with the teammate’s original architecture, which was based on:
- building one baseline schedule,
- then injecting disruption scenarios on top of it.

Second, it is easier to interpret. Because the baseline is fixed, the effect of each disruption is easier to attribute to network structure, node position, and buffer behavior.

Third, it is better for identifying critical nodes. If both the baseline and the disruptions were randomized at the same time, the source of risk would be harder to isolate.

So, for the current stage of development, MC-A is the more appropriate and more explainable analysis framework.

## 9. One-sentence summary

The current pipeline now supports two complementary levels of analysis:

- **Deterministic analysis** explains **how one disruption propagates through the network**.
- **MC-A analysis** evaluates **how the fixed system behaves under many random single-node disruptions**.

Together, these two analyses provide both:
- **mechanism-level understanding**, and
- **system-level risk assessment**.

## 10. Practical interpretation for the current generator

With the current implementation, the simulation generator can now support the following workflow:

1. Generate a baseline schedule for the supply-chain case study.
2. Inject a specific disruption and explain how delay propagates through the network.
3. Repeat many random single-node disruption scenarios under the same fixed baseline.
4. Quantify root-level risk and node criticality.
5. Produce interpretable reports, rankings, and risk summaries.

This makes the current framework more than a simple sample generator. It is now a **simulation-based supply-chain disruption analysis pipeline**.
