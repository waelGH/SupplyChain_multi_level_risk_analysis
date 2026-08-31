from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

MAX_TESTED_DELAY = 45


def short_name(node_id: str) -> str:
    return node_id.split("::", 1)[1] if "::" in node_id else node_id


def load_data(base_dir: Path):
    summary = pd.read_csv(
        base_dir / "vessel_case_study_sensitivity_v2_summary.csv"
    )
    heatmap = pd.read_csv(
        base_dir / "vessel_case_study_sensitivity_v2_heatmap.csv",
        index_col=0,
    )
    return summary, heatmap


def make_heatmap(summary_df, heatmap_df, output_dir):
    ordered_nodes = summary_df["disrupted_node_id"].tolist()
    heatmap_df = heatmap_df.reindex(ordered_nodes)

    row_labels = [short_name(x) for x in heatmap_df.index]
    disruption_days = [int(x) for x in heatmap_df.columns]
    data = heatmap_df.to_numpy(dtype=float)

    fig, ax = plt.subplots(figsize=(11.2, max(7.5, 0.38 * len(row_labels))))
    im = ax.imshow(
        data,
        aspect="auto",
        interpolation="nearest",
        vmin=0,
        vmax=np.nanmax(data),
    )

    for row_idx, (_, row) in enumerate(summary_df.iterrows()):
        threshold = row["critical_disruption_days"]
        if pd.notna(threshold):
            threshold = int(threshold)
            if threshold in disruption_days:
                col_idx = disruption_days.index(threshold)
                ax.plot(
                    col_idx,
                    row_idx,
                    marker="o",
                    markersize=4,
                    markerfacecolor="none",
                    markeredgecolor="white",
                    markeredgewidth=1.0,
                )

    ax.set_xlabel("Injected disruption magnitude (days)")
    ax.set_ylabel("Disrupted node")

    xticks = [
        i for i, day in enumerate(disruption_days)
        if day == 1 or day % 5 == 0
    ]
    ax.set_xticks(xticks)
    ax.set_xticklabels([str(disruption_days[i]) for i in xticks])
    ax.set_yticks(np.arange(len(row_labels)))
    ax.set_yticklabels(row_labels)

    cbar = fig.colorbar(im, ax=ax, pad=0.02)
    cbar.set_label("Final-system delay (days)")

    fig.tight_layout()
    fig.savefig(output_dir / "sensitivity_v2_heatmap.png", dpi=300, bbox_inches="tight")
    fig.savefig(output_dir / "sensitivity_v2_heatmap.pdf", bbox_inches="tight")
    plt.close(fig)


def make_threshold_ranking(summary_df, output_dir):
    df = summary_df.copy()
    df["threshold_sort"] = df["critical_disruption_days"].fillna(
        MAX_TESTED_DELAY + 1
    )
    df = df.sort_values(
        by=[
            "threshold_sort",
            "root_delay_at_45_days",
            "max_impacted_nodes",
            "disrupted_node_id",
        ],
        ascending=[True, False, False, True],
    ).reset_index(drop=True)

    node_labels = [short_name(x) for x in df["disrupted_node_id"]]
    fig, ax = plt.subplots(figsize=(9.5, max(7.5, 0.38 * len(node_labels))))

    y = np.arange(len(df))
    observed = df["critical_disruption_days"].notna()
    observed_x = df.loc[observed, "critical_disruption_days"].astype(int).to_numpy()
    observed_y = y[observed.to_numpy()]
    censored_y = y[(~observed).to_numpy()]

    for i, row in df.iterrows():
        threshold = row["critical_disruption_days"]
        x_value = int(threshold) if pd.notna(threshold) else MAX_TESTED_DELAY
        ax.hlines(y=i, xmin=0, xmax=x_value, linewidth=1.2)

    ax.plot(observed_x, observed_y, marker="o", linestyle="none", markersize=6)

    if len(censored_y) > 0:
        ax.plot(
            np.full(len(censored_y), MAX_TESTED_DELAY),
            censored_y,
            marker=">",
            linestyle="none",
            markersize=7,
        )

    for i, row in df.iterrows():
        threshold = row["critical_disruption_days"]
        if pd.notna(threshold):
            value = int(threshold)
            label = str(value)
            x_text = value + 0.6
        else:
            label = f">{MAX_TESTED_DELAY}"
            x_text = MAX_TESTED_DELAY + 0.6
        ax.text(x_text, i, label, va="center", fontsize=9)

    ax.axvline(
        MAX_TESTED_DELAY,
        linestyle="--",
        linewidth=0.8,
        alpha=0.6,
    )
    ax.set_yticks(y)
    ax.set_yticklabels(node_labels)
    ax.invert_yaxis()
    ax.set_xlabel("Critical disruption magnitude, $d_i^*$ (days)")
    ax.set_ylabel("Disrupted node")
    ax.set_xlim(0, 49)
    ax.set_xticks(np.arange(0, 46, 5))
    ax.grid(axis="x", linewidth=0.5, alpha=0.3)

    fig.tight_layout()
    fig.savefig(
        output_dir / "sensitivity_v2_threshold_ranking.png",
        dpi=300,
        bbox_inches="tight",
    )
    fig.savefig(
        output_dir / "sensitivity_v2_threshold_ranking.pdf",
        bbox_inches="tight",
    )
    plt.close(fig)


def main():
    base_dir = Path(__file__).resolve().parent
    output_dir = base_dir / "figures"
    output_dir.mkdir(exist_ok=True)

    summary_df, heatmap_df = load_data(base_dir)
    make_heatmap(summary_df, heatmap_df, output_dir)
    make_threshold_ranking(summary_df, output_dir)

    print("Sensitivity visualization completed successfully.")
    print(f"Saved figures under: {output_dir}")


if __name__ == "__main__":
    main()
