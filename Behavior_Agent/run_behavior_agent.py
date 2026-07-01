import os
import sys
import time
import argparse
import pandas as pd
import numpy as np

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Behavior_Agent.behavior_agent import BehaviorAgent
from Behavior_Agent.mock_data_generator import generate_all

# Where to save the final output (parent directory for Correlation Agent)
PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_FILE = os.path.join(PARENT_DIR, "behavior_agent_output.csv")

# Where to save detailed results (inside Behavior_Agent folder)
AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
DETAILED_OUTPUT = os.path.join(AGENT_DIR, "behavior_agent_detailed_results.csv")

#  Data Loading
def load_data(ueba_path=None, host_path=None):
    if ueba_path and os.path.exists(ueba_path):
        print(f"  Loading real UEBA data from: {ueba_path}")
        ueba_df = pd.read_csv(ueba_path, low_memory=False)
    else:
        if ueba_path:
            print(f"  [WARN] {ueba_path} not found — generating mock data")
        else:
            print("  No UEBA path provided — generating mock data")

        ueba_df, host_df = generate_all(output_dir=AGENT_DIR)
        mock_host_path = os.path.join(AGENT_DIR, "host_profiles_mock.csv")

        if host_path is None or not os.path.exists(host_path):
            host_path = mock_host_path

        return ueba_df, pd.read_csv(host_path)

    if host_path and os.path.exists(host_path):
        print(f"  Loading host profiles from: {host_path}")
        host_df = pd.read_csv(host_path)
    else:
        # Try common locations
        common_paths = [
            os.path.join(PARENT_DIR, "host_profiles.csv"),
            os.path.join(AGENT_DIR, "host_profiles_mock.csv"),
        ]
        host_df = None
        for p in common_paths:
            if os.path.exists(p):
                print(f"  Loading host profiles from: {p}")
                host_df = pd.read_csv(p)
                break

        if host_df is None:
            print("  [WARN] No host profiles found — generating mock profiles")
            _, host_df = generate_all(output_dir=AGENT_DIR)
            host_df = pd.read_csv(os.path.join(AGENT_DIR, "host_profiles_mock.csv"))

    return ueba_df, host_df

#  Main Pipeline
def run_behavior_agent(ueba_path=None, host_path=None):
    start_time = time.time()

    print("=" * 65)
    print("  GIBL BEHAVIOR AGENT")
    print("  Hybrid Anomaly Detection: Isolation Forest + Banking Rules")
    print("=" * 65)

    # ── Step 1: Load data ──
    print("\n[1] Loading data...")
    ueba_df, host_df = load_data(ueba_path, host_path)
    print(f"    UEBA events  : {len(ueba_df):,}")
    print(f"    Host profiles: {len(host_df):,}")

    # ── Step 2: Initialize agent ──
    print("\n[2] Initializing Behavior Agent...")
    agent = BehaviorAgent(
        contamination=0.02,   # ~2% expected anomaly rate
        n_estimators=200,     # 200 trees in the forest
        random_state=42,
    )

    # ── Step 3: Load host context ──
    print("\n[3] Loading host context...")
    agent.load_host_context(host_df)

    # ── Step 4: Train the model ──
    print("\n[4] Training Isolation Forest model...")
    train_start = time.time()
    agent.fit(ueba_df)
    train_time = time.time() - train_start
    print(f"    Training time: {train_time:.2f} seconds")

    # ── Step 5: Score all events ──
    print("\n[5] Scoring all events (hybrid: ML + Rules)...")
    score_start = time.time()
    results = agent.score_batch(ueba_df)
    score_time = time.time() - score_start
    print(f"    Scoring time : {score_time:.2f} seconds")
    print(f"    Throughput   : {len(results) / score_time:.0f} events/sec")

    # ── Step 6: Save detailed per-event results ──
    print(f"\n[6] Saving detailed results to {DETAILED_OUTPUT}...")
    detailed_rows = []
    for r in results:
        detailed_rows.append({
            "entity": r["entity"],
            "timestamp": r["timestamp"],
            "score": r["score"],
            "ml_score": r["ml_score"],
            "rule_score": r["rule_score"],
            "flags": "|".join(r["flags"]) if r["flags"] else "",
            "mitre": "|".join([f"{t[0]}:{t[1]}" for t in r["mitre"]]) if r["mitre"] else "",
            "source_ip": r["source_ip"],
            "username": r["username"],
            "hostname": r["hostname"],
        })
    detailed_df = pd.DataFrame(detailed_rows)
    detailed_df.to_csv(DETAILED_OUTPUT, index=False)
    print(f"    -> {len(detailed_df):,} detailed results saved")

    # ── Step 7: Aggregate by source_ip ──
    print(f"\n[7] Aggregating results by source IP...")
    output_df = agent.aggregate_by_ip(results)

    # ── Step 8: Save final output ──
    print(f"\n[8] Saving output to {OUTPUT_FILE}...")
    output_df.to_csv(OUTPUT_FILE, index=False)
    print(f"    -> {len(output_df):,} rows written to {OUTPUT_FILE}")

    # ── Summary ──
    total_time = time.time() - start_time
    print("\n" + "=" * 65)
    print("  BEHAVIOR AGENT COMPLETE")
    print("=" * 65)
    print(f"  Total time         : {total_time:.2f} seconds")
    print(f"  Events processed   : {len(results):,}")
    print(f"  Unique source IPs  : {len(output_df):,}")

    if not output_df.empty:
        n_anomalous = (output_df["is_behavior_anomaly"] == 1).sum()
        n_normal = len(output_df) - n_anomalous
        print(f"  Normal IPs         : {n_normal:,}")
        print(f"  Anomalous IPs      : {n_anomalous:,}")
        print(f"  Anomaly rate       : {n_anomalous / len(output_df):.1%}")

        # Show top 5 most anomalous IPs
        print(f"\n  Top 5 Most Anomalous IPs:")
        print(f"  {'Source IP':<20} {'Score':<8} {'Flags'}")
        print(f"  {'-' * 50}")
        top5 = output_df.head(5)
        for _, row in top5.iterrows():
            active_flags = []
            for col in ["ind_off_hours", "ind_high_deviation", "ind_large_transfer",
                        "ind_unauthorized_db", "ind_swift_access"]:
                if row.get(col, 0) == 1:
                    active_flags.append(col.replace("ind_", ""))
            print(f"  {row['source_ip']:<20} {row['behavior_score']:<8.4f} "
                  f"{', '.join(active_flags) if active_flags else 'ml_anomaly'}")

    print(f"\n  Output files:")
    print(f"    -> {OUTPUT_FILE}")
    print(f"    -> {DETAILED_OUTPUT}")
    print("=" * 65)

    return output_df, detailed_df, results

#  CLI Entry Point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="GIBL Behavior Agent — Hybrid Anomaly Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_behavior_agent.py                               # Use mock data
  python run_behavior_agent.py --ueba ueba_user_behavior.csv # Use real data
  python run_behavior_agent.py --ueba data.csv --hosts hosts.csv
        """,
    )
    parser.add_argument(
        "--ueba", type=str, default=None,
        help="Path to ueba_user_behavior.csv (default: generate mock data)"
    )
    parser.add_argument(
        "--hosts", type=str, default=None,
        help="Path to host_profiles.csv (default: auto-detect or generate mock)"
    )

    args = parser.parse_args()
    run_behavior_agent(ueba_path=args.ueba, host_path=args.hosts)
