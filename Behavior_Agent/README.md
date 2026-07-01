# Behavior Agent - Technical Documentation
## GIBL AI/ML Hackathon 2026 | Track D | Sentinels of the Network
### Team JIJIBISHA

---

## Table of Contents

1. [Overview](#overview)
2. [Why This Design](#why-this-design)
3. [File Structure](#file-structure)
4. [How It Works](#how-it-works)
5. [Data Sources](#data-sources)
6. [The 9 Anomaly Checks](#the-9-anomaly-checks)
7. [Integration with Other Agents](#integration-with-other-agents)
8. [How to Run](#how-to-run)
9. [Output Format](#output-format)

---

## Overview

The Behavior Agent is one of five agents in our multi-agent intrusion detection system. It analyzes **User and Entity Behavior Analytics (UEBA)** events to detect:

- **Insider threats** (legitimate accounts being misused)
- **Compromised credentials** (stolen accounts behaving abnormally)
- **Policy violations** (unauthorized database access, SWIFT off-hours activity)
- **Data exfiltration** (unusually large data transfers)

It uses a **Hybrid Architecture** combining two layers:

| Layer | Technology | What It Does |
|---|---|---|
| **Layer 1: ML Brain** | Isolation Forest (scikit-learn) | Learns what "normal" user behavior looks like from 9 numerical features. Detects complex multi-variable anomalies that no single rule could catch. |
| **Layer 2: Security Guard** | Deterministic Rules | Enforces bank-specific policies: Pumori CBS database whitelist, SWIFT segment restrictions, data exfiltration thresholds, peer deviation monitoring. |

The final score for each event is:
```
final_score = max(ml_score, rule_score)
```

This means:
- If the ML model spots a subtle anomaly that rules miss → ML score wins
- If a rule catches a clear policy violation → Rule score wins (and can force score to 1.0)

---

## Why This Design

### Why not ONLY rules?
Rules are black-and-white. If you set a rule "flag if bytes > 100MB", an attacker stealing 95MB slips through. The Isolation Forest examines **all 9 features together** and can detect that 95MB at 3AM from a teller who normally transfers 2MB is suspicious, even though no single threshold was crossed.

### Why not ONLY ML?
ML models don't understand banking regulations. The Pumori CBS database has a strict access whitelist — if a non-authorized account queries it, that's a **critical security violation regardless of what the ML model thinks**. Rules act as a safety net that the ML cannot bypass.

### Why Isolation Forest specifically?
1. **Unsupervised** — it doesn't need labeled attack data to learn what's "normal"
2. **Fast on CPU** — trains in ~1 second on 1,500 events, no GPU needed
3. **Matches the proposal paper** — our Flow Agent also uses Isolation Forest, giving the project architectural consistency
4. **NRB compliant** — runs entirely on-premises, no cloud dependency

### Why the Hybrid approach?
This was chosen because it maximizes both detection accuracy and regulatory compliance:
- The ML layer handles the **"unknown unknowns"** (novel attack patterns)
- The rules layer handles the **"known knowns"** (explicit bank policies from NRB, SWIFT CSP)
- Together they produce a well-calibrated anomaly score (0.0-1.0) for the Correlation Agent

---

## File Structure

```
Network_intrusion_detection_system/
├── Behavior_Agent/
│   ├── __init__.py                          # Python package initializer
│   ├── behavior_agent.py                    # Core BehaviorAgent class
│   ├── mock_data_generator.py               # Simulated data generator
│   ├── run_behavior_agent.py                # Main execution pipeline
│   ├── behavior_agent_demo.ipynb            # Jupyter notebook for presentation
│   ├── behavior_agent_detailed_results.csv  # Per-event scoring details (generated)
│   ├── ueba_mock_data.csv                   # Simulated UEBA events (generated)
│   ├── host_profiles_mock.csv               # Simulated host profiles (generated)
│   └── README.md                            # This documentation file
│
├── behavior_agent_output.csv                # FINAL OUTPUT for Correlation Agent
├── correlation_agent.py                     # Correlation Agent (teammate's code)
├── packet_agent_output.csv                  # Packet Agent output (teammate's code)
└── flow_agent.ipynb                         # Flow Agent (teammate's code)
```

### File Descriptions

#### `__init__.py`
- **What:** Makes the `Behavior_Agent` directory a Python package
- **Why:** Allows clean imports: `from Behavior_Agent.behavior_agent import BehaviorAgent`
- **Size:** ~5 lines

#### `behavior_agent.py`
- **What:** Contains the `BehaviorAgent` class — the core engine
- **Why:** Separating the class from the execution script follows software engineering best practices. The class can be imported by the Correlation Agent, the demo notebook, or any test script independently.
- **Key methods:**
  - `load_host_context()` — loads host_profiles.csv for segment awareness
  - `fit()` — trains the Isolation Forest and builds user profiles
  - `score_event()` — scores a single event (ML + rules combined)
  - `score_batch()` — scores an entire DataFrame
  - `aggregate_by_ip()` — produces the final per-IP output for Correlation Agent

#### `mock_data_generator.py`
- **What:** Generates ~1,400 simulated UEBA events and ~37 host profiles
- **Why:** We don't have the real 500,000-row `ueba_user_behavior.csv` yet. The mock data allows us to develop, test, and demonstrate the agent locally. It uses the exact column names and data types from the official Data Dictionary (§3.4 and §3.5).
- **Embedded attack scenarios:**
  - Saturday 3:18 AM data exfiltration (ram.shrestha — the main GIBL scenario)
  - SWIFT off-hours unauthorized access (rajesh.pandey)
  - Pumori database unauthorized queries (sunil.karki)
  - Insider threat with elevated peer deviation (deepak.bhattarai)
  - Brute force with failed login spikes (admin.operations)

#### `run_behavior_agent.py`
- **What:** The main execution script — run this to produce the output
- **Why:** Orchestrates the full pipeline: load data → train model → score events → aggregate → save CSV. Supports both mock data (default) and real data (via `--ueba` flag).
- **Usage:**
  ```bash
  python run_behavior_agent.py                                # mock data
  python run_behavior_agent.py --ueba ueba_user_behavior.csv  # real data
  ```

#### `behavior_agent_demo.ipynb`
- **What:** Jupyter notebook with visualizations and step-by-step walkthrough
- **Why:** For presenting to hackathon judges. Shows score distributions, ML vs Rules comparison, attack scenario detection, confusion matrix, and AUROC.

---

## How It Works

### Step-by-Step Pipeline

```
Step 1: LOAD DATA
    ├── ueba_user_behavior.csv (or mock data)
    └── host_profiles.csv (for segment/criticality context)
            │
            ▼
Step 2: EXTRACT 9 FEATURES per event
    bytes_transferred, duration_sec, failed_attempts,
    peer_deviation, is_off_hours, is_new_resource,
    hour_of_day, day_of_week, event_type_risk
            │
            ▼
Step 3: TRAIN ISOLATION FOREST
    StandardScaler normalizes features → IsolationForest learns
    what "normal" looks like → calibrate score range
            │
            ▼
Step 4: SCORE EACH EVENT (hybrid)
    ├── Layer 1: ML Brain → anomaly score from Isolation Forest
    ├── Layer 2: Security Guard → score from 9 rule checks
    └── Combined: final_score = max(ml_score, rule_score)
            │
            ▼
Step 5: AGGREGATE BY SOURCE IP
    Group all events by device IP → take maximum score →
    compile indicator flags → one row per IP
            │
            ▼
Step 6: SAVE behavior_agent_output.csv
    Ready for the Correlation Agent to merge and fuse
```

### The 9 Features Used by the ML Model

| # | Feature | Source Column | Why It Matters |
|---|---|---|---|
| 1 | `bytes_transferred` | Direct | Large transfers indicate data exfiltration |
| 2 | `duration_sec` | Direct | Unusually long sessions may indicate data staging |
| 3 | `failed_attempts_prior_1h` | Direct | Spike = brute force or credential stuffing |
| 4 | `peer_group_deviation_score` | Direct | The primary UEBA feature (Data Dictionary §3.4) |
| 5 | `is_off_hours_num` | `is_off_hours` (bool→int) | 67% of C2 beacons occur Saturday 03:00-05:00 |
| 6 | `is_new_resource_num` | `is_new_resource` (bool→int) | First-time SWIFT access is critical |
| 7 | `hour_of_day` | Extracted from `timestamp` | Time context for temporal anomalies |
| 8 | `day_of_week` | Extracted from `timestamp` | Weekend activity is suspicious |
| 9 | `event_type_risk` | Mapped from `event_type` | USB_INSERT and SOFTWARE_INSTALL are higher risk |

---

## The 9 Anomaly Checks (Security Guard Rules)

| # | Check | Trigger Condition | Score Added | MITRE Technique |
|---|---|---|---|---|
| 1 | Off-Hours Access | `is_off_hours == True` | +0.15 (extra +0.15 if Saturday 3-5 AM) | T1078 |
| 2 | Peer Group Deviation | `peer_group_deviation_score >= 0.65` | +0.20 to +0.35 | T1078 |
| 3 | Large Data Transfer | `bytes > 100MB` AND user avg `< 5MB` | +0.40 | T1041 |
| 4 | New SWIFT Resource | `is_new_resource` AND resource contains "SWIFT" | +0.35 | T1005 |
| 5 | Failed Access Spike | `failed_attempts >= 5` | +0.20 to +0.35 | T1110 |
| 6 | SWIFT Off-Hours | Host in SWIFT segment AND off-hours | Force to 0.90 | T1021 |
| 7 | **Pumori Unauthorized** | Queries Pumori DB AND not in whitelist | **Force to 1.0** | T1005 |
| 8 | High-Risk Event Type | USB_INSERT, SOFTWARE_INSTALL, PRIVILEGE_USE | +0.20 to +0.30 | T1078 |
| 9 | Honeypot Contact | Source IP is a honeypot | Force to 0.95 | — |

> **Note:** Check 7 (Pumori Unauthorized) is a **critical override** — it forces the score to 1.0 regardless of all other signals. This matches our proposal paper §6.3.

---

## Integration with Other Agents

### Where the Behavior Agent Sits

```
    Packet Agent ──────── Flow Agent ──────── Behavior Agent
    (Zeek logs)           (NetFlow)            (UEBA + Windows)
         │                    │                      │
         │  sp                │  sf                  │  sb
         ▼                    ▼                      ▼
    ┌──────────────────────────────────────────────────────┐
    │              CORRELATION AGENT                        │
    │   Gated Fusion: g=sigmoid(sf-sb)                      │
    │   fused = g*sf + (1-g)*sb                             │
    │   threat = 0.85*fused + 0.15*sp                       │
    │   + co-occurrence boost if 2+ agents flag same entity │
    └──────────────────────┬───────────────────────────────┘
                           │
                           ▼
                    RESPONSE AGENT
```

### How to Integrate with the Correlation Agent

The Correlation Agent (`correlation_agent.py`) currently merges by `source_ip`. To add the Behavior Agent output, the teammate needs to add:

```python
# In correlation_agent.py — add after packet agent merge:

# Load Behavior Agent output
behavior_df = pd.read_csv("behavior_agent_output.csv")
behavior_slim = behavior_df.rename(columns={"source_ip": "src_ip"})

# Merge onto the main flows
df = df.merge(behavior_slim, on="src_ip", how="left")
df["behavior_score"] = df["behavior_score"].fillna(0.0)
```

Then update the gated fusion to use all three agent scores:
```python
# Three-agent gated fusion (matching the proposal paper equations):
g = sigmoid(sf - sb)
fused = g * sf + (1 - g) * sb
threat = 0.85 * fused + 0.15 * sp
```

---

## How to Run

### Quick Start (Mock Data)
```bash
cd d:\GIBL\Network_intrusion_detection_system\Behavior_Agent
python run_behavior_agent.py
```

### With Real Data
```bash
python run_behavior_agent.py --ueba path/to/ueba_user_behavior.csv --hosts path/to/host_profiles.csv
```

### In Jupyter Notebook
```bash
cd d:\GIBL\Network_intrusion_detection_system
jupyter notebook Behavior_Agent/behavior_agent_demo.ipynb
```

### Requirements
- Python 3.9+
- pandas
- numpy
- scikit-learn
- matplotlib (for notebook only)

---

## Output Format

### `behavior_agent_output.csv` (for Correlation Agent)

| Column | Type | Description |
|---|---|---|
| `source_ip` | STRING | Device IP address — **join key** for Correlation Agent |
| `behavior_score` | FLOAT | Maximum anomaly score (0.0-1.0) for this IP |
| `is_behavior_anomaly` | INT | 1 if any event from this IP scored >= 0.65 |
| `ind_off_hours` | INT | 1 if off-hours activity was detected |
| `ind_high_deviation` | INT | 1 if peer group deviation >= 0.65 |
| `ind_large_transfer` | INT | 1 if data exfiltration pattern detected |
| `ind_unauthorized_db` | INT | 1 if unauthorized Pumori access detected |
| `ind_swift_access` | INT | 1 if SWIFT segment access anomaly detected |
| `behavior_event_count` | INT | Total UEBA events processed for this IP |

### `behavior_agent_detailed_results.csv` (for analysis)

| Column | Type | Description |
|---|---|---|
| `entity` | STRING | username@hostname identifier |
| `timestamp` | STRING | Event timestamp |
| `score` | FLOAT | Final hybrid score (0.0-1.0) |
| `ml_score` | FLOAT | Isolation Forest component |
| `rule_score` | FLOAT | Security Guard component |
| `flags` | STRING | Pipe-separated anomaly flags |
| `mitre` | STRING | Pipe-separated MITRE ATT&CK mappings |
| `source_ip` | STRING | Device IP |
| `username` | STRING | User who performed the action |
| `hostname` | STRING | Host where it happened |

---

## References

- **Data Dictionary:** §3.4 (ueba_user_behavior), §3.5 (host_profiles), §4 (Hidden Patterns), §6 (Network Segments)
- **Proposal Paper:** §4.4 (Behavior Agent), §3.5 (Gated Fusion), §6.3 (Pumori Protection)
- **MITRE ATT&CK:** T1078 (Valid Accounts), T1041 (Exfiltration), T1005 (Data from Local System), T1110 (Brute Force), T1021 (Remote Services)
