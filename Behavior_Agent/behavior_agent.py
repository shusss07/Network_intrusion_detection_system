import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import defaultdict
import warnings

warnings.filterwarnings("ignore")
# Risk tiers for event types — higher risk events contribute more to the score.
# Based on typical SOC analyst prioritization in banking environments.
EVENT_TYPE_RISK = {
    "FILE_ACCESS":      0.05,
    "DB_QUERY":         0.10,
    "EMAIL_SEND":       0.05,
    "SHARE_ACCESS":     0.10,
    "PRINT":            0.02,
    "REMOTE_LOGIN":     0.15,
    "PRIVILEGE_USE":    0.25,
    "SOFTWARE_INSTALL": 0.30,
    "USB_INSERT":       0.20,
    "LARGE_DOWNLOAD":   0.15,
}

# MITRE ATT&CK mapping for behavior anomalies.
# Each flag maps to a (tactic, technique_id) tuple.
BEHAVIOR_MITRE_MAP = {
    "off_hours":              ("Persistence",          "T1078"),
    "high_peer_deviation":    ("Valid Accounts",       "T1078"),
    "elevated_peer_deviation":("Valid Accounts",       "T1078"),
    "large_data_transfer":    ("Exfiltration",         "T1041"),
    "new_swift_resource":     ("Collection",           "T1005"),
    "new_resource":           ("Discovery",            "T1083"),
    "failed_access_spike":    ("Credential Access",    "T1110"),
    "failed_access_elevated": ("Credential Access",    "T1110"),
    "swift_off_hours":        ("Lateral Movement",     "T1021"),
    "unauthorized_pumori":    ("Collection",           "T1005"),
    "privilege_abuse":        ("Privilege Escalation",  "T1078"),
    "ml_anomaly":             ("Anomaly",              "T0000"),
}

# Feature columns used by the Isolation Forest model.
FEATURE_COLUMNS = [
    "bytes_transferred",
    "duration_sec",
    "failed_attempts_prior_1h",
    "peer_group_deviation_score",
    "is_off_hours_num",
    "is_new_resource_num",
    "hour_of_day",
    "day_of_week",
    "event_type_risk",
]

# Default list of accounts authorized to query the Pumori CBS database.
# Any other account querying Pumori triggers an immediate CRITICAL alert.
DEFAULT_PUMORI_WHITELIST = [
    "srv_pumori_app",
    "pumori_batch",
    "admin_db_sync",
    "cbs_service",
    "pumori_reporting",
]

class BehaviorAgent:
    
    def __init__(self, pumori_whitelist=None, contamination=0.02,
                 n_estimators=200, random_state=42):
        self.pumori_whitelist = [
            u.lower() for u in (pumori_whitelist or DEFAULT_PUMORI_WHITELIST)
        ]
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state

        # ML components (initialized during fit)
        self.model = None
        self.scaler = None
        self.is_fitted = False

        # Host context (loaded separately)
        self.host_profiles = None
        self.hostname_to_segment = {}
        self.hostname_to_ip = {}
        self.ip_to_hostname = {}
        self.hostname_to_criticality = {}
        self.honeypot_ips = set()

        # Per-user behavioral profiles (built during fit, updated during scoring)
        self.user_profiles = defaultdict(lambda: {
            "bytes_history": [],
            "peer_scores": [],
            "login_hours": [],
            "event_count": 0,
        })

    def load_host_context(self, host_profiles_path_or_df):
        if isinstance(host_profiles_path_or_df, str):
            self.host_profiles = pd.read_csv(host_profiles_path_or_df)
        else:
            self.host_profiles = host_profiles_path_or_df.copy()

        # Build lookup dictionaries for fast access during scoring
        for _, row in self.host_profiles.iterrows():
            hostname = row["hostname"]
            ip = row["ip_address"]
            self.hostname_to_segment[hostname] = row.get("segment", "UNKNOWN")
            self.hostname_to_ip[hostname] = ip
            self.ip_to_hostname[ip] = hostname
            self.hostname_to_criticality[hostname] = row.get("criticality", "MEDIUM")
            if row.get("is_honeypot", False):
                self.honeypot_ips.add(ip)

        print(f"    [BehaviorAgent] Loaded context for {len(self.host_profiles)} hosts")
        print(f"    [BehaviorAgent] Segments: {set(self.hostname_to_segment.values())}")
        print(f"    [BehaviorAgent] Honeypots: {len(self.honeypot_ips)}")

    def _prepare_features(self, df):
        features = pd.DataFrame(index=df.index)

        # Direct numerical columns
        features["bytes_transferred"] = pd.to_numeric(
            df["bytes_transferred"], errors="coerce"
        ).fillna(0)
        features["duration_sec"] = pd.to_numeric(
            df["duration_sec"], errors="coerce"
        ).fillna(0)
        features["failed_attempts_prior_1h"] = pd.to_numeric(
            df["failed_attempts_prior_1h"], errors="coerce"
        ).fillna(0)
        features["peer_group_deviation_score"] = pd.to_numeric(
            df["peer_group_deviation_score"], errors="coerce"
        ).fillna(0)

        # Convert boolean columns to numeric (0/1)
        features["is_off_hours_num"] = df["is_off_hours"].map(
            {True: 1, False: 0, "True": 1, "False": 0}
        ).fillna(0).astype(int)
        features["is_new_resource_num"] = df["is_new_resource"].map(
            {True: 1, False: 0, "True": 1, "False": 0}
        ).fillna(0).astype(int)

        # Temporal features from timestamp
        timestamps = pd.to_datetime(df["timestamp"], errors="coerce")
        features["hour_of_day"] = timestamps.dt.hour.fillna(12).astype(int)
        features["day_of_week"] = timestamps.dt.dayofweek.fillna(0).astype(int)

        # Event type risk score
        features["event_type_risk"] = df["event_type"].map(
            EVENT_TYPE_RISK
        ).fillna(0.05)

        return features[FEATURE_COLUMNS]

    def fit(self, ueba_df):
        print(f"    [BehaviorAgent] Training on {len(ueba_df):,} events...")

        # Step 1: Extract features
        X = self._prepare_features(ueba_df)
        print(f"    [BehaviorAgent] Feature matrix: {X.shape[0]} rows x {X.shape[1]} features")

        # Step 2: Scale features (StandardScaler normalizes to mean=0, std=1)
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Step 3: Train Isolation Forest
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,  # Use all CPU cores
        )
        self.model.fit(X_scaled)
        self.is_fitted = True
        print(f"    [BehaviorAgent] Isolation Forest trained "
              f"({self.n_estimators} trees, contamination={self.contamination})")

        # Step 4: Calibrate score range using training data
        # score_samples() returns negative values for anomalies, positive for normal.
        # We compute percentiles to properly map to 0-1.
        train_scores = self.model.score_samples(X_scaled)
        self.score_min = float(np.percentile(train_scores, 1))   # deepest anomalies
        self.score_max = float(np.percentile(train_scores, 99))  # most normal
        print(f"    [BehaviorAgent] Score calibration: min={self.score_min:.4f}, max={self.score_max:.4f}")

        # Step 5: Build per-user behavioral profiles from training data
        for _, row in ueba_df.iterrows():
            username = str(row.get("username", "unknown"))
            profile = self.user_profiles[username]
            profile["bytes_history"].append(int(row.get("bytes_transferred", 0)))
            profile["peer_scores"].append(float(row.get("peer_group_deviation_score", 0)))
            ts = pd.to_datetime(row.get("timestamp", "2026-01-01"), errors="coerce")
            if pd.notna(ts):
                profile["login_hours"].append(ts.hour)
            profile["event_count"] += 1

        print(f"    [BehaviorAgent] Built profiles for {len(self.user_profiles)} users")
        return self

    def _ml_score(self, features_row):
        
        if not self.is_fitted:
            return 0.0

        X = features_row[FEATURE_COLUMNS].values.reshape(1, -1)
        X_scaled = self.scaler.transform(X)
        raw_score = self.model.score_samples(X_scaled)[0]

        # Convert using calibrated range from training data.
        # raw_score is negative for anomalies, positive for normal.
        # We invert and normalize: lower raw_score -> higher anomaly score.
        score_range = self.score_max - self.score_min
        if score_range == 0:
            score_range = 1.0  # avoid division by zero
        score = float(np.clip((self.score_max - raw_score) / score_range, 0.0, 1.0))
        return round(score, 4)

    def _rule_checks(self, event):
        flags = []
        mitre = []
        rule_score = 0.0

        username = str(event.get("username", "")).lower()
        hostname = str(event.get("hostname", ""))
        resource = str(event.get("resource_accessed", "")).lower()
        event_type = str(event.get("event_type", ""))

        #Check 1: Off-Hours Access
        # Hidden Pattern #1: 67% of C2 beacons occur Saturday 03:00–05:00 NPT
        is_off_hours = event.get("is_off_hours", False)
        if is_off_hours in (True, "True", 1, "1"):
            rule_score += 0.15
            flags.append("off_hours")
            mitre.append(BEHAVIOR_MITRE_MAP["off_hours"])

            # Extra penalty for weekend early-morning (Saturday 03:00-05:00)
            ts = pd.to_datetime(event.get("timestamp", ""), errors="coerce")
            if pd.notna(ts) and ts.dayofweek == 5 and 3 <= ts.hour <= 5:
                rule_score += 0.15  # additional weekend penalty
                flags.append("weekend_early_morning")

        #Check 2: Peer Group Deviation
        # Hidden Pattern #5: compromised users consistently > 0.65
        peer_score = float(event.get("peer_group_deviation_score", 0.0))
        if peer_score >= 0.80:
            rule_score += 0.35
            flags.append("high_peer_deviation")
            mitre.append(BEHAVIOR_MITRE_MAP["high_peer_deviation"])
        elif peer_score >= 0.65:
            rule_score += 0.20
            flags.append("elevated_peer_deviation")
            mitre.append(BEHAVIOR_MITRE_MAP["elevated_peer_deviation"])

        # Check 3: Large Data Transfer (Hidden Pattern from data dictionary)
        # "insider threat events have bytes_transferred > 100 MB where
        #  the same user's 30-day average is < 5 MB"
        bytes_transferred = int(event.get("bytes_transferred", 0))
        profile = self.user_profiles.get(username, {})
        bytes_history = profile.get("bytes_history", [])
        avg_bytes = float(np.mean(bytes_history)) if bytes_history else 0.0

        if bytes_transferred > 100_000_000 and avg_bytes < 5_000_000:
            rule_score += 0.40
            flags.append("large_data_transfer")
            mitre.append(BEHAVIOR_MITRE_MAP["large_data_transfer"])
        elif bytes_transferred > 50_000_000 and avg_bytes < 5_000_000:
            rule_score += 0.20
            flags.append("large_data_transfer")

        #Check 4: New Resource Access
        # "SWIFT MT-type messages in this field are a critical signal"
        is_new = event.get("is_new_resource", False)
        if is_new in (True, "True", 1, "1"):
            if "swift_mt" in resource or "swift" in resource:
                rule_score += 0.35
                flags.append("new_swift_resource")
                mitre.append(BEHAVIOR_MITRE_MAP["new_swift_resource"])
            else:
                rule_score += 0.10
                flags.append("new_resource")

        # Check 5: Failed Access Spike
        failed = int(event.get("failed_attempts_prior_1h", 0))
        if failed >= 10:
            rule_score += 0.35
            flags.append("failed_access_spike")
            mitre.append(BEHAVIOR_MITRE_MAP["failed_access_spike"])
        elif failed >= 5:
            rule_score += 0.20
            flags.append("failed_access_elevated")
            mitre.append(BEHAVIOR_MITRE_MAP["failed_access_elevated"])

        # Check 6: SWIFT Segment Off-Hours Access
        # NRB SWIFT CSP: any SWIFT activity outside business hours = immediate alert
        segment = self.hostname_to_segment.get(hostname, "")
        if segment == "SWIFT" and is_off_hours in (True, "True", 1, "1"):
            rule_score = max(rule_score, 0.90)
            if "swift_off_hours" not in flags:
                flags.append("swift_off_hours")
                mitre.append(BEHAVIOR_MITRE_MAP["swift_off_hours"])

        #Check 7: Pumori Database Unauthorized Access (CRITICAL OVERRIDE)
        # Paper §6.3: "Any process not on the whitelist that queries Pumori
        #  is flagged as Critical immediately, regardless of query volume."
        if "pumori" in resource:
            if username not in self.pumori_whitelist:
                # CRITICAL: Immediate override to maximum score
                all_flags = ["unauthorized_pumori"] + flags
                all_mitre = [BEHAVIOR_MITRE_MAP["unauthorized_pumori"]] + mitre
                return 1.0, all_flags, all_mitre

        # Check 8: High-Risk Event Types
        if event_type in ("USB_INSERT", "SOFTWARE_INSTALL", "PRIVILEGE_USE"):
            risk = EVENT_TYPE_RISK.get(event_type, 0.05)
            rule_score += risk
            if event_type == "PRIVILEGE_USE":
                flags.append("privilege_abuse")
                mitre.append(BEHAVIOR_MITRE_MAP["privilege_abuse"])

        # Check 9: Honeypot Contact
        source_ip = str(event.get("source_ip", ""))
        if source_ip in self.honeypot_ips:
            # Any activity from a honeypot IP is guaranteed suspicious
            rule_score = max(rule_score, 0.95)
            flags.append("honeypot_contact")

        return min(rule_score, 1.0), flags, mitre

    def score_event(self, event, features_row=None):
        # Layer 1: ML Brain
        ml_score = 0.0
        if self.is_fitted and features_row is not None:
            ml_score = self._ml_score(features_row)

        # Layer 2: Security Guard
        rule_score, flags, mitre = self._rule_checks(event)

        # Hybrid combination: take the maximum
        final_score = max(ml_score, rule_score)

        # If ML score is high but rules didn't fire strongly, note it
        if ml_score > 0.65 and rule_score < 0.50:
            flags.append("ml_anomaly")
            mitre.append(BEHAVIOR_MITRE_MAP["ml_anomaly"])

        # Build entity identifier and resolve source_ip
        hostname = str(event.get("hostname", "unknown"))
        username = str(event.get("username", "unknown"))
        source_ip = str(event.get("source_ip", ""))
        if not source_ip:
            source_ip = self.hostname_to_ip.get(hostname, "")

        return {
            "entity": f"{username}@{hostname}",
            "agent": "behavior",
            "score": round(min(final_score, 1.0), 4),
            "ml_score": round(ml_score, 4),
            "rule_score": round(min(rule_score, 1.0), 4),
            "flags": flags,
            "mitre": mitre,
            "source_ip": source_ip,
            "username": username,
            "hostname": hostname,
            "timestamp": str(event.get("timestamp", "")),
        }

    def score_batch(self, ueba_df):
        print(f"    [BehaviorAgent] Scoring {len(ueba_df):,} events...")

        # Pre-compute all features in one pass (vectorized, fast)
        features = self._prepare_features(ueba_df)

        results = []
        for idx in ueba_df.index:
            event = ueba_df.loc[idx].to_dict()
            features_row = features.loc[idx]
            result = self.score_event(event, features_row)
            results.append(result)

            # Update user profile with this event
            username = str(event.get("username", "unknown")).lower()
            profile = self.user_profiles[username]
            profile["bytes_history"].append(int(event.get("bytes_transferred", 0)))
            profile["peer_scores"].append(float(event.get("peer_group_deviation_score", 0)))
            profile["event_count"] += 1

        # Print scoring summary
        scores = [r["score"] for r in results]
        n_flagged = sum(1 for s in scores if s >= 0.65)
        print(f"    [BehaviorAgent] Scoring complete:")
        print(f"      Mean score  : {np.mean(scores):.4f}")
        print(f"      Max score   : {np.max(scores):.4f}")
        print(f"      Flagged     : {n_flagged:,} events (score >= 0.65)")

        return results
    
    def aggregate_by_ip(self, results):
        ip_data = defaultdict(lambda: {
            "behavior_score": 0.0,
            "is_behavior_anomaly": 0,
            "all_flags": set(),
            "event_count": 0,
        })

        for r in results:
            ip = r["source_ip"]
            if not ip:
                continue
            data = ip_data[ip]
            data["behavior_score"] = max(data["behavior_score"], r["score"])
            data["event_count"] += 1
            data["all_flags"].update(r["flags"])
            if r["score"] >= 0.65:
                data["is_behavior_anomaly"] = 1

        rows = []
        for ip, data in ip_data.items():
            flags = data["all_flags"]
            rows.append({
                "source_ip": ip,
                "behavior_score": round(data["behavior_score"], 4),
                "is_behavior_anomaly": data["is_behavior_anomaly"],
                "ind_off_hours": 1 if ("off_hours" in flags or
                                       "swift_off_hours" in flags or
                                       "weekend_early_morning" in flags) else 0,
                "ind_high_deviation": 1 if ("high_peer_deviation" in flags or
                                            "elevated_peer_deviation" in flags) else 0,
                "ind_large_transfer": 1 if "large_data_transfer" in flags else 0,
                "ind_unauthorized_db": 1 if "unauthorized_pumori" in flags else 0,
                "ind_swift_access": 1 if ("swift_off_hours" in flags or
                                          "new_swift_resource" in flags) else 0,
                "behavior_event_count": data["event_count"],
            })

        output_df = pd.DataFrame(rows)
        if not output_df.empty:
            output_df = output_df.sort_values("behavior_score", ascending=False)

        print(f"    [BehaviorAgent] Aggregated to {len(output_df)} unique source IPs")
        n_anomalous = (output_df["is_behavior_anomaly"] == 1).sum() if not output_df.empty else 0
        print(f"    [BehaviorAgent] Anomalous IPs: {n_anomalous}")

        return output_df.reset_index(drop=True)
