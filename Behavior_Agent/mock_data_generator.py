
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import os

RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)
random.seed(RANDOM_SEED)

# Time range: Jan 2025 to Jun 2026 (18 months, matching data dictionary)
START_DATE = datetime(2025, 1, 1)
END_DATE = datetime(2026, 6, 30)

# Event types from data dictionary §3.4
EVENT_TYPES = [
    "FILE_ACCESS", "DB_QUERY", "EMAIL_SEND", "SHARE_ACCESS",
    "PRINT", "REMOTE_LOGIN", "PRIVILEGE_USE", "SOFTWARE_INSTALL",
    "USB_INSERT", "LARGE_DOWNLOAD",
]

# Normal event type distribution (weighted — DB_QUERY and FILE_ACCESS dominate)
NORMAL_EVENT_WEIGHTS = [0.25, 0.25, 0.15, 0.10, 0.05, 0.08, 0.03, 0.02, 0.02, 0.05]

# Anomaly types from data dictionary
ANOMALY_TYPES = [
    "UNUSUAL_HOURS", "LARGE_DATA_TRANSFER", "NEW_RESOURCE",
    "PRIVILEGE_ABUSE", "SWIFT_ACCESS",
]

# Common Nepali names for realistic usernames
FIRST_NAMES = [
    "ram", "sita", "hari", "gita", "krishna", "laxmi", "bishnu", "sarita",
    "rajesh", "anita", "suresh", "kamala", "deepak", "sunita", "prakash",
    "mina", "rajan", "puja", "arun", "bindu", "nabin", "rita", "sunil",
    "rekha", "bikash", "sanju", "roshan", "nisha", "kiran", "maya",
]

LAST_NAMES = [
    "shrestha", "sharma", "adhikari", "thapa", "gurung", "tamang",
    "rai", "magar", "poudel", "bhattarai", "khadka", "bhandari",
    "pandey", "basnet", "karki", "koirala", "joshi", "regmi",
]

# Resources that users access
NORMAL_RESOURCES = [
    "customer_records", "transaction_logs", "account_statements",
    "loan_applications", "kyc_documents", "branch_reports",
    "hr_payroll", "email_server", "shared_drive_finance",
    "shared_drive_operations", "intranet_portal", "attendance_system",
]

SENSITIVE_RESOURCES = [
    "pumori_customer_table", "pumori_loan_table", "pumori_transaction_db",
    "SWIFT_MT103_outgoing", "SWIFT_MT202_cover", "SWIFT_MT940_statements",
    "ad_admin_console", "firewall_config", "backup_vault",
]

# Departments
DEPARTMENTS = [
    "retail_banking", "corporate_banking", "treasury", "it_operations",
    "compliance", "hr", "finance", "risk_management",
]

def generate_host_profiles():
    """
    Generate a realistic host_profiles.csv matching data dictionary §3.5.
    Covers all 5 network segments with proper IP ranges from §6.
    """
    hosts = []

    # ── CORE_BANKING segment (10.10.x.x, 10.20.x.x) ──
    core_hosts = [
        ("SRV-DC-01",  "10.10.1.10", "SERVER", "Windows Server 2019", "10.0.17763", "CRITICAL", "it_operations"),
        ("SRV-DC-02",  "10.10.1.11", "SERVER", "Windows Server 2019", "10.0.17763", "CRITICAL", "it_operations"),
        ("SRV-SQL-01", "10.10.2.10", "SERVER", "Windows Server 2019", "10.0.17763", "CRITICAL", "it_operations"),
        ("SRV-SQL-02", "10.10.2.11", "SERVER", "Windows Server 2019", "10.0.17763", "CRITICAL", "it_operations"),
        ("SRV-APP-01", "10.10.3.10", "SERVER", "Windows Server 2022", "10.0.20348", "HIGH",     "it_operations"),
        ("SRV-FILE-01","10.20.0.10", "SERVER", "Windows Server 2019", "10.0.17763", "HIGH",     "it_operations"),
    ]
    for h, ip, ht, os_name, os_ver, crit, dept in core_hosts:
        hosts.append(_host_row(h, ip, ht, os_name, os_ver, "CORE_BANKING", crit, dept, "current"))

    # ── SWIFT segment (10.30.x.x) ──
    swift_hosts = [
        ("SWIFT-GW-01", "10.30.1.10", "SWIFT_GATEWAY", "Windows Server 2019", "10.0.17763", "CRITICAL", "treasury"),
        ("SWIFT-GW-02", "10.30.1.11", "SWIFT_GATEWAY", "Windows Server 2019", "10.0.17763", "CRITICAL", "treasury"),
        ("SWIFT-GW-03", "10.30.2.10", "SWIFT_GATEWAY", "Windows Server 2019", "10.0.17763", "CRITICAL", "treasury"),
    ]
    for h, ip, ht, os_name, os_ver, crit, dept in swift_hosts:
        hosts.append(_host_row(h, ip, ht, os_name, os_ver, "SWIFT", crit, dept, "current"))

    # ── ATM segment (10.40.x.x) ──
    atm_cities = [("KTM", 5), ("PKR", 3), ("BTW", 2)]
    atm_counter = 1
    for city, count in atm_cities:
        for i in range(1, count + 1):
            hostname = f"ATM-{city}-{atm_counter:03d}"
            ip = f"10.40.0.{atm_counter + 10}"
            patch = random.choice(["current", "1_month_behind", "3_months_behind"])
            hosts.append(_host_row(hostname, ip, "ATM", "Windows 10 IoT", "10.0.19041",
                                   "ATM", "CRITICAL", "retail_banking", patch))
            atm_counter += 1

    # ── WORKSTATION segment (192.168.x.x) ──
    ws_counter = 1
    for city, count in [("KTM", 8), ("PKR", 4), ("BTW", 3)]:
        subnet = {"KTM": "192.168.1", "PKR": "192.168.2", "BTW": "192.168.10"}[city]
        for i in range(1, count + 1):
            hostname = f"WS-{city}-{ws_counter:03d}"
            ip = f"{subnet}.{ws_counter + 10}"
            dept = random.choice(["retail_banking", "corporate_banking", "finance", "hr", "compliance"])
            patch = random.choice(["current", "current", "1_month_behind", "3_months_behind"])
            hosts.append(_host_row(hostname, ip, "WORKSTATION", "Windows 11", "10.0.22621",
                                   "WORKSTATION", "MEDIUM", dept, patch))
            ws_counter += 1

    # ── DMZ segment (172.16.x.x) ──
    dmz_hosts = [
        ("SRV-PROXY-01", "172.16.0.10", "SERVER", "Ubuntu 22.04", "22.04", "MEDIUM", "it_operations"),
        ("SRV-PROXY-02", "172.16.0.11", "SERVER", "Ubuntu 22.04", "22.04", "MEDIUM", "it_operations"),
    ]
    for h, ip, ht, os_name, os_ver, crit, dept in dmz_hosts:
        hosts.append(_host_row(h, ip, ht, os_name, os_ver, "DMZ", crit, dept, "current"))

    # Add one honeypot (data dictionary says ~2% of hosts)
    hosts.append(_host_row("WS-KTM-099", "192.168.1.99", "WORKSTATION", "Windows 10", "10.0.19041",
                           "WORKSTATION", "LOW", "it_operations", "6_months_behind", is_honeypot=True))

    df = pd.DataFrame(hosts)
    return df


def _host_row(hostname, ip, host_type, os_name, os_version, segment,
              criticality, department, patch_level, is_honeypot=False):
    """Build a single host profile row matching data dictionary §3.5."""
    mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
    first_seen = START_DATE + timedelta(days=random.randint(0, 30))
    last_seen = END_DATE - timedelta(days=random.randint(0, 10))

    # Generate some open ports based on host type
    port_map = {
        "SERVER":        [22, 80, 443, 3389, 445, 1433],
        "SWIFT_GATEWAY": [443, 1433, 8443],
        "ATM":           [443, 8080],
        "WORKSTATION":   [135, 445, 3389],
    }
    open_ports = ",".join(str(p) for p in port_map.get(host_type, [135, 445]))
    services = "sshd,httpd" if host_type == "SERVER" else "winrm,smb"

    is_vuln = random.random() < 0.15  # 15% of hosts have a known vulnerability
    cve_list = "CVE-2024-21410|CVE-2023-36884" if is_vuln else ""

    return {
        "hostname": hostname,
        "ip_address": ip,
        "mac_address": mac,
        "host_type": host_type,
        "os": os_name,
        "os_version": os_version,
        "segment": segment,
        "criticality": criticality,
        "department": department,
        "patch_level": patch_level,
        "last_seen": last_seen.strftime("%Y-%m-%d %H:%M:%S"),
        "first_seen": first_seen.strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports": open_ports,
        "running_services": services,
        "is_known_vulnerable": is_vuln,
        "cve_list": cve_list,
        "is_honeypot": is_honeypot,
    }

def generate_ueba_events(host_profiles_df, n_normal=1200, n_attack=100):
    
    events = []

    # Build user roster (assign users to workstations)
    workstations = host_profiles_df[host_profiles_df["host_type"] == "WORKSTATION"]
    users = _generate_user_roster(workstations)

    # Service accounts (legitimate Pumori access)
    service_accounts = [
        {"username": "srv_pumori_app", "hostname": "SRV-APP-01", "department": "it_operations"},
        {"username": "pumori_batch",   "hostname": "SRV-SQL-01", "department": "it_operations"},
        {"username": "admin_db_sync",  "hostname": "SRV-SQL-02", "department": "it_operations"},
    ]

    # ── Generate normal events ──
    event_counter = 1
    for i in range(n_normal):
        user = random.choice(users)
        event = _normal_event(user, host_profiles_df, event_counter)
        events.append(event)
        event_counter += 1

    # ── Generate legitimate service account events ──
    for i in range(50):
        svc = random.choice(service_accounts)
        event = _service_account_event(svc, host_profiles_df, event_counter)
        events.append(event)
        event_counter += 1

    # ── Generate legitimate off-hours events (~6% as per data dictionary) ──
    for i in range(int(n_normal * 0.06)):
        user = random.choice(users)
        event = _legitimate_off_hours_event(user, host_profiles_df, event_counter)
        events.append(event)
        event_counter += 1

    # ── ATTACK SCENARIO 1: Saturday 3:18 AM data exfiltration ──
    # The main GIBL scenario — a compromised teller account at 3 AM
    attacker_user = {"username": "ram.shrestha", "hostname": "WS-KTM-001",
                     "department": "retail_banking", "role": "teller"}
    for i in range(15):
        event = _saturday_attack_event(attacker_user, host_profiles_df, event_counter, i)
        events.append(event)
        event_counter += 1

    # ── ATTACK SCENARIO 2: SWIFT off-hours unauthorized access ──
    swift_attacker = {"username": "rajesh.pandey", "hostname": "SWIFT-GW-01",
                      "department": "treasury", "role": "officer"}
    for i in range(10):
        event = _swift_attack_event(swift_attacker, host_profiles_df, event_counter, i)
        events.append(event)
        event_counter += 1

    # ── ATTACK SCENARIO 3: Pumori unauthorized queries ──
    pumori_attacker = {"username": "sunil.karki", "hostname": "WS-KTM-005",
                       "department": "retail_banking", "role": "teller"}
    for i in range(8):
        event = _pumori_attack_event(pumori_attacker, host_profiles_df, event_counter, i)
        events.append(event)
        event_counter += 1

    # ── ATTACK SCENARIO 4: Insider threat (elevated peer deviation) ──
    insider = {"username": "deepak.bhattarai", "hostname": "WS-KTM-003",
               "department": "corporate_banking", "role": "manager"}
    for i in range(12):
        event = _insider_threat_event(insider, host_profiles_df, event_counter, i)
        events.append(event)
        event_counter += 1

    # ── ATTACK SCENARIO 5: Brute force (failed login spikes) ──
    brute_target = {"username": "admin.operations", "hostname": "SRV-DC-01",
                    "department": "it_operations", "role": "admin"}
    for i in range(10):
        event = _brute_force_event(brute_target, host_profiles_df, event_counter, i)
        events.append(event)
        event_counter += 1

    df = pd.DataFrame(events)

    # Shuffle so attacks are not grouped together
    df = df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

    return df

def _generate_user_roster(workstations_df):
    """Create a roster of users assigned to workstations."""
    users = []
    used_names = set()
    for _, ws in workstations_df.iterrows():
        first = random.choice(FIRST_NAMES)
        last = random.choice(LAST_NAMES)
        username = f"{first}.{last}"
        # Ensure unique usernames
        while username in used_names:
            first = random.choice(FIRST_NAMES)
            last = random.choice(LAST_NAMES)
            username = f"{first}.{last}"
        used_names.add(username)
        users.append({
            "username": username,
            "hostname": ws["hostname"],
            "department": ws.get("department", "retail_banking"),
            "role": random.choice(["teller", "officer", "manager"]),
        })
    return users


def _get_ip(hostname, host_profiles_df):
    """Look up the IP address for a given hostname."""
    match = host_profiles_df[host_profiles_df["hostname"] == hostname]
    if not match.empty:
        return match.iloc[0]["ip_address"]
    return "192.168.1.100"  # fallback


def _random_business_timestamp():
    """Generate a random timestamp during business hours (08:00-18:00 NPT, weekday)."""
    days = (END_DATE - START_DATE).days
    day = START_DATE + timedelta(days=random.randint(0, days))
    # Skip weekends
    while day.weekday() >= 5:  # 5=Saturday, 6=Sunday
        day += timedelta(days=1)
    hour = random.randint(8, 17)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ms = random.randint(0, 999)
    return day.replace(hour=hour, minute=minute, second=second,
                       microsecond=ms * 1000)


def _make_event_id(counter):
    """Generate UE-XXXXXXXXXX format event ID."""
    return f"UE-{counter:010X}"


def _normal_event(user, host_profiles_df, counter):
    """Generate a single normal business-hours UEBA event."""
    ts = _random_business_timestamp()
    event_type = random.choices(EVENT_TYPES, weights=NORMAL_EVENT_WEIGHTS, k=1)[0]
    resource = random.choice(NORMAL_RESOURCES)

    return {
        "event_id": _make_event_id(counter),
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "username": user["username"],
        "hostname": user["hostname"],
        "event_type": event_type,
        "resource_accessed": resource,
        "bytes_transferred": int(np.random.lognormal(mean=12, sigma=2)),  # ~100KB median
        "duration_sec": round(np.random.exponential(scale=30) + 1, 2),
        "source_ip": _get_ip(user["hostname"], host_profiles_df),
        "is_off_hours": False,
        "is_new_resource": random.random() < 0.05,  # 5% chance
        "failed_attempts_prior_1h": 0,
        "peer_group_deviation_score": round(np.random.beta(2, 10), 4),  # skewed low (mostly < 0.3)
        "is_anomaly": False,
        "anomaly_type": "",
        "mitre_technique": "",
    }


def _service_account_event(svc, host_profiles_df, counter):
    """Generate a legitimate service account event (Pumori DB access)."""
    ts = _random_business_timestamp()
    return {
        "event_id": _make_event_id(counter),
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "username": svc["username"],
        "hostname": svc["hostname"],
        "event_type": "DB_QUERY",
        "resource_accessed": random.choice(["pumori_customer_table", "pumori_transaction_db"]),
        "bytes_transferred": int(np.random.lognormal(mean=14, sigma=1)),  # ~1MB
        "duration_sec": round(np.random.exponential(scale=5) + 0.5, 2),
        "source_ip": _get_ip(svc["hostname"], host_profiles_df),
        "is_off_hours": False,
        "is_new_resource": False,
        "failed_attempts_prior_1h": 0,
        "peer_group_deviation_score": round(np.random.beta(2, 20), 4),  # very low deviation
        "is_anomaly": False,
        "anomaly_type": "",
        "mitre_technique": "",
    }


def _legitimate_off_hours_event(user, host_profiles_df, counter):
    """Generate a legitimate off-hours event (batch job or on-call, ~6% of dataset)."""
    days = (END_DATE - START_DATE).days
    day = START_DATE + timedelta(days=random.randint(0, days))
    hour = random.choice([6, 7, 19, 20, 21])  # early morning or late evening
    ts = day.replace(hour=hour, minute=random.randint(0, 59),
                     second=random.randint(0, 59), microsecond=random.randint(0, 999) * 1000)
    return {
        "event_id": _make_event_id(counter),
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "username": user["username"],
        "hostname": user["hostname"],
        "event_type": random.choice(["FILE_ACCESS", "DB_QUERY", "EMAIL_SEND"]),
        "resource_accessed": random.choice(NORMAL_RESOURCES),
        "bytes_transferred": int(np.random.lognormal(mean=12, sigma=2)),
        "duration_sec": round(np.random.exponential(scale=20) + 1, 2),
        "source_ip": _get_ip(user["hostname"], host_profiles_df),
        "is_off_hours": True,
        "is_new_resource": False,
        "failed_attempts_prior_1h": 0,
        "peer_group_deviation_score": round(np.random.beta(3, 8), 4),  # slightly higher but still normal
        "is_anomaly": False,
        "anomaly_type": "",
        "mitre_technique": "",
    }


# ── Attack Scenario Generators ──

def _saturday_attack_event(user, host_profiles_df, counter, seq):
    """
    Saturday 3:18 AM data exfiltration — the main GIBL attack scenario.
    A compromised teller account queries the Pumori database at 3 AM on a Saturday
    and transfers 400 MB of customer data.
    """
    # All events clustered around Saturday May 17, 2026, 03:00-04:00 AM
    base_time = datetime(2026, 5, 17, 3, 18, 0)  # Saturday 3:18 AM
    ts = base_time + timedelta(minutes=seq * 2, seconds=random.randint(0, 30))

    bytes_transferred = random.randint(50_000_000, 500_000_000)  # 50 MB to 500 MB

    return {
        "event_id": _make_event_id(counter),
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "username": user["username"],
        "hostname": user["hostname"],
        "event_type": random.choice(["DB_QUERY", "LARGE_DOWNLOAD", "FILE_ACCESS"]),
        "resource_accessed": random.choice(["pumori_customer_table", "pumori_loan_table",
                                            "customer_records"]),
        "bytes_transferred": bytes_transferred,
        "duration_sec": round(random.uniform(60, 300), 2),
        "source_ip": _get_ip(user["hostname"], host_profiles_df),
        "is_off_hours": True,
        "is_new_resource": seq == 0,  # first access is new
        "failed_attempts_prior_1h": 0,
        "peer_group_deviation_score": round(random.uniform(0.78, 0.95), 4),
        "is_anomaly": True,
        "anomaly_type": "LARGE_DATA_TRANSFER",
        "mitre_technique": "T1041",
    }


def _swift_attack_event(user, host_profiles_df, counter, seq):
    """SWIFT off-hours unauthorized access — accessing SWIFT gateway at night."""
    base_time = datetime(2026, 4, 12, 2, 30, 0)  # 2:30 AM
    ts = base_time + timedelta(minutes=seq * 3, seconds=random.randint(0, 59))

    return {
        "event_id": _make_event_id(counter),
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "username": user["username"],
        "hostname": user["hostname"],
        "event_type": random.choice(["DB_QUERY", "REMOTE_LOGIN", "PRIVILEGE_USE"]),
        "resource_accessed": random.choice(["SWIFT_MT103_outgoing", "SWIFT_MT202_cover",
                                            "SWIFT_MT940_statements"]),
        "bytes_transferred": random.randint(1_000, 50_000),
        "duration_sec": round(random.uniform(10, 120), 2),
        "source_ip": _get_ip(user["hostname"], host_profiles_df),
        "is_off_hours": True,
        "is_new_resource": seq < 2,
        "failed_attempts_prior_1h": random.randint(0, 2),
        "peer_group_deviation_score": round(random.uniform(0.70, 0.92), 4),
        "is_anomaly": True,
        "anomaly_type": "SWIFT_ACCESS",
        "mitre_technique": "T1021",
    }


def _pumori_attack_event(user, host_profiles_df, counter, seq):
    """Unauthorized Pumori database access by a non-whitelisted account."""
    ts = _random_business_timestamp()

    return {
        "event_id": _make_event_id(counter),
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "username": user["username"],
        "hostname": user["hostname"],
        "event_type": "DB_QUERY",
        "resource_accessed": random.choice(["pumori_customer_table", "pumori_loan_table",
                                            "pumori_transaction_db"]),
        "bytes_transferred": random.randint(5_000_000, 200_000_000),
        "duration_sec": round(random.uniform(5, 60), 2),
        "source_ip": _get_ip(user["hostname"], host_profiles_df),
        "is_off_hours": random.random() < 0.3,
        "is_new_resource": True,
        "failed_attempts_prior_1h": random.randint(0, 3),
        "peer_group_deviation_score": round(random.uniform(0.60, 0.85), 4),
        "is_anomaly": True,
        "anomaly_type": "PRIVILEGE_ABUSE",
        "mitre_technique": "T1005",
    }


def _insider_threat_event(user, host_profiles_df, counter, seq):
    """Insider threat — consistently elevated peer deviation scores."""
    ts = _random_business_timestamp()

    return {
        "event_id": _make_event_id(counter),
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "username": user["username"],
        "hostname": user["hostname"],
        "event_type": random.choice(["FILE_ACCESS", "SHARE_ACCESS", "LARGE_DOWNLOAD",
                                     "USB_INSERT", "EMAIL_SEND"]),
        "resource_accessed": random.choice(SENSITIVE_RESOURCES + NORMAL_RESOURCES),
        "bytes_transferred": random.randint(10_000_000, 150_000_000),
        "duration_sec": round(random.uniform(30, 600), 2),
        "source_ip": _get_ip(user["hostname"], host_profiles_df),
        "is_off_hours": random.random() < 0.4,
        "is_new_resource": random.random() < 0.3,
        "failed_attempts_prior_1h": 0,
        "peer_group_deviation_score": round(random.uniform(0.68, 0.92), 4),  # consistently high
        "is_anomaly": True,
        "anomaly_type": random.choice(["LARGE_DATA_TRANSFER", "NEW_RESOURCE"]),
        "mitre_technique": "T1078",
    }


def _brute_force_event(user, host_profiles_df, counter, seq):
    """Brute force attack — multiple failed login attempts."""
    base_time = datetime(2026, 3, 8, 14, 0, 0)
    ts = base_time + timedelta(minutes=seq, seconds=random.randint(0, 30))

    return {
        "event_id": _make_event_id(counter),
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "username": user["username"],
        "hostname": user["hostname"],
        "event_type": "REMOTE_LOGIN",
        "resource_accessed": "ad_admin_console",
        "bytes_transferred": random.randint(100, 5000),
        "duration_sec": round(random.uniform(0.5, 3), 2),
        "source_ip": _get_ip(user["hostname"], host_profiles_df),
        "is_off_hours": False,
        "is_new_resource": False,
        "failed_attempts_prior_1h": random.randint(8, 25),
        "peer_group_deviation_score": round(random.uniform(0.55, 0.80), 4),
        "is_anomaly": True,
        "anomaly_type": "PRIVILEGE_ABUSE",
        "mitre_technique": "T1110",
    }


def generate_all(output_dir=None):
    
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        ueba_path = os.path.join(output_dir, "ueba_mock_data.csv")
        host_path = os.path.join(output_dir, "host_profiles_mock.csv")
    else:
        ueba_path = "ueba_mock_data.csv"
        host_path = "host_profiles_mock.csv"

    print("=" * 60)
    print("  GIBL Mock Data Generator")
    print("=" * 60)

    # Step 1: Generate host profiles
    print("\n[1] Generating host profiles...")
    host_df = generate_host_profiles()
    host_df.to_csv(host_path, index=False)
    print(f"    -> {len(host_df)} hosts written to {host_path}")

    # Step 2: Generate UEBA events
    print("\n[2] Generating UEBA events...")
    ueba_df = generate_ueba_events(host_df, n_normal=1200, n_attack=100)
    ueba_df.to_csv(ueba_path, index=False)
    print(f"    -> {len(ueba_df)} events written to {ueba_path}")

    # Step 3: Summary
    n_anomaly = ueba_df["is_anomaly"].sum()
    n_normal = len(ueba_df) - n_anomaly
    print(f"\n    Normal events : {n_normal:,}")
    print(f"    Attack events : {n_anomaly:,}")
    print(f"    Attack rate   : {n_anomaly / len(ueba_df):.1%}")
    print(f"\n    Anomaly types:")
    for atype, count in ueba_df[ueba_df["is_anomaly"]]["anomaly_type"].value_counts().items():
        print(f"      {atype:<25} {count:>5}")

    print("\n" + "=" * 60)
    print("  Mock data generation complete!")
    print("=" * 60)

    return ueba_df, host_df


if __name__ == "__main__":
    generate_all()
