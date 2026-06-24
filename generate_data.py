"""
Synthetic network security log generator.
Creates a realistic dataset of network traffic / intrusion events for analysis.
"""
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

np.random.seed(42)

N = 8000

attack_types = ["Normal", "DDoS", "Port Scan", "Brute Force", "Malware", "Phishing", "SQL Injection"]
attack_weights = [0.55, 0.12, 0.12, 0.08, 0.06, 0.04, 0.03]

protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS"]
protocol_weights = [0.35, 0.20, 0.10, 0.15, 0.20]

countries = ["India", "USA", "China", "Russia", "Germany", "Brazil", "UK", "Netherlands", "Vietnam", "Nigeria"]
country_weights = [0.22, 0.18, 0.14, 0.12, 0.08, 0.06, 0.06, 0.06, 0.04, 0.04]

severity_map = {
    "Normal": "Low", "DDoS": "High", "Port Scan": "Medium", "Brute Force": "High",
    "Malware": "Critical", "Phishing": "Medium", "SQL Injection": "Critical"
}

start_time = datetime(2026, 1, 1)

rows = []
for i in range(N):
    ts = start_time + timedelta(minutes=int(np.random.exponential(scale=180) * i / N * 500))
    attack = np.random.choice(attack_types, p=attack_weights)
    protocol = np.random.choice(protocols, p=protocol_weights)
    country = np.random.choice(countries, p=country_weights)
    src_ip = f"{np.random.randint(1,223)}.{np.random.randint(0,255)}.{np.random.randint(0,255)}.{np.random.randint(0,255)}"
    dst_ip = f"10.0.{np.random.randint(0,20)}.{np.random.randint(1,255)}"
    port = int(np.random.choice([22, 80, 443, 21, 3389, 8080, 53, 25, 3306, np.random.randint(1024, 65535)]))
    bytes_transferred = int(np.random.lognormal(mean=7, sigma=1.8))
    duration = round(np.random.exponential(scale=4.5), 2)
    failed_logins = np.random.poisson(0.4) if attack == "Brute Force" else np.random.poisson(0.05)
    is_attack = 0 if attack == "Normal" else 1
    severity = severity_map[attack]
    blocked = 1 if (is_attack and np.random.rand() < 0.78) else 0

    rows.append([
        ts, src_ip, dst_ip, port, protocol, attack, severity,
        bytes_transferred, duration, failed_logins, country, is_attack, blocked
    ])

df = pd.DataFrame(rows, columns=[
    "timestamp", "source_ip", "dest_ip", "dest_port", "protocol", "attack_type",
    "severity", "bytes_transferred", "session_duration_sec", "failed_logins",
    "source_country", "is_attack", "blocked"
])

df = df.sort_values("timestamp").reset_index(drop=True)
df.to_csv("/home/claude/cyber-security-analytics/data/network_security_logs.csv", index=False)
print(f"Generated {len(df)} rows")
print(df.head())
print(df["attack_type"].value_counts())
