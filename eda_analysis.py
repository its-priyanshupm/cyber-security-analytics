"""
Exploratory Data Analysis - Network Security Logs
Cyber Security Analytics Project
"""
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

sns.set_style("whitegrid")
plt.rcParams["figure.dpi"] = 110

df = pd.read_csv("/home/claude/cyber-security-analytics/data/network_security_logs.csv", parse_dates=["timestamp"])
df["hour"] = df["timestamp"].dt.hour
df["date"] = df["timestamp"].dt.date

OUT = "/home/claude/cyber-security-analytics/visuals"

# 1. Attack type distribution
plt.figure(figsize=(8, 5))
order = df["attack_type"].value_counts().index
sns.countplot(data=df, y="attack_type", order=order, hue="attack_type", palette="rocket", legend=False)
plt.title("Network Events by Attack Type")
plt.xlabel("Count")
plt.ylabel("")
plt.tight_layout()
plt.savefig(f"{OUT}/01_attack_type_distribution.png")
plt.close()

# 2. Severity breakdown
plt.figure(figsize=(6, 6))
sev_order = ["Low", "Medium", "High", "Critical"]
sev_counts = df["severity"].value_counts().reindex(sev_order)
colors = ["#4CAF50", "#FFC107", "#FF7043", "#C62828"]
plt.pie(sev_counts, labels=sev_counts.index, autopct="%1.1f%%", colors=colors, startangle=90)
plt.title("Severity Level Distribution")
plt.tight_layout()
plt.savefig(f"{OUT}/02_severity_distribution.png")
plt.close()

# 3. Attacks by hour of day
plt.figure(figsize=(9, 5))
hourly_attacks = df[df["is_attack"] == 1].groupby("hour").size()
sns.lineplot(x=hourly_attacks.index, y=hourly_attacks.values, marker="o", color="#C62828")
plt.title("Attack Volume by Hour of Day")
plt.xlabel("Hour (24h)")
plt.ylabel("Number of Attacks")
plt.xticks(range(0, 24))
plt.tight_layout()
plt.savefig(f"{OUT}/03_attacks_by_hour.png")
plt.close()

# 4. Top source countries for attacks
plt.figure(figsize=(8, 5))
top_countries = df[df["is_attack"] == 1]["source_country"].value_counts().head(8)
sns.barplot(x=top_countries.values, y=top_countries.index, hue=top_countries.index, palette="mako", legend=False)
plt.title("Top Source Countries for Attack Traffic")
plt.xlabel("Number of Attacks")
plt.ylabel("")
plt.tight_layout()
plt.savefig(f"{OUT}/04_top_attack_countries.png")
plt.close()

# 5. Blocked vs Allowed attacks
plt.figure(figsize=(6, 5))
blocked_counts = df[df["is_attack"] == 1]["blocked"].map({1: "Blocked", 0: "Not Blocked"}).value_counts()
sns.barplot(x=blocked_counts.index, y=blocked_counts.values, hue=blocked_counts.index,
            palette=["#2E7D32", "#C62828"], legend=False)
plt.title("Firewall Response to Detected Attacks")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig(f"{OUT}/05_blocked_vs_allowed.png")
plt.close()

# 6. Protocol usage in attacks
plt.figure(figsize=(7, 5))
protocol_attack = df[df["is_attack"] == 1]["protocol"].value_counts()
sns.barplot(x=protocol_attack.index, y=protocol_attack.values, hue=protocol_attack.index, palette="flare", legend=False)
plt.title("Protocols Used in Attack Traffic")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig(f"{OUT}/06_protocol_usage.png")
plt.close()

# Summary stats for README
summary = {
    "total_events": len(df),
    "total_attacks": int(df["is_attack"].sum()),
    "attack_rate_pct": round(df["is_attack"].mean() * 100, 2),
    "block_rate_pct": round(df[df["is_attack"] == 1]["blocked"].mean() * 100, 2),
    "most_common_attack": df[df["is_attack"] == 1]["attack_type"].value_counts().idxmax(),
    "peak_attack_hour": int(hourly_attacks.idxmax()),
    "top_attack_country": top_countries.idxmax(),
    "critical_events": int((df["severity"] == "Critical").sum()),
}

print("=== Summary Statistics ===")
for k, v in summary.items():
    print(f"{k}: {v}")

import json
with open("/home/claude/cyber-security-analytics/visuals/summary_stats.json", "w") as f:
    json.dump(summary, f, indent=2)
