# Cyber Security Analytics — Network Threat Detection & Insights

A data analytics project that analyzes network security event logs to identify attack patterns, threat sources, and firewall effectiveness using **Python (EDA)**, **SQL**, and **Power BI**.

## Project Overview
This project simulates a Security Operations Center (SOC) analyst workflow: ingesting raw network event logs, exploring them with Python, querying them with SQL, and visualizing key threat metrics in an interactive Power BI dashboard.

## Dataset
`data/network_security_logs.csv` — 8,000 simulated network events with fields:

| Column | Description |
|---|---|
| timestamp | Event date/time |
| source_ip / dest_ip | Source and destination IP addresses |
| dest_port | Destination port |
| protocol | TCP / UDP / ICMP / HTTP / HTTPS |
| attack_type | Normal, DDoS, Port Scan, Brute Force, Malware, Phishing, SQL Injection |
| severity | Low / Medium / High / Critical |
| bytes_transferred | Bytes transferred in the session |
| session_duration_sec | Session duration in seconds |
| failed_logins | Count of failed login attempts |
| source_country | Country of origin |
| is_attack | 1 if malicious, 0 if normal traffic |
| blocked | 1 if the firewall blocked the event |

> Data is synthetically generated (`data/generate_data.py`) to resemble realistic SOC traffic patterns and class imbalance, since real intrusion datasets often carry licensing/privacy restrictions.

## Key Findings
- **45.5%** of all logged events were classified as malicious traffic
- **Port Scan** and **DDoS** were the most frequent attack types
- The firewall successfully blocked **78.6%** of detected attacks — leaving ~21% requiring manual review
- Attack volume **peaks around 3 PM**, suggesting threat actors may target business hours for cover
- **India, USA, and China** were the top three source countries for attack traffic in this dataset
- **669 critical-severity events** were recorded, some of which were not blocked — these are flagged in the SQL queries for prioritized review

## Tech Stack
- **Python**: pandas, numpy, matplotlib, seaborn — data generation & EDA
- **SQL**: SQLite — 10 analytical queries covering attack trends, block rates, and risk prioritization
- **Power BI**: 3-page interactive dashboard (Executive Overview, Threat Intelligence, Operational Detail)

## Repository Structure
```
cyber-security-analytics/
├── data/
│   ├── generate_data.py            # synthetic data generator
│   └── network_security_logs.csv   # dataset (8,000 rows)
├── notebooks/
│   └── eda_analysis.py             # Python EDA & chart generation
├── sql/
│   ├── analysis_queries.sql        # 10 SQL queries
│   ├── load_to_sqlite.py           # loads CSV into SQLite for querying
│   └── logs.db                     # SQLite database
├── powerbi/
│   ├── network_security_logs_powerbi.csv
│   └── POWERBI_GUIDE.md            # step-by-step dashboard build guide
├── visuals/
│   ├── 01_attack_type_distribution.png
│   ├── 02_severity_distribution.png
│   ├── 03_attacks_by_hour.png
│   ├── 04_top_attack_countries.png
│   ├── 05_blocked_vs_allowed.png
│   ├── 06_protocol_usage.png
│   └── summary_stats.json
└── README.md
```

## How to Run
```bash
# 1. Generate the dataset
python data/generate_data.py

# 2. Run the EDA and generate charts
python notebooks/eda_analysis.py

# 3. Load into SQLite and run SQL queries
python sql/load_to_sqlite.py
sqlite3 sql/logs.db < sql/analysis_queries.sql

# 4. Open powerbi/network_security_logs_powerbi.csv in Power BI Desktop
#    and follow powerbi/POWERBI_GUIDE.md
```

## Sample Visualization
![Attack Type Distribution](visuals/01_attack_type_distribution.png)

---
**Author**: Priyanshu Mishra | [GitHub](https://github.com/its-priyanshupm) | [LinkedIn](https://www.linkedin.com/in/priyanshu-poddar-a69ba3243/)
