-- ============================================================
-- Cyber Security Analytics: SQL Queries
-- Dataset: network_security_logs.csv (loaded into table `logs`)
-- ============================================================

-- 1. Total events and overall attack rate
SELECT
    COUNT(*) AS total_events,
    SUM(is_attack) AS total_attacks,
    ROUND(100.0 * SUM(is_attack) / COUNT(*), 2) AS attack_rate_pct
FROM logs;

-- 2. Breakdown of events by attack type, ordered by frequency
SELECT
    attack_type,
    COUNT(*) AS event_count,
    ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM logs), 2) AS pct_of_total
FROM logs
GROUP BY attack_type
ORDER BY event_count DESC;

-- 3. Firewall block rate per attack type
SELECT
    attack_type,
    COUNT(*) AS total,
    SUM(blocked) AS blocked_count,
    ROUND(100.0 * SUM(blocked) / COUNT(*), 2) AS block_rate_pct
FROM logs
WHERE is_attack = 1
GROUP BY attack_type
ORDER BY block_rate_pct ASC;          -- lowest block rate = highest risk

-- 4. Top 10 source countries generating attack traffic
SELECT
    source_country,
    COUNT(*) AS attack_count
FROM logs
WHERE is_attack = 1
GROUP BY source_country
ORDER BY attack_count DESC
LIMIT 10;

-- 5. Hourly attack volume (identify peak attack windows)
SELECT
    CAST(strftime('%H', timestamp) AS INTEGER) AS hour_of_day,
    COUNT(*) AS attack_count
FROM logs
WHERE is_attack = 1
GROUP BY hour_of_day
ORDER BY hour_of_day;

-- 6. Critical severity events that were NOT blocked (highest priority for review)
SELECT
    timestamp, source_ip, dest_ip, dest_port, attack_type, source_country
FROM logs
WHERE severity = 'Critical' AND blocked = 0
ORDER BY timestamp DESC;

-- 7. Brute force attempts with high failed login counts
SELECT
    source_ip, dest_ip, failed_logins, timestamp
FROM logs
WHERE attack_type = 'Brute Force' AND failed_logins >= 1
ORDER BY failed_logins DESC;

-- 8. Average bytes transferred and session duration by attack type
SELECT
    attack_type,
    ROUND(AVG(bytes_transferred), 0) AS avg_bytes,
    ROUND(AVG(session_duration_sec), 2) AS avg_duration_sec
FROM logs
GROUP BY attack_type
ORDER BY avg_bytes DESC;

-- 9. Daily attack trend (for time-series charting)
SELECT
    DATE(timestamp) AS day,
    SUM(is_attack) AS attacks,
    COUNT(*) AS total_events
FROM logs
GROUP BY day
ORDER BY day;

-- 10. Protocols most associated with attack traffic
SELECT
    protocol,
    SUM(is_attack) AS attack_count,
    COUNT(*) AS total_count,
    ROUND(100.0 * SUM(is_attack) / COUNT(*), 2) AS attack_share_pct
FROM logs
GROUP BY protocol
ORDER BY attack_count DESC;
