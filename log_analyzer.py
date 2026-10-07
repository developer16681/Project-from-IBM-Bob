"""
+==============================================================================+
|              AUTOMATED LOG ANALYZER  --  Security Intelligence Engine       |
|                    Author: Senior Cybersecurity Engineer                    |
+==============================================================================+

Parses Linux auth.log, Windows Security Event 4625, and Firewall DROP logs.
Detects: Brute-Force, Suspicious IPs, Port Scans, Off-Hours Logins.
Outputs: Terminal Summary Report + security_alerts.csv

Run:
    python log_analyzer.py
"""

import re
import sys
import csv
import textwrap
from datetime import datetime, time as dtime
from collections import defaultdict

import pandas as pd

# ------------------------------------------------------------------------------
# SECTION 1 - SAMPLE EMBEDDED LOG DATA
# ------------------------------------------------------------------------------

LINUX_AUTH_LOGS = """
Jan 15 02:14:03 webserver sshd[1452]: Failed password for root from 203.0.113.45 port 52341 ssh2
Jan 15 02:14:05 webserver sshd[1453]: Failed password for root from 203.0.113.45 port 52342 ssh2
Jan 15 02:14:07 webserver sshd[1454]: Failed password for root from 203.0.113.45 port 52343 ssh2
Jan 15 02:14:09 webserver sshd[1455]: Failed password for root from 203.0.113.45 port 52344 ssh2
Jan 15 02:14:11 webserver sshd[1456]: Failed password for admin from 203.0.113.45 port 52345 ssh2
Jan 15 02:14:13 webserver sshd[1457]: Failed password for admin from 203.0.113.45 port 52346 ssh2
Jan 15 02:15:00 webserver sshd[1460]: Accepted password for deploy from 198.51.100.7 port 44201 ssh2
Jan 15 08:30:01 webserver sshd[1500]: Accepted password for alice from 192.168.1.10 port 33901 ssh2
Jan 15 09:05:22 webserver sshd[1510]: Failed password for bob from 192.168.1.55 port 41001 ssh2
Jan 15 03:47:18 webserver sshd[1520]: Accepted password for root from 10.0.0.5 port 22100 ssh2
Jan 15 03:50:01 webserver sshd[1521]: Failed password for ubuntu from 185.220.101.32 port 60001 ssh2
Jan 15 03:50:03 webserver sshd[1522]: Failed password for ubuntu from 185.220.101.32 port 60002 ssh2
Jan 15 03:50:05 webserver sshd[1523]: Failed password for ubuntu from 185.220.101.32 port 60003 ssh2
Jan 15 03:50:07 webserver sshd[1524]: Failed password for ubuntu from 185.220.101.32 port 60004 ssh2
Jan 15 03:50:09 webserver sshd[1525]: Failed password for ubuntu from 185.220.101.32 port 60005 ssh2
Jan 15 11:22:44 webserver sshd[1530]: Accepted password for carol from 172.16.0.22 port 55001 ssh2
Jan 15 14:10:00 webserver sshd[1540]: Failed password for oracle from 91.108.56.77 port 11001 ssh2
Jan 15 14:10:01 webserver sshd[1541]: Failed password for oracle from 91.108.56.77 port 11002 ssh2
Jan 15 14:10:02 webserver sshd[1542]: Failed password for oracle from 91.108.56.77 port 11003 ssh2
Jan 15 22:58:11 webserver sshd[1550]: Accepted password for dave from 10.0.1.8 port 38001 ssh2
""".strip()

WINDOWS_SECURITY_LOGS = """
2024-01-15T02:30:00Z | EventID=4625 | AccountName=Administrator | IpAddress=203.0.113.45 | Port=3389 | Status=0xC000006D
2024-01-15T02:30:02Z | EventID=4625 | AccountName=Administrator | IpAddress=203.0.113.45 | Port=3389 | Status=0xC000006D
2024-01-15T02:30:04Z | EventID=4625 | AccountName=Administrator | IpAddress=203.0.113.45 | Port=3389 | Status=0xC000006D
2024-01-15T02:30:06Z | EventID=4625 | AccountName=Administrator | IpAddress=203.0.113.45 | Port=3389 | Status=0xC000006D
2024-01-15T02:30:08Z | EventID=4625 | AccountName=Guest        | IpAddress=203.0.113.45 | Port=3389 | Status=0xC000006D
2024-01-15T09:10:00Z | EventID=4625 | AccountName=john.doe     | IpAddress=192.168.2.50 | Port=3389 | Status=0xC0000064
2024-01-15T09:10:02Z | EventID=4625 | AccountName=john.doe     | IpAddress=192.168.2.50 | Port=3389 | Status=0xC0000064
2024-01-15T04:15:00Z | EventID=4625 | AccountName=svcaccount   | IpAddress=77.88.55.242 | Port=445  | Status=0xC000006D
2024-01-15T04:15:01Z | EventID=4625 | AccountName=svcaccount   | IpAddress=77.88.55.242 | Port=445  | Status=0xC000006D
2024-01-15T04:15:02Z | EventID=4625 | AccountName=svcaccount   | IpAddress=77.88.55.242 | Port=445  | Status=0xC000006D
2024-01-15T04:15:03Z | EventID=4625 | AccountName=backupadmin  | IpAddress=77.88.55.242 | Port=445  | Status=0xC000006D
""".strip()

FIREWALL_LOGS = """
Jan 15 01:00:01 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.99 DST=10.0.0.1 PROTO=TCP DPT=22   ACTION=DROP
Jan 15 01:00:02 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.99 DST=10.0.0.1 PROTO=TCP DPT=23   ACTION=DROP
Jan 15 01:00:03 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.99 DST=10.0.0.1 PROTO=TCP DPT=80   ACTION=DROP
Jan 15 01:00:04 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.99 DST=10.0.0.1 PROTO=TCP DPT=443  ACTION=DROP
Jan 15 01:00:05 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.99 DST=10.0.0.1 PROTO=TCP DPT=8080 ACTION=DROP
Jan 15 01:00:06 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.99 DST=10.0.0.1 PROTO=TCP DPT=3306 ACTION=DROP
Jan 15 01:00:07 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.99 DST=10.0.0.1 PROTO=TCP DPT=5432 ACTION=DROP
Jan 15 01:00:08 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.99 DST=10.0.0.1 PROTO=TCP DPT=6379 ACTION=DROP
Jan 15 08:22:10 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=192.168.5.30 DST=10.0.0.1 PROTO=TCP DPT=22   ACTION=DROP
Jan 15 08:22:11 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=192.168.5.30 DST=10.0.0.1 PROTO=TCP DPT=22   ACTION=DROP
Jan 15 08:22:12 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=192.168.5.30 DST=10.0.0.1 PROTO=TCP DPT=22   ACTION=DROP
Jan 15 10:05:00 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.32 DST=10.0.0.1 PROTO=UDP DPT=53  ACTION=DROP
Jan 15 10:05:01 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.32 DST=10.0.0.1 PROTO=TCP DPT=25  ACTION=DROP
Jan 15 10:05:02 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.32 DST=10.0.0.1 PROTO=TCP DPT=587 ACTION=DROP
Jan 15 10:05:03 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.32 DST=10.0.0.1 PROTO=TCP DPT=143 ACTION=DROP
Jan 15 10:05:04 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.32 DST=10.0.0.1 PROTO=TCP DPT=993 ACTION=DROP
Jan 15 15:30:00 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=10.10.10.1  DST=10.0.0.1 PROTO=TCP DPT=22   ACTION=DROP
""".strip()

# ------------------------------------------------------------------------------
# SECTION 2 - CONFIGURATION
# ------------------------------------------------------------------------------

CONFIG = {
    "brute_force_threshold":   3,    # failed attempts to flag an IP
    "port_scan_threshold":     5,    # distinct ports to flag a port scan
    "business_hours_start":    8,    # 08:00 inclusive
    "business_hours_end":      18,   # 18:00 exclusive
    "output_csv":              "security_alerts.csv",
}

# ------------------------------------------------------------------------------
# SECTION 3 - LOG PARSERS
# ------------------------------------------------------------------------------

YEAR = datetime.now().year  # used to reconstruct full timestamps from syslog lines

# Regex patterns -- compiled once for performance
RE_LINUX_FAILED = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r".*?Failed password for (?:invalid user )?(?P<user>\S+)"
    r" from (?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
    r" port (?P<port>\d+)"
)
RE_LINUX_ACCEPTED = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r".*?Accepted password for (?P<user>\S+)"
    r" from (?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
    r" port (?P<port>\d+)"
)
RE_WIN4625 = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"
    r".*?AccountName=(?P<user>\S+)"
    r".*?IpAddress=(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
    r".*?Port=(?P<port>\d+)"
)
RE_FIREWALL = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r".*?SRC=(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
    r".*?DPT=(?P<port>\d+)"
    r".*?ACTION=(?P<action>\w+)"
)


def _syslog_ts(month: str, day: str, t: str) -> datetime:
    """Convert syslog-style date parts to a datetime object."""
    return datetime.strptime(f"{YEAR} {month} {day.zfill(2)} {t}", "%Y %b %d %H:%M:%S")


def parse_linux_auth(raw: str) -> list[dict]:
    """Parse Linux auth.log/secure lines into normalised records."""
    records = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        m = RE_LINUX_FAILED.search(line)
        if m:
            records.append({
                "timestamp":  _syslog_ts(m["month"], m["day"], m["time"]),
                "source":     "linux_auth",
                "event_type": "failed_login",
                "src_ip":     m["src_ip"],
                "username":   m["user"],
                "port":       int(m["port"]),
                "action":     "FAILED",
            })
            continue
        m = RE_LINUX_ACCEPTED.search(line)
        if m:
            records.append({
                "timestamp":  _syslog_ts(m["month"], m["day"], m["time"]),
                "source":     "linux_auth",
                "event_type": "successful_login",
                "src_ip":     m["src_ip"],
                "username":   m["user"],
                "port":       int(m["port"]),
                "action":     "ACCEPTED",
            })
    return records


def parse_windows_security(raw: str) -> list[dict]:
    """Parse Windows Security Event 4625 (failed logon) lines."""
    records = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        m = RE_WIN4625.search(line)
        if m:
            records.append({
                "timestamp":  datetime.strptime(m["ts"], "%Y-%m-%dT%H:%M:%SZ"),
                "source":     "windows_security",
                "event_type": "failed_login",
                "src_ip":     m["src_ip"],
                "username":   m["user"].strip(),
                "port":       int(m["port"]),
                "action":     "FAILED",
            })
    return records


def parse_firewall(raw: str) -> list[dict]:
    """Parse UFW/iptables BLOCK/DROP lines."""
    records = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        m = RE_FIREWALL.search(line)
        if m:
            records.append({
                "timestamp":  _syslog_ts(m["month"], m["day"], m["time"]),
                "source":     "firewall",
                "event_type": "connection_drop",
                "src_ip":     m["src_ip"],
                "username":   None,
                "port":       int(m["port"]),
                "action":     m["action"].upper(),
            })
    return records


# ------------------------------------------------------------------------------
# SECTION 4 - NORMALISATION -> DATAFRAME
# ------------------------------------------------------------------------------

def ingest_all_logs() -> pd.DataFrame:
    """Run all parsers and return one unified, normalised DataFrame."""
    all_records = (
        parse_linux_auth(LINUX_AUTH_LOGS)
        + parse_windows_security(WINDOWS_SECURITY_LOGS)
        + parse_firewall(FIREWALL_LOGS)
    )

    df = pd.DataFrame(all_records, columns=[
        "timestamp", "source", "event_type", "src_ip", "username", "port", "action"
    ])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df


# ------------------------------------------------------------------------------
# SECTION 5 - DETECTION ENGINE
# ------------------------------------------------------------------------------

def detect_brute_force(df: pd.DataFrame, threshold: int) -> pd.DataFrame:
    """
    Flag source IPs with >= threshold failed login attempts.
    Returns one row per offending IP with attempt count and targeted accounts.
    """
    failed = df[df["action"] == "FAILED"].copy()
    grouped = (
        failed.groupby("src_ip")
        .agg(
            attempt_count=("src_ip", "count"),
            targeted_users=("username", lambda x: ", ".join(sorted(x.dropna().unique()))),
            ports_used=("port", lambda x: ", ".join(str(p) for p in sorted(x.unique()))),
            sources_seen=("source", lambda x: ", ".join(sorted(x.unique()))),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
        )
        .reset_index()
    )
    flagged = grouped[grouped["attempt_count"] >= threshold].copy()
    flagged["alert_type"] = "BRUTE_FORCE"
    flagged["severity"] = flagged["attempt_count"].apply(_brute_severity)
    return flagged


def detect_suspicious_ips(df: pd.DataFrame) -> pd.DataFrame:
    """
    Flag IPs appearing across multiple distinct log sources (cross-service repeat offenders).
    """
    cross = (
        df.groupby("src_ip")["source"]
        .nunique()
        .reset_index(name="service_count")
    )
    flagged = cross[cross["service_count"] > 1].copy()

    # Enrich with total event count
    counts = df.groupby("src_ip").size().reset_index(name="total_events")
    flagged = flagged.merge(counts, on="src_ip")

    # Collect all usernames seen
    users = (
        df[df["src_ip"].isin(flagged["src_ip"])]
        .groupby("src_ip")["username"]
        .apply(lambda x: ", ".join(sorted(x.dropna().unique())))
        .reset_index(name="targeted_users")
    )
    flagged = flagged.merge(users, on="src_ip")
    flagged["alert_type"] = "SUSPICIOUS_IP"
    flagged["severity"] = "High"
    return flagged


def detect_port_scans(df: pd.DataFrame, threshold: int) -> pd.DataFrame:
    """
    Flag source IPs that triggered DROP events on >= threshold distinct destination ports.
    """
    fw = df[df["event_type"] == "connection_drop"].copy()
    grouped = (
        fw.groupby("src_ip")
        .agg(
            distinct_ports=("port", "nunique"),
            port_list=("port", lambda x: ", ".join(str(p) for p in sorted(x.unique()))),
            drop_count=("src_ip", "count"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
        )
        .reset_index()
    )
    flagged = grouped[grouped["distinct_ports"] >= threshold].copy()
    flagged["alert_type"] = "PORT_SCAN"
    flagged["severity"] = flagged["distinct_ports"].apply(
        lambda p: "Critical" if p >= 8 else "High"
    )
    return flagged


def detect_off_hours_logins(df: pd.DataFrame, start_h: int, end_h: int) -> pd.DataFrame:
    """
    Flag successful logins occurring outside business hours [start_h, end_h).
    """
    success = df[df["action"] == "ACCEPTED"].copy()
    success["hour"] = success["timestamp"].dt.hour
    off_hours = success[
        (success["hour"] < start_h) | (success["hour"] >= end_h)
    ].copy()

    if off_hours.empty:
        return pd.DataFrame()

    result = off_hours[["timestamp", "src_ip", "username", "port", "source"]].copy()
    result["alert_type"] = "OFF_HOURS_LOGIN"
    result["severity"] = result["timestamp"].apply(
        lambda ts: "Critical" if ts.hour < 5 or ts.hour >= 22 else "Medium"
    )
    return result


def _brute_severity(count: int) -> str:
    if count >= 10:
        return "Critical"
    elif count >= 6:
        return "High"
    elif count >= 3:
        return "Medium"
    return "Low"


# ------------------------------------------------------------------------------
# SECTION 6 - ALERT AGGREGATION
# ------------------------------------------------------------------------------

def run_all_detections(df: pd.DataFrame) -> list[dict]:
    """Run every detection module and return a flat list of alert dicts."""
    alerts = []

    # -- Brute Force --
    bf = detect_brute_force(df, CONFIG["brute_force_threshold"])
    for _, row in bf.iterrows():
        alerts.append({
            "alert_type":      row["alert_type"],
            "severity":        row["severity"],
            "src_ip":          row["src_ip"],
            "detail":          f"Failed logins: {row['attempt_count']} | "
                               f"Users: {row['targeted_users']} | "
                               f"Ports: {row['ports_used']} | "
                               f"Sources: {row['sources_seen']}",
            "first_seen":      str(row["first_seen"]),
            "last_seen":       str(row["last_seen"]),
        })

    # -- Suspicious IPs --
    si = detect_suspicious_ips(df)
    for _, row in si.iterrows():
        alerts.append({
            "alert_type":  row["alert_type"],
            "severity":    row["severity"],
            "src_ip":      row["src_ip"],
            "detail":      f"Seen across {row['service_count']} services | "
                           f"Total events: {row['total_events']} | "
                           f"Users: {row['targeted_users']}",
            "first_seen":  "",
            "last_seen":   "",
        })

    # -- Port Scans --
    ps = detect_port_scans(df, CONFIG["port_scan_threshold"])
    for _, row in ps.iterrows():
        alerts.append({
            "alert_type":  row["alert_type"],
            "severity":    row["severity"],
            "src_ip":      row["src_ip"],
            "detail":      f"Distinct ports hit: {row['distinct_ports']} | "
                           f"Ports: {row['port_list']} | "
                           f"Total drops: {row['drop_count']}",
            "first_seen":  str(row["first_seen"]),
            "last_seen":   str(row["last_seen"]),
        })

    # -- Off-Hours Logins --
    oh = detect_off_hours_logins(
        df,
        CONFIG["business_hours_start"],
        CONFIG["business_hours_end"],
    )
    if not oh.empty:
        for _, row in oh.iterrows():
            alerts.append({
                "alert_type":  row["alert_type"],
                "severity":    row["severity"],
                "src_ip":      row["src_ip"],
                "detail":      f"User '{row['username']}' logged in at "
                               f"{row['timestamp'].strftime('%H:%M:%S')} "
                               f"via {row['source']}:{row['port']}",
                "first_seen":  str(row["timestamp"]),
                "last_seen":   str(row["timestamp"]),
            })

    return alerts


# ------------------------------------------------------------------------------
# SECTION 7 - TERMINAL REPORT
# ------------------------------------------------------------------------------

# ANSI colours -- degrade gracefully on Windows when TERM is not set
def _ansi(code: str, text: str) -> str:
    if sys.stdout.isatty() or sys.platform != "win32":
        return f"\033[{code}m{text}\033[0m"
    return text

BOLD    = lambda t: _ansi("1",    t)
RED     = lambda t: _ansi("31",   t)
YELLOW  = lambda t: _ansi("33",   t)
GREEN   = lambda t: _ansi("32",   t)
CYAN    = lambda t: _ansi("36",   t)
MAGENTA = lambda t: _ansi("35",   t)
DIM     = lambda t: _ansi("2",    t)

SEV_COLOR = {
    "Critical": RED,
    "High":     MAGENTA,
    "Medium":   YELLOW,
    "Low":      GREEN,
}

SEV_ORDER = ["Critical", "High", "Medium", "Low"]


def _severity_badge(sev: str) -> str:
    fn = SEV_COLOR.get(sev, lambda x: x)
    return fn(f"[{sev:<8}]")


def print_report(df: pd.DataFrame, alerts: list[dict]) -> None:
    w = 82  # report width

    def hline(char="-"):
        print(char * w)

    def banner(text: str):
        print(BOLD(f"  {text}"))

    print()
    print(BOLD("=" * w))
    print(BOLD(f"{'AUTOMATED LOG ANALYZER -- SECURITY REPORT':^{w}}"))
    print(BOLD(f"{'Generated: ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'):^{w}}"))
    print(BOLD("=" * w))

    # -- Overview --------------------------------------------------------------
    print()
    banner("[*]  OVERVIEW")
    hline()
    total_events  = len(df)
    total_alerts  = len(alerts)
    sources       = df["source"].value_counts().to_dict()
    event_types   = df["event_type"].value_counts().to_dict()

    print(f"  Total log events parsed : {BOLD(str(total_events))}")
    print(f"  Total alerts flagged    : {BOLD(RED(str(total_alerts)))}")
    print()
    print("  Events by source:")
    for src, cnt in sources.items():
        print(f"    {DIM('*')} {src:<25} {cnt:>4} events")
    print()
    print("  Events by type:")
    for etype, cnt in event_types.items():
        print(f"    {DIM('*')} {etype:<25} {cnt:>4} events")

    # -- Severity Breakdown ----------------------------------------------------
    print()
    banner("[!]  SEVERITY BREAKDOWN")
    hline()
    sev_counts: dict[str, int] = defaultdict(int)
    for a in alerts:
        sev_counts[a["severity"]] += 1
    for sev in SEV_ORDER:
        cnt = sev_counts.get(sev, 0)
        bar = "#" * min(cnt * 3, 40)
        print(f"  {_severity_badge(sev)}  {bar}  {cnt}")

    # -- High-Risk IP Table ----------------------------------------------------
    print()
    banner("[!!]  HIGH-RISK SUSPICIOUS IP TABLE")
    hline()
    fmt = "  {:<18} {:<12} {:<10} {}"
    print(BOLD(fmt.format("Source IP", "Alert Type", "Severity", "Detail (truncated)")))
    hline(".")
    high_risk = [a for a in alerts if a["severity"] in ("Critical", "High")]
    if not high_risk:
        print("  No critical/high alerts detected.")
    else:
        for a in sorted(high_risk, key=lambda x: SEV_ORDER.index(x["severity"])):
            detail_short = textwrap.shorten(a["detail"], width=42, placeholder="...")
            sev_fn = SEV_COLOR.get(a["severity"], lambda x: x)
            print(fmt.format(
                a["src_ip"],
                a["alert_type"],
                sev_fn(a["severity"]),
                detail_short,
            ))

    # -- All Alerts ------------------------------------------------------------
    print()
    banner("[+]  ALL ALERTS (DETAILED)")
    hline()
    for i, a in enumerate(alerts, 1):
        ts_range = (
            f"{a['first_seen']} -> {a['last_seen']}"
            if a["first_seen"] else "--"
        )
        print(f"  [{i:>2}] {_severity_badge(a['severity'])} "
              f"{CYAN(a['alert_type']):<30} IP: {BOLD(a['src_ip'])}")
        print(f"        {DIM('Detail  :')} {a['detail']}")
        print(f"        {DIM('Timespan:')} {ts_range}")
        print()

    # -- Footer ----------------------------------------------------------------
    hline()
    print(BOLD(f"  Alerts exported to: {CONFIG['output_csv']}"))
    print(BOLD("=" * w))
    print()


# ------------------------------------------------------------------------------
# SECTION 8 - CSV EXPORT
# ------------------------------------------------------------------------------

def export_alerts_csv(alerts: list[dict], path: str) -> None:
    """Write all alerts to a CSV file."""
    if not alerts:
        print("No alerts to export.")
        return

    fieldnames = ["alert_type", "severity", "src_ip", "detail", "first_seen", "last_seen"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(alerts)


# ------------------------------------------------------------------------------
# SECTION 9 - ENTRY POINT
# ------------------------------------------------------------------------------

def main() -> None:
    print(DIM("  [*] Ingesting and normalising log data ..."))
    df = ingest_all_logs()

    print(DIM(f"  [*] Running detection engine on {len(df)} events ..."))
    alerts = run_all_detections(df)

    print(DIM(f"  [*] {len(alerts)} alert(s) generated. Building report ...\n"))
    print_report(df, alerts)

    print(DIM(f"  [*] Exporting alerts to '{CONFIG['output_csv']}' ..."))
    export_alerts_csv(alerts, CONFIG["output_csv"])
    print(DIM(f"  [+] Done. CSV saved -> {CONFIG['output_csv']}\n"))


if __name__ == "__main__":
    main()
