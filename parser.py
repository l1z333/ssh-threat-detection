"""
parser.py — SSH Threat Detection Tool: Layer 1
================================================
Reads an SSH auth log, extracts failed login attempts via regex,
stores results in SQLite, and outputs flagged IPs based on a threshold.

Usage:
    python parser.py --log-file sample_auth.log
    python parser.py --log-file sample_auth.log --threshold 3
    python parser.py --log-file sample_auth.log --threshold 3 --output json
    python parser.py --log-file sample_auth.log --output csv
    python parser.py --log-file /var/log/auth.log --threshold 10 --output txt
"""

import re
import sqlite3
import argparse
import json
import csv
import sys
import os
from datetime import datetime
from collections import defaultdict


# ── Constants ────────────────────────────────────────────────────────────────

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "threats.db")

# Matches lines like:
#   Jan 15 03:12:01 server sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2
#   Jan 15 03:17:01 server sshd[1240]: Failed password for invalid user hacker from 1.2.3.4 port 33210 ssh2
FAILED_LOGIN_RE = re.compile(
    r"^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})"  # timestamp
    r".+sshd\[\d+\]:\s+"                                               # sshd[pid]:
    r"Failed password for (?:invalid user )?(?P<username>\S+)"        # username
    r" from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"                          # IP address
    r" port \d+"                                                       # port
)


# ── Database ─────────────────────────────────────────────────────────────────

def init_db(db_path: str) -> sqlite3.Connection:
    """Create the database and tables if they don't already exist."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS attempts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ip        TEXT    NOT NULL,
            username  TEXT    NOT NULL,
            timestamp TEXT    NOT NULL,
            count     INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS enriched_ips (
            ip            TEXT PRIMARY KEY,
            country       TEXT,
            city          TEXT,
            lat           REAL,
            lon           REAL,
            abuse_score   INTEGER,
            total_reports INTEGER,
            risk_score    REAL,
            flagged_at    TEXT
        );
    """)
    conn.commit()
    return conn


def clear_attempts(conn: sqlite3.Connection) -> None:
    """Wipe previous parse results so re-runs are idempotent."""
    conn.execute("DELETE FROM attempts")
    conn.commit()


def insert_attempts(conn: sqlite3.Connection, rows: list[dict]) -> None:
    """Bulk-insert parsed attempt rows."""
    conn.executemany(
        "INSERT INTO attempts (ip, username, timestamp, count) VALUES (:ip, :username, :timestamp, :count)",
        rows,
    )
    conn.commit()


def query_flagged(conn: sqlite3.Connection, threshold: int) -> list[sqlite3.Row]:
    """Return IPs whose total failure count meets or exceeds the threshold."""
    return conn.execute(
        """
        SELECT
            ip,
            GROUP_CONCAT(DISTINCT username)  AS usernames,
            MIN(timestamp)                   AS first_seen,
            MAX(timestamp)                   AS last_seen,
            SUM(count)                       AS total_failures
        FROM attempts
        GROUP BY ip
        HAVING total_failures >= ?
        ORDER BY total_failures DESC
        """,
        (threshold,),
    ).fetchall()


# ── Parsing ───────────────────────────────────────────────────────────────────

def parse_log(log_path: str) -> list[dict]:
    """
    Read the log file line by line.
    Returns a flat list of individual failed-login events.
    Each entry has: ip, username, timestamp, count (always 1 here).
    """
    if not os.path.exists(log_path):
        print(f"[ERROR] Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    events = []
    skipped = 0
    current_year = datetime.now().year  # auth.log has no year — assume current

    with open(log_path, "r", errors="replace") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.rstrip()
            match = FAILED_LOGIN_RE.match(line)
            if not match:
                skipped += 1
                continue

            month = match.group("month")
            day   = match.group("day").zfill(2)
            time  = match.group("time")

            # Parse to a proper ISO timestamp; handle bad dates gracefully
            try:
                ts = datetime.strptime(
                    f"{current_year} {month} {day} {time}",
                    "%Y %b %d %H:%M:%S"
                ).isoformat()
            except ValueError:
                ts = f"{current_year}-{month}-{day}T{time}"

            events.append({
                "ip":        match.group("ip"),
                "username":  match.group("username"),
                "timestamp": ts,
                "count":     1,
            })

    print(f"[INFO] Parsed {len(events)} failed login events ({skipped} lines skipped)")
    return events


# ── Output formatters ─────────────────────────────────────────────────────────

def _rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict]:
    return [dict(r) for r in rows]


def output_json(rows: list[sqlite3.Row]) -> None:
    print(json.dumps(_rows_to_dicts(rows), indent=2))


def output_csv(rows: list[sqlite3.Row]) -> None:
    if not rows:
        print("No flagged IPs found.")
        return
    dicts = _rows_to_dicts(rows)
    writer = csv.DictWriter(sys.stdout, fieldnames=dicts[0].keys())
    writer.writeheader()
    writer.writerows(dicts)


def output_txt(rows: list[sqlite3.Row], threshold: int) -> None:
    if not rows:
        print(f"No IPs exceeded the threshold of {threshold} failures.")
        return

    print(f"\n{'═' * 72}")
    print(f"  SSH THREAT DETECTION — FLAGGED IPs  (threshold: ≥{threshold} failures)")
    print(f"{'═' * 72}\n")

    for r in rows:
        print(f"  IP            : {r['ip']}")
        print(f"  Total Failures: {r['total_failures']}")
        print(f"  Usernames tried: {r['usernames']}")
        print(f"  First seen    : {r['first_seen']}")
        print(f"  Last seen     : {r['last_seen']}")
        print(f"  {'─' * 68}")

    print(f"\n  Total flagged IPs: {len(rows)}\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def build_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="parser.py",
        description="SSH log parser — Layer 1 of the SSH Threat Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python parser.py --log-file sample_auth.log
  python parser.py --log-file sample_auth.log --threshold 3 --output json
  python parser.py --log-file /var/log/auth.log --threshold 10 --output csv
        """,
    )
    parser.add_argument(
        "--log-file",
        required=True,
        metavar="PATH",
        help="Path to the auth.log file to parse",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        metavar="N",
        help="Minimum number of failures to flag an IP (default: 5)",
    )
    parser.add_argument(
        "--output",
        choices=["json", "csv", "txt"],
        default="txt",
        help="Output format: json | csv | txt (default: txt)",
    )
    parser.add_argument(
        "--db",
        default=DB_PATH,
        metavar="PATH",
        help=f"Path to the SQLite database (default: {DB_PATH})",
    )
    return parser.parse_args()


def main() -> None:
    args = build_args()

    # 1. Parse the log file
    events = parse_log(args.log_file)

    if not events:
        print("[WARN] No failed login events found. Check the log file format.")
        sys.exit(0)

    # 2. Set up the database
    conn = init_db(args.db)
    clear_attempts(conn)        # idempotent: fresh results each run
    insert_attempts(conn, events)
    print(f"[INFO] Stored {len(events)} events in {args.db}")

    # 3. Query flagged IPs
    flagged = query_flagged(conn, args.threshold)
    print(f"[INFO] {len(flagged)} IP(s) flagged at threshold ≥{args.threshold}\n")

    # 4. Render output
    if args.output == "json":
        output_json(flagged)
    elif args.output == "csv":
        output_csv(flagged)
    else:
        output_txt(flagged, args.threshold)

    conn.close()


if __name__ == "__main__":
    main()
