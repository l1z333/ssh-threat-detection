"""
scorer.py — SSH Threat Detection Tool: Layer 2 (Scoring & Reporting)
=====================================================================
Reads enriched IP data from SQLite and produces a ranked threat report.
Assigns risk labels (CRITICAL / HIGH / MEDIUM / LOW) and outputs results.

Usage:
    python scorer.py
    python scorer.py --output json
    python scorer.py --output csv
    python scorer.py --min-risk 50
    python scorer.py --output json --min-risk 30
"""

import sqlite3
import argparse
import json
import csv
import os
import sys
from datetime import datetime


# ── Constants ────────────────────────────────────────────────────────────────

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "threats.db")

# Risk label thresholds
CRITICAL_THRESHOLD = 75
HIGH_THRESHOLD     = 50
MEDIUM_THRESHOLD   = 25


# ── Risk label ────────────────────────────────────────────────────────────────

def risk_label(score: float) -> str:
    if score >= CRITICAL_THRESHOLD:
        return "CRITICAL"
    elif score >= HIGH_THRESHOLD:
        return "HIGH"
    elif score >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    else:
        return "LOW"


def risk_badge(score: float) -> str:
    """ASCII badge for terminal output."""
    label = risk_label(score)
    badges = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH":     "🟠 HIGH    ",
        "MEDIUM":   "🟡 MEDIUM  ",
        "LOW":      "🟢 LOW     ",
    }
    return badges[label]


# ── Database ──────────────────────────────────────────────────────────────────

def get_connection(db_path: str) -> sqlite3.Connection:
    if not os.path.exists(db_path):
        print(f"[ERROR] Database not found: {db_path}", file=sys.stderr)
        print("[ERROR] Run parser.py then enricher.py first.", file=sys.stderr)
        sys.exit(1)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def fetch_scored_ips(conn: sqlite3.Connection, min_risk: float) -> list[dict]:
    """
    Join enriched_ips with attempts to get full picture.
    Returns list of dicts sorted by risk_score descending.
    """
    rows = conn.execute(
        """
        SELECT
            e.ip,
            e.country,
            e.city,
            e.lat,
            e.lon,
            e.abuse_score,
            e.total_reports,
            e.risk_score,
            e.flagged_at,
            SUM(a.count)                    AS total_failures,
            GROUP_CONCAT(DISTINCT a.username) AS usernames,
            MIN(a.timestamp)                AS first_seen,
            MAX(a.timestamp)                AS last_seen
        FROM enriched_ips e
        JOIN attempts a ON e.ip = a.ip
        WHERE e.risk_score >= ?
        GROUP BY e.ip
        ORDER BY e.risk_score DESC
        """,
        (min_risk,),
    ).fetchall()

    return [dict(r) for r in rows]


# ── Output formatters ─────────────────────────────────────────────────────────

def output_txt(rows: list[dict], min_risk: float) -> None:
    if not rows:
        print(f"No IPs found with risk score ≥ {min_risk}")
        return

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{'═' * 72}")
    print(f"  SSH THREAT DETECTION — RISK REPORT")
    print(f"  Generated: {now}  |  Min risk: {min_risk}  |  IPs: {len(rows)}")
    print(f"{'═' * 72}\n")

    for r in rows:
        score = r["risk_score"] or 0
        print(f"  {risk_badge(score)}  {r['ip']:<18}  Risk: {score:>6.2f}/100")
        print(f"  {'─' * 68}")
        print(f"  Location      : {r['city'] or '?'}, {r['country'] or 'Unknown'}")
        print(f"  Coordinates   : {r['lat'] or '?'}, {r['lon'] or '?'}")
        print(f"  Abuse Score   : {r['abuse_score']}/100  ({r['total_reports']} global reports)")
        print(f"  Local Failures: {r['total_failures']}")
        print(f"  Usernames     : {r['usernames']}")
        print(f"  First seen    : {r['first_seen']}")
        print(f"  Last seen     : {r['last_seen']}")
        print()

    # Summary stats
    scores = [r["risk_score"] or 0 for r in rows]
    critical = sum(1 for s in scores if s >= CRITICAL_THRESHOLD)
    high     = sum(1 for s in scores if HIGH_THRESHOLD <= s < CRITICAL_THRESHOLD)
    medium   = sum(1 for s in scores if MEDIUM_THRESHOLD <= s < HIGH_THRESHOLD)
    low      = sum(1 for s in scores if s < MEDIUM_THRESHOLD)

    print(f"{'═' * 72}")
    print(f"  SUMMARY")
    print(f"  🔴 Critical : {critical}")
    print(f"  🟠 High     : {high}")
    print(f"  🟡 Medium   : {medium}")
    print(f"  🟢 Low      : {low}")
    print(f"  Total       : {len(rows)}")
    print(f"{'═' * 72}\n")


def output_json(rows: list[dict]) -> None:
    # Add risk label to each row
    for r in rows:
        r["risk_label"] = risk_label(r["risk_score"] or 0)
    print(json.dumps(rows, indent=2))


def output_csv(rows: list[dict]) -> None:
    if not rows:
        print("No data.")
        return
    for r in rows:
        r["risk_label"] = risk_label(r["risk_score"] or 0)
    writer = csv.DictWriter(sys.stdout, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)


# ── iptables helper ───────────────────────────────────────────────────────────

def generate_iptables(rows: list[dict]) -> None:
    """Print iptables DROP rules for all flagged IPs."""
    print("\n# iptables DROP rules — generated by scorer.py")
    print(f"# {datetime.now().isoformat()}\n")
    for r in rows:
        label = risk_label(r["risk_score"] or 0)
        print(f"iptables -A INPUT -s {r['ip']} -j DROP   # {label} | risk={r['risk_score']} | {r['country'] or 'Unknown'}")
    print()


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="scorer.py",
        description="Layer 2 — Score and report enriched threat IPs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scorer.py
  python scorer.py --output json
  python scorer.py --output csv
  python scorer.py --min-risk 50
  python scorer.py --iptables
        """,
    )
    parser.add_argument(
        "--output",
        choices=["txt", "json", "csv"],
        default="txt",
        help="Output format (default: txt)",
    )
    parser.add_argument(
        "--min-risk",
        type=float,
        default=0,
        metavar="SCORE",
        help="Only show IPs with risk score >= this value (default: 0)",
    )
    parser.add_argument(
        "--db",
        default=DB_PATH,
        metavar="PATH",
        help=f"Path to SQLite database (default: {DB_PATH})",
    )
    parser.add_argument(
        "--iptables",
        action="store_true",
        help="Also print iptables DROP rules for all flagged IPs",
    )
    return parser.parse_args()


def main() -> None:
    args = build_args()
    conn = get_connection(args.db)
    rows = fetch_scored_ips(conn, args.min_risk)
    conn.close()

    if not rows:
        print(f"[WARN] No enriched IPs found with risk ≥ {args.min_risk}.")
        print("[WARN] Run parser.py then enricher.py first.")
        return

    if args.output == "json":
        output_json(rows)
    elif args.output == "csv":
        output_csv(rows)
    else:
        output_txt(rows, args.min_risk)

    if args.iptables:
        generate_iptables(rows)


if __name__ == "__main__":
    main()
