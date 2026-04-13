"""
enricher.py — SSH Threat Detection Tool: Layer 2 (Enrichment)
==============================================================
For each flagged IP (from the `attempts` table), this module:
  1. Calls ip-api.com (free, no key) for GeoIP data
  2. Calls AbuseIPDB v2/check (free API key) for abuse data
  3. Writes all enrichment results to the `enriched_ips` table in SQLite

Usage:
    python enricher.py
    python enricher.py --threshold 5
    python enricher.py --threshold 3 --db data/threats.db
    python enricher.py --dry-run
"""

import sqlite3
import requests
import argparse
import os
import sys
import time
from datetime import datetime


# ── Constants ────────────────────────────────────────────────────────────────

DB_PATH        = os.path.join(os.path.dirname(__file__), "data", "threats.db")
ABUSEIPDB_KEY  = "59946363344c0eac67362d55e612a86014c6e993789cf0767a878eaf4a2e6d7bebb15c2372bca4ca"
GEOIP_URL      = "http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp,query"
ABUSEIPDB_URL  = "https://api.abuseipdb.com/api/v2/check"
REQUEST_DELAY  = 1.5   # seconds between API calls (ip-api free tier: 45 req/min)


# ── Database ─────────────────────────────────────────────────────────────────

def get_connection(db_path: str) -> sqlite3.Connection:
    if not os.path.exists(db_path):
        print(f"[ERROR] Database not found: {db_path}", file=sys.stderr)
        print("[ERROR] Run parser.py first to create the database.", file=sys.stderr)
        sys.exit(1)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def get_flagged_ips(conn: sqlite3.Connection, threshold: int) -> list[str]:
    """Return IPs from attempts table that meet the failure threshold."""
    rows = conn.execute(
        """
        SELECT ip, SUM(count) AS total
        FROM attempts
        GROUP BY ip
        HAVING total >= ?
        ORDER BY total DESC
        """,
        (threshold,),
    ).fetchall()
    return [row["ip"] for row in rows]


def already_enriched(conn: sqlite3.Connection, ip: str) -> bool:
    """Check if IP already has enrichment data."""
    row = conn.execute(
        "SELECT ip FROM enriched_ips WHERE ip = ?", (ip,)
    ).fetchone()
    return row is not None


def upsert_enriched(conn: sqlite3.Connection, data: dict) -> None:
    """Insert or replace enrichment record."""
    conn.execute(
        """
        INSERT OR REPLACE INTO enriched_ips
            (ip, country, city, lat, lon, abuse_score, total_reports, risk_score, flagged_at)
        VALUES
            (:ip, :country, :city, :lat, :lon, :abuse_score, :total_reports, :risk_score, :flagged_at)
        """,
        data,
    )
    conn.commit()


# ── GeoIP via ip-api.com ─────────────────────────────────────────────────────

def get_geoip(ip: str) -> dict:
    """
    Query ip-api.com for geolocation data.
    Returns a dict with: country, city, lat, lon
    Falls back to None values on any error.
    """
    defaults = {"country": None, "city": None, "lat": None, "lon": None}
    try:
        resp = requests.get(GEOIP_URL.format(ip=ip), timeout=5)
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") != "success":
            print(f"  [GeoIP] No data for {ip}: {data.get('message', 'unknown')}")
            return defaults

        return {
            "country": data.get("country"),
            "city":    data.get("city"),
            "lat":     data.get("lat"),
            "lon":     data.get("lon"),
        }

    except requests.exceptions.Timeout:
        print(f"  [GeoIP] Timeout for {ip}")
    except requests.exceptions.RequestException as e:
        print(f"  [GeoIP] Error for {ip}: {e}")

    return defaults


# ── AbuseIPDB ────────────────────────────────────────────────────────────────

def get_abuse(ip: str) -> dict:
    """
    Query AbuseIPDB v2/check endpoint.
    Returns a dict with: abuse_score, total_reports
    Falls back to 0 values on any error.
    """
    defaults = {"abuse_score": 0, "total_reports": 0}

    if not ABUSEIPDB_KEY:
        print(f"  [AbuseIPDB] No API key — skipping")
        return defaults

    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            headers={
                "Key":    ABUSEIPDB_KEY,
                "Accept": "application/json",
            },
            params={
                "ipAddress":    ip,
                "maxAgeInDays": "90",
            },
            timeout=5,
        )

        if resp.status_code == 401:
            print(f"  [AbuseIPDB] Invalid API key")
            return defaults

        if resp.status_code == 429:
            print(f"  [AbuseIPDB] Rate limited — waiting 60s")
            time.sleep(60)
            return defaults

        resp.raise_for_status()
        d = resp.json().get("data", {})

        return {
            "abuse_score":   d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
        }

    except requests.exceptions.Timeout:
        print(f"  [AbuseIPDB] Timeout for {ip}")
    except requests.exceptions.RequestException as e:
        print(f"  [AbuseIPDB] Error for {ip}: {e}")

    return defaults


# ── Risk scorer (inline for standalone use) ───────────────────────────────────

def compute_risk_score(local_count: int, abuse_score: int, max_count: int = 20) -> float:
    """
    Composite risk score 0–100:
      - 40% weight: normalized local failure count (capped at max_count)
      - 60% weight: AbuseIPDB confidence score
    """
    normalized_count = min(local_count / max_count, 1.0) * 100
    score = (normalized_count * 0.4) + (abuse_score * 0.6)
    return round(min(score, 100.0), 2)


# ── Main enrichment loop ──────────────────────────────────────────────────────

def enrich_all(conn: sqlite3.Connection, threshold: int, force: bool, dry_run: bool) -> None:
    flagged = get_flagged_ips(conn, threshold)

    if not flagged:
        print(f"[WARN] No IPs found at threshold ≥{threshold}. Run parser.py first.")
        return

    print(f"[INFO] Found {len(flagged)} flagged IP(s) to enrich\n")

    # Get local failure counts for risk scoring
    counts = {
        row["ip"]: row["total"]
        for row in conn.execute(
            "SELECT ip, SUM(count) AS total FROM attempts GROUP BY ip"
        ).fetchall()
    }

    max_count = max(counts.values()) if counts else 1

    for i, ip in enumerate(flagged, start=1):
        print(f"[{i}/{len(flagged)}] Enriching {ip} ...")

        if not force and already_enriched(conn, ip):
            print(f"  [SKIP] Already enriched (use --force to re-enrich)\n")
            continue

        # GeoIP
        geo = get_geoip(ip)
        print(f"  [GeoIP]    {geo.get('city', '?')}, {geo.get('country', '?')} "
              f"({geo.get('lat', '?')}, {geo.get('lon', '?')})")

        time.sleep(REQUEST_DELAY)

        # AbuseIPDB
        abuse = get_abuse(ip)
        print(f"  [Abuse]    Score: {abuse['abuse_score']}  "
              f"Reports: {abuse['total_reports']}")

        # Risk score
        local_count = counts.get(ip, 1)
        risk = compute_risk_score(local_count, abuse["abuse_score"], max_count)
        print(f"  [Risk]     Score: {risk}/100  (local failures: {local_count})")

        record = {
            "ip":            ip,
            "country":       geo["country"],
            "city":          geo["city"],
            "lat":           geo["lat"],
            "lon":           geo["lon"],
            "abuse_score":   abuse["abuse_score"],
            "total_reports": abuse["total_reports"],
            "risk_score":    risk,
            "flagged_at":    datetime.now().isoformat(),
        }

        if dry_run:
            print(f"  [DRY RUN]  Would write: {record}\n")
        else:
            upsert_enriched(conn, record)
            print(f"  [DB]       Saved to enriched_ips ✓\n")

        time.sleep(REQUEST_DELAY)

    print("[INFO] Enrichment complete.")
    if not dry_run:
        print(f"[INFO] Results saved to enriched_ips table in {conn}") 


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="enricher.py",
        description="Layer 2 — Enrich flagged IPs with GeoIP and AbuseIPDB data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python enricher.py
  python enricher.py --threshold 3
  python enricher.py --force
  python enricher.py --dry-run
        """,
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        metavar="N",
        help="Minimum failures to consider an IP flagged (default: 5)",
    )
    parser.add_argument(
        "--db",
        default=DB_PATH,
        metavar="PATH",
        help=f"Path to SQLite database (default: {DB_PATH})",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-enrich IPs even if already in enriched_ips table",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run without writing to the database",
    )
    return parser.parse_args()


def main() -> None:
    args = build_args()
    conn = get_connection(args.db)
    enrich_all(conn, args.threshold, args.force, args.dry_run)
    conn.close()


if __name__ == "__main__":
    main()
