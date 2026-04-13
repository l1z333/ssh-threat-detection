"""
app.py — SSH Threat Detection Tool: Layer 3 (Flask Dashboard)
=============================================================
Serves the web dashboard with:
  - /                  → redirect to /table
  - /table             → Page 1: IP table with risk badges
  - /timeline          → Page 2: Attack timeline (attempts per hour)
  - /map               → Page 3: World map with IP dots
  - /api/ips           → JSON: all enriched IPs
  - /api/timeline      → JSON: attempts grouped by hour
  - /api/block/<ip>    → POST: generate iptables DROP rule

Usage:
    python app.py
    python app.py --port 8080
    python app.py --db data/threats.db --debug
"""

import sqlite3
import argparse
import os
import sys
from datetime import datetime
from flask import Flask, jsonify, render_template, redirect, url_for, request, abort


# ── App setup ─────────────────────────────────────────────────────────────────

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "data", "threats.db")


# ── Database helpers ──────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def risk_label(score: float) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    return "LOW"


# ── API endpoints ─────────────────────────────────────────────────────────────

@app.route("/api/ips")
def api_ips():
    """Return all enriched IPs as JSON, joined with attempt counts."""
    conn = get_db()
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
            SUM(a.count)                      AS total_failures,
            GROUP_CONCAT(DISTINCT a.username) AS usernames,
            MIN(a.timestamp)                  AS first_seen,
            MAX(a.timestamp)                  AS last_seen
        FROM enriched_ips e
        JOIN attempts a ON e.ip = a.ip
        GROUP BY e.ip
        ORDER BY e.risk_score DESC
        """
    ).fetchall()
    conn.close()

    data = []
    for r in rows:
        d = dict(r)
        d["risk_label"] = risk_label(d["risk_score"])
        d["usernames"]  = d["usernames"].split(",") if d["usernames"] else []
        data.append(d)

    return jsonify(data)


@app.route("/api/timeline")
def api_timeline():
    """Return attempts grouped by hour for the Chart.js timeline."""
    conn = get_db()
    rows = conn.execute(
        """
        SELECT
            strftime('%Y-%m-%dT%H:00', timestamp) AS hour,
            SUM(count) AS attempts
        FROM attempts
        GROUP BY hour
        ORDER BY hour ASC
        """
    ).fetchall()
    conn.close()

    data = [{"hour": r["hour"], "attempts": r["attempts"]} for r in rows]
    return jsonify(data)


@app.route("/api/stats")
def api_stats():
    """Return summary stats for the dashboard header."""
    conn = get_db()

    total_attempts = conn.execute("SELECT SUM(count) FROM attempts").fetchone()[0] or 0
    total_ips      = conn.execute("SELECT COUNT(DISTINCT ip) FROM attempts").fetchone()[0] or 0
    enriched       = conn.execute("SELECT COUNT(*) FROM enriched_ips").fetchone()[0] or 0
    critical       = conn.execute(
        "SELECT COUNT(*) FROM enriched_ips WHERE risk_score >= 75"
    ).fetchone()[0] or 0

    conn.close()
    return jsonify({
        "total_attempts": total_attempts,
        "total_ips":      total_ips,
        "enriched":       enriched,
        "critical":       critical,
    })


@app.route("/api/block/<ip>", methods=["POST"])
def api_block(ip):
    """Generate an iptables DROP rule for a given IP."""
    # Basic IP validation
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        abort(400, description="Invalid IP address")

    conn = get_db()
    row = conn.execute(
        "SELECT risk_score, country FROM enriched_ips WHERE ip = ?", (ip,)
    ).fetchone()
    conn.close()

    label   = risk_label(row["risk_score"] if row else 0)
    country = row["country"] if row else "Unknown"
    rule    = f"iptables -A INPUT -s {ip} -j DROP   # {label} | {country} | {datetime.now().strftime('%Y-%m-%d %H:%M')}"

    return jsonify({"ip": ip, "rule": rule, "label": label})


# ── Page routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("table"))


@app.route("/table")
def table():
    return render_template("table.html", active="table")


@app.route("/timeline")
def timeline():
    return render_template("timeline.html", active="timeline")


@app.route("/map")
def map_page():
    return render_template("map.html", active="map")


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_args():
    parser = argparse.ArgumentParser(
        prog="app.py",
        description="Layer 3 — Flask dashboard for SSH Threat Detection",
    )
    parser.add_argument("--port",  type=int, default=5000, help="Port (default: 5000)")
    parser.add_argument("--host",  default="127.0.0.1",   help="Host (default: 127.0.0.1)")
    parser.add_argument("--db",    default=DB_PATH,        help="Path to SQLite database")
    parser.add_argument("--debug", action="store_true",    help="Enable Flask debug mode")
    return parser.parse_args()


if __name__ == "__main__":
    args = build_args()
    DB_PATH = args.db

    if not os.path.exists(DB_PATH):
        print(f"[ERROR] Database not found: {DB_PATH}", file=sys.stderr)
        print("[ERROR] Run parser.py then enricher.py first.", file=sys.stderr)
        sys.exit(1)

    print(f"""
╔══════════════════════════════════════════════╗
║     SSH THREAT DETECTION — DASHBOARD         ║
╠══════════════════════════════════════════════╣
║  http://{args.host}:{args.port}/table        ║
║  http://{args.host}:{args.port}/timeline     ║
║  http://{args.host}:{args.port}/map          ║
╚══════════════════════════════════════════════╝
    """)

    app.run(host=args.host, port=args.port, debug=args.debug)
