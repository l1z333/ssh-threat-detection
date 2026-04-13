# SSH Threat Detection Tool

A full-stack cybersecurity tool that parses SSH authentication logs, enriches flagged IPs with geolocation and abuse data, scores them by risk, and visualises everything in a live web dashboard.

Built in Python 3.11 with Flask, SQLite, Chart.js, and Leaflet.js — no ORMs, no heavy frameworks, no cloud dependencies.

---

## Live Demo (Local)

```bash
python parser.py --log-file sample_auth.log --threshold 5
python enricher.py --threshold 5
python app.py
# Open http://127.0.0.1:5000
```

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [File Structure](#3-file-structure)
4. [Layer 1 — Log Parser](#4-layer-1--log-parser)
5. [Layer 2 — Enrichment & Scoring](#5-layer-2--enrichment--scoring)
6. [Layer 3 — Flask Dashboard](#6-layer-3--flask-dashboard)
7. [Design Decisions](#7-design-decisions)
8. [Installation & Usage](#8-installation--usage)
9. [Sample Output](#9-sample-output)

---

## 1. Project Overview

SSH brute-force attacks are one of the most common threats against internet-facing Linux servers. Every failed login attempt leaves a trace in `/var/log/auth.log`. The problem is that this file is raw, unstructured text — thousands of lines with no easy way to identify which IPs are genuinely dangerous versus which ones made a few mistakes.

This tool solves that by:

- **Parsing** the raw log with regex to extract every failed login attempt
- **Aggregating** attempts per IP to find repeat offenders
- **Enriching** flagged IPs with real-world threat intelligence (location, global abuse history)
- **Scoring** each IP with a composite risk score (0–100)
- **Visualising** everything in a live dashboard — table, timeline, world map

The end result is a system where a security analyst (or a student) can run one pipeline and immediately know: *which IPs are dangerous, where they're from, and what to do about them.*

---

## 2. Architecture

The project is split into three independent layers. Each layer can run on its own — you don't need the dashboard to use the parser, and you don't need the enricher to see the parsed data.

```
┌─────────────────────────────────────────────────────────┐
│                     LAYER 1 — PARSER                    │
│  /var/log/auth.log  →  regex  →  SQLite (attempts)      │
│  CLI: --log-file, --threshold, --output [json|csv|txt]  │
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────┐
│                  LAYER 2 — ENRICHMENT                   │
│  flagged IPs  →  ip-api.com  →  GeoIP data              │
│             →  AbuseIPDB API  →  abuse score            │
│             →  risk scorer    →  0–100 score            │
│  SQLite (enriched_ips)                                  │
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────┐
│                  LAYER 3 — DASHBOARD                    │
│  Flask API  →  /api/ips, /api/timeline, /api/stats      │
│  Pages: IP Table | Attack Timeline | World Map          │
│  Block Panel: generate iptables DROP rules              │
└─────────────────────────────────────────────────────────┘
```

**Data flow through SQLite:**

```
auth.log
   └─► attempts table (ip, username, timestamp, count)
              └─► enriched_ips table (+ country, city, lat, lon, abuse_score, risk_score)
                         └─► Flask API ──► Browser Dashboard
```

---

## 3. File Structure

```
ssh-threat-detection/
│
├── parser.py          # Layer 1: log parsing, regex, SQLite writer, CLI
├── enricher.py        # Layer 2: GeoIP + AbuseIPDB API calls, DB writer
├── scorer.py          # Layer 2: risk scoring, threat report, iptables output
├── app.py             # Layer 3: Flask backend, API endpoints, page routes
│
├── templates/
│   ├── base.html      # Shared navbar, stats bar, JS utilities
│   ├── table.html     # Page 1: sortable IP table with risk badges
│   ├── timeline.html  # Page 2: Chart.js attack timeline
│   └── map.html       # Page 3: Leaflet.js world map
│
├── static/
│   └── style.css      # Full dashboard styling (dark cyberpunk theme)
│
├── sample_auth.log    # Realistic test log (51 events, 8 IPs)
├── requirements.txt   # Python dependencies
└── data/
    └── threats.db     # SQLite database (auto-created by parser.py)
```

---

## 4. Layer 1 — Log Parser

**File:** `parser.py`

### What it does

Reads an SSH auth log line by line, extracts failed login events using regex, stores them in SQLite, and outputs flagged IPs in your chosen format.

### The regex — thinking process

The core challenge of Layer 1 was writing a regex that correctly captures failed logins while ignoring everything else (CRON jobs, successful logins, GNOME sessions, etc.).

A typical failed login line looks like this:
```
Jan 15 03:12:01 server sshd[1234]: Failed password for root from 192.168.1.101 port 22 ssh2
```

But there's a variation for unknown usernames:
```
Jan 15 03:17:01 server sshd[1240]: Failed password for invalid user hacker from 91.108.4.11 port 33210 ssh2
```

The key insight was the phrase `"invalid user"` — it appears optionally between `"for"` and the username. The regex uses `(?:invalid user )?` to make that part optional, capturing both cases with one pattern:

```python
FAILED_LOGIN_RE = re.compile(
    r"^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r".+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(?P<username>\S+)"
    r" from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    r" port \d+"
)
```

Named capture groups (`?P<name>`) were used instead of positional groups so the code is self-documenting — `match.group("ip")` is clearer than `match.group(4)`.

### Why SQLite — not a file or dict

Early in the design, the simplest approach would have been to store results in a Python dictionary in memory. But that means:
- Results disappear when the script exits
- Layer 2 (enricher) has no way to read Layer 1's output without re-parsing
- The Flask dashboard has nothing to query

SQLite solves all three problems. It's a file-based database — no server to run, no installation needed — and it lets all three layers share data through a common `threats.db` file. Each layer reads and writes to the same database independently.

The decision to use **raw sqlite3** (no ORM like SQLAlchemy) was deliberate — it keeps dependencies minimal and makes the SQL queries explicit and readable.

### Why two tables

```sql
attempts     -- one row per individual failed login event
enriched_ips -- one row per IP, with GeoIP + abuse + risk data
```

These are separated because they serve different purposes. `attempts` is the raw event log — every single failed login with its timestamp and username. `enriched_ips` is derived intelligence — one summary row per IP with all the external API data. Keeping them separate means you can re-run the enricher without re-parsing the log, and you can query raw events independently of enrichment.

### The threshold logic

The `--threshold` flag (default: 5) controls which IPs get flagged. This is implemented as a `HAVING` clause in SQL:

```sql
SELECT ip, SUM(count) AS total
FROM attempts
GROUP BY ip
HAVING total >= ?
```

This is more efficient than filtering in Python because the database does the aggregation. The threshold of 5 was chosen as a sensible default — one or two failed attempts could be a user mistyping their password, but five or more in a session strongly suggests automated brute-forcing.

---

## 5. Layer 2 — Enrichment & Scoring

**Files:** `enricher.py`, `scorer.py`

### Why enrich at all?

Knowing that `185.220.101.5` made 6 failed login attempts tells you very little on its own. But knowing that this IP is located in Brandenburg, Germany, has been reported 157 times globally, and has a 100% abuse confidence score — that tells you this is a known Tor exit node used for automated attacks worldwide. Enrichment transforms raw data into actionable intelligence.

### GeoIP — why ip-api.com

Several GeoIP services were considered:

| Service | Cost | Key required | Rate limit |
|---|---|---|---|
| MaxMind GeoLite2 | Free | Yes (registration) | Local DB |
| ip-api.com | Free | **No** | 45 req/min |
| ipinfo.io | Free tier | Yes | 50k/month |
| ipstack | Free tier | Yes | 100/month |

**ip-api.com** was chosen because it requires no API key, has a generous free rate limit, and returns all needed fields (country, city, lat, lon) in a single JSON response. For a tool meant to run locally without setup friction, this was the clear winner.

The 1.5 second delay between requests (`REQUEST_DELAY = 1.5`) was added to stay comfortably within the 45 requests/minute limit.

Private/local IPs (like `192.168.x.x`) correctly return no geo data — the tool handles this gracefully by storing `None` values rather than crashing.

### AbuseIPDB — why this service

AbuseIPDB is the industry-standard crowdsourced threat intelligence database for IP reputation. When a server admin blocks a malicious IP, they often report it to AbuseIPDB. The result is a database of hundreds of millions of reports from real-world attacks.

The `abuseConfidenceScore` (0–100) is calculated by AbuseIPDB based on the number and recency of reports, the diversity of reporters, and the categories of abuse. A score of 100 means the IP has been consistently reported as malicious by many independent sources.

The `maxAgeInDays: 90` parameter was chosen to focus on recent activity — an IP that was malicious two years ago but has since been reassigned shouldn't be penalised as heavily.

### The risk scoring formula — thinking process

The composite risk score needed to balance two signals:

1. **Local count** — how many times did this IP attack *our* server?
2. **Global abuse score** — how malicious is this IP *worldwide*?

The formula:
```
risk_score = (normalized_local_count × 0.4) + (abuse_score × 0.6)
```

**Why 40/60 weighting?** Global reputation (AbuseIPDB) is given more weight because it represents verified, crowdsourced intelligence from thousands of servers. Local count alone can be misleading — a legitimate user who forgot their password might make 10 attempts, while a sophisticated attacker might make exactly 5 attempts (to stay under basic thresholds) but have a 95% global abuse score.

**Why normalize local count?** Raw counts aren't directly comparable to a 0–100 percentage score. The local count is normalized against the maximum count seen in the current batch (capped at 20) to produce a 0–100 value before applying the weight.

**Risk labels:**
```
CRITICAL  ≥ 75  — known malicious, active attacker
HIGH      ≥ 50  — significant risk, likely automated
MEDIUM    ≥ 25  — suspicious, worth monitoring
LOW       < 25  — low confidence threat
```

These thresholds were chosen to match common security tooling conventions (similar to CVSS severity levels).

---

## 6. Layer 3 — Flask Dashboard

**Files:** `app.py`, `templates/`, `static/`

### Why Flask

Flask was chosen over alternatives for these reasons:

| Framework | Why not chosen |
|---|---|
| Django | Too heavy — brings ORM, admin, migrations we don't need |
| FastAPI | Excellent for APIs but adds async complexity for a local tool |
| Streamlit | Good for data apps but limited UI control, not vanilla JS |
| **Flask** | Minimal, explicit, pairs perfectly with vanilla JS frontend |

Flask's `sqlite3` integration is straightforward — each request opens a connection, queries, and closes. No connection pooling needed for a single-user local tool.

### API design

The backend exposes three data endpoints and one action endpoint:

```
GET  /api/ips       — all enriched IPs (joined with attempt counts)
GET  /api/timeline  — attempts grouped by hour (for Chart.js)
GET  /api/stats     — summary counts for the header stats bar
POST /api/block/:ip — generate iptables DROP rule for one IP
```

The frontend is entirely JavaScript-driven — pages load empty and fetch data from these APIs. This separation means the API could later be consumed by other tools (a CLI, a mobile app, a SIEM integration) without changing the backend.

### Why Chart.js for the timeline

Chart.js was chosen over D3.js because:
- D3 requires writing SVG manipulation code manually — significant overhead for a bar chart
- Chart.js provides a bar chart in ~20 lines of config
- It's available on cdnjs.cloudflare.com with no npm/build step needed

The bars are colour-coded by volume: red for ≥10 attempts/hour (active brute force), orange for ≥5 (elevated), cyan for lower counts.

### Why Leaflet.js for the world map

Leaflet.js was chosen for the world map over alternatives:

| Option | Why not chosen |
|---|---|
| Google Maps | Requires API key and billing |
| Mapbox | Requires API key |
| D3 geo projection | Complex to implement, no tiles |
| **Leaflet + OSM** | Free, no key, OpenStreetMap tiles, simple API |

The map tiles use a CSS `filter: invert(1) hue-rotate(180deg)` trick to convert the standard OpenStreetMap light tiles into a dark map that matches the dashboard's colour scheme — without needing a paid dark tile provider.

Circle markers are sized by risk score (`radius = risk_score / 5`) so more dangerous IPs are visually larger on the map.

### The dark terminal aesthetic

The dashboard uses a deliberate "cybersecurity terminal" aesthetic:
- **Font:** Share Tech Mono (monospace) for data, Rajdhani for UI labels
- **Colours:** Deep navy backgrounds (`#090d13`), cyan accent (`#00d4ff`), red/orange/yellow/green for risk levels
- **Scanlines:** A CSS `repeating-linear-gradient` overlay simulates a CRT monitor effect
- **Animations:** The navbar dot pulses to indicate the system is live

This aesthetic was chosen because it matches the domain — this is a security tool, not a business dashboard. The visual language should communicate that you're looking at raw threat data.

---

## 7. Design Decisions

### No ORM

Raw `sqlite3` was used throughout. ORMs like SQLAlchemy add abstraction that hides the actual queries being run. For a project where understanding the data flow is important, explicit SQL is better. It's also one fewer dependency.

### Each file runs independently

Every Python file can be run on its own:
- `parser.py` works without `enricher.py` being present
- `enricher.py` only needs the database that `parser.py` creates
- `scorer.py` only reads from the database
- `app.py` only reads from the database

This layered independence means you can test, debug, and run each component separately. It also means the tool degrades gracefully — if AbuseIPDB is down, the enricher still runs and writes GeoIP data.

### Idempotent runs

Running `parser.py` twice on the same log file produces the same result — it clears the `attempts` table before inserting. Running `enricher.py` twice skips already-enriched IPs unless `--force` is passed. This makes repeated runs safe and predictable.

### Sample log design

The `sample_auth.log` was carefully designed to include:
- IPs with high failure counts (to test threshold logic)
- IPs that span multiple hours (to test timeline grouping)
- `invalid user` lines (to test the regex variation)
- Successful logins (to verify they're correctly ignored)
- Private IPs like `192.168.x.x` (to test graceful GeoIP failure)
- Real public IPs like `185.220.101.5` (a known Tor exit node that AbuseIPDB scores at 100%)

---

## 8. Installation & Usage

### Requirements

- Python 3.10+
- pip

### Install dependencies

```bash
pip install -r requirements.txt
```

### Full pipeline

```bash
# Step 1: Parse log file and store results
python parser.py --log-file sample_auth.log --threshold 5

# Step 2: Enrich flagged IPs with GeoIP + AbuseIPDB data
python enricher.py --threshold 5

# Step 3: View scored threat report in terminal
python scorer.py --output txt

# Step 4: Launch web dashboard
python app.py
# Open http://127.0.0.1:5000
```

### CLI reference

**parser.py**
```
--log-file PATH     Path to auth.log file (required)
--threshold N       Minimum failures to flag an IP (default: 5)
--output FORMAT     Output format: txt | json | csv (default: txt)
--db PATH           Path to SQLite database (default: data/threats.db)
```

**enricher.py**
```
--threshold N       Match parser threshold (default: 5)
--force             Re-enrich already-processed IPs
--dry-run           Run without writing to database
--db PATH           Path to SQLite database
```

**scorer.py**
```
--output FORMAT     txt | json | csv (default: txt)
--min-risk SCORE    Only show IPs above this risk score (default: 0)
--iptables          Also print iptables DROP rules
--db PATH           Path to SQLite database
```

**app.py**
```
--port N            Port to run on (default: 5000)
--host HOST         Host to bind to (default: 127.0.0.1)
--debug             Enable Flask debug mode
```

### Using with a real auth.log

```bash
# Copy log to avoid permission issues
sudo cp /var/log/auth.log ./real_auth.log
sudo chown $USER:$USER ./real_auth.log

# Run pipeline
python parser.py --log-file real_auth.log --threshold 10
python enricher.py --threshold 10
python app.py
```

---

## 9. Sample Output

### Terminal (scorer.py --iptables)

```
════════════════════════════════════════════════════════════════════════
  SSH THREAT DETECTION — RISK REPORT
════════════════════════════════════════════════════════════════════════

  🔴 CRITICAL   185.220.101.5      Risk:  78.46/100
  Location      : Brandenburg, Germany
  Abuse Score   : 100/100  (157 global reports)
  Local Failures: 6

  🟡 MEDIUM     192.168.1.101      Risk:  40.00/100
  Location      : Unknown (private IP)
  Local Failures: 13

# iptables DROP rules
iptables -A INPUT -s 185.220.101.5 -j DROP   # CRITICAL | Germany
iptables -A INPUT -s 192.168.1.101 -j DROP   # MEDIUM | Unknown
```

### Dashboard pages

- **IP Table** — sortable by any column, filterable by IP/country/username, risk badges, abuse percentage bars, one-click block button
- **Attack Timeline** — bar chart of attempts per hour, colour-coded red/orange/cyan by severity
- **World Map** — dark world map with circle markers sized by risk score, click for full IP details

---

## Tech Stack

| Component | Technology | Why |
|---|---|---|
| Language | Python 3.11 | Standard for security tooling, rich stdlib |
| Database | SQLite (raw sqlite3) | Zero-config, file-based, no ORM overhead |
| Log parsing | Python `re` module | Built-in, no dependencies |
| GeoIP | ip-api.com | Free, no API key required |
| Threat intel | AbuseIPDB v2 API | Industry standard IP reputation database |
| Web framework | Flask | Minimal, explicit, no bloat |
| Charts | Chart.js 4.4 | Simple config, CDN-hosted, no build step |
| Maps | Leaflet.js 1.9 | Free, OpenStreetMap tiles, no API key |
| Frontend | Vanilla JS + CSS | No framework needed for this scope |
| Fonts | Share Tech Mono + Rajdhani | Terminal aesthetic, free on Google Fonts |

---

## Author

Sara Liz Thomas — built as a college cybersecurity project demonstrating log analysis, threat intelligence integration, and security dashboard development.
