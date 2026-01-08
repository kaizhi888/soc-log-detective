# SOC-Style Log Detective

**Suspicious Login Detector + Case Report Generator**

A Python-based cybersecurity tool that ingests authentication logs, detects suspicious patterns using rule-based detectors, and generates professional incident reports. Designed for solo SOC analysts and interview demonstrations.

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

## Features

- **JSONL Log Ingestion**: Parse authentication logs from any provider (Azure AD, CloudTrail, custom)
- **Three Detection Rules**:
  - 🌍 **Impossible Travel**: Detects logins from geographically distant locations within impossible timeframes
  - 🔓 **Brute Force / Credential Stuffing**: Identifies failure chains followed by successful authentication
  - 📱 **New Device Anomaly**: Flags logins from previously unseen devices or user agents
- **Case Correlation**: Groups related alerts into unified security incidents
- **Dual Output**: Machine-readable JSON + human-friendly Markdown reports
- **Interactive UI**: Streamlit dashboard for visual analysis

## Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
│  JSONL Logs     │────▶│   Ingest     │────▶│  AuthEvents     │
│  (sample.jsonl) │     │  (parse)     │     │  (normalized)   │
└─────────────────┘     └──────────────┘     └────────┬────────┘
                                                      │
                        ┌─────────────────────────────┼─────────────────────────────┐
                        │                             │                             │
                        ▼                             ▼                             ▼
              ┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
              │ Impossible      │         │ Fail→Success    │         │ New Device      │
              │ Travel Detector │         │ Chain Detector  │         │ Detector        │
              └────────┬────────┘         └────────┬────────┘         └────────┬────────┘
                       │                           │                           │
                       └───────────────────────────┼───────────────────────────┘
                                                   ▼
                                          ┌──────────────┐
                                          │    Alerts    │
                                          │   (scored)   │
                                          └──────┬───────┘
                                                 │
                                                 ▼
                                          ┌──────────────┐
                                          │  Correlate   │
                                          │  into Cases  │
                                          └──────┬───────┘
                                                 │
                        ┌────────────────────────┼────────────────────────┐
                        ▼                        ▼                        ▼
                 ┌─────────────┐          ┌─────────────┐          ┌─────────────┐
                 │ alerts.json │          │ cases.json  │          │ cases.md    │
                 │ (machine)   │          │ (machine)   │          │ (human)     │
                 └─────────────┘          └─────────────┘          └─────────────┘
```

## Quick Start

### Installation

```bash
# Clone the repository
cd "SOC-Style Log Detective"

# Install in development mode
pip install -e ".[dev]"

# Or using Make
make install
```

### Run Demo

```bash
# Using the CLI
log-detective demo

# Or using Make
make demo

# Or using Python module
python -m log_detective demo
```

This analyzes the sample logs and creates:
- `out/alerts.json` - All detected alerts
- `out/cases.json` - Correlated cases
- `out/cases.md` - Human-readable report

### Launch Interactive UI

```bash
# Using CLI
log-detective ui

# Or using Make
make ui

# Or directly with Streamlit
streamlit run src/log_detective/ui_streamlit.py
```

## CLI Usage

```bash
# Full analysis with custom thresholds
log-detective analyze \
    --input samples/sample_auth_logs.jsonl \
    --outdir out/ \
    --speed-threshold 900 \
    --max-travel-hours 6 \
    --failure-window 20 \
    --min-failures 8 \
    --case-window 8

# Enable debug logging
log-detective analyze --input logs.jsonl --debug
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | Required | Path to JSONL log file |
| `--outdir` | `out/` | Output directory |
| `--speed-threshold` | 900 | Impossible travel speed (km/h) |
| `--max-travel-hours` | 6 | Max hours for travel detection |
| `--failure-window` | 20 | Failure chain window (minutes) |
| `--min-failures` | 8 | Min failures before success |
| `--case-window` | 8 | Case correlation window (hours) |
| `--debug` | False | Enable debug logging |

## Detectors

### 1. Impossible Travel

Detects when a user successfully authenticates from two geographically distant locations within an impossible timeframe.

**Logic:**
- Calculate haversine distance between consecutive success logins
- Compute required travel speed = distance_km / hours_between
- Flag if speed > threshold AND time < max_hours

**Severity:**
- 🔴 **Critical**: Speed > 2000 km/h AND time < 2 hours
- 🟠 **High**: Speed > 900 km/h AND time < 6 hours
- 🟡 **Medium**: Otherwise when triggered

### 2. Failure → Success Chain

Identifies brute force or credential stuffing attempts where multiple failed logins are followed by a successful authentication.

**Logic:**
- Group failures by user + IP within time window
- Flag if failures exceed threshold then success occurs

**Severity:**
- 🟠 **High**: Same-IP failures ≥ 12 then success
- 🟡 **Medium**: Failures ≥ threshold then success
- 🟢 **Low**: Small chain but still suspicious

### 3. New Device Anomaly

Flags successful logins from devices or user agents never seen before for that user.

**Logic:**
- Build baseline of known device_ids and UA families per user
- Flag success from new device
- Risk bump if also new country

**Severity:**
- 🟠 **High**: New device + new country
- 🟡 **Medium**: New device only

## Log Format

Input logs must be JSONL (one JSON object per line) with these fields:

```json
{
  "event_id": "evt-001",
  "ts": "2025-01-01T08:00:00Z",
  "provider": "azure",
  "user": "alice@corp.com",
  "action": "login_attempt",
  "source_ip": "203.0.113.50",
  "country": "US",
  "city": "New York",
  "lat": 40.7128,
  "lon": -74.0060,
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
  "device_id": "dev-abc123",
  "auth_method": "password",
  "result": "success",
  "failure_reason": null
}
```

**Required fields:** `event_id`, `ts`, `user`, `source_ip`, `result`

**Result values:** `"success"` or `"failure"` (this is the source of truth)

## Output Examples

### alerts.json

```json
[
  {
    "alert_id": "alert-001",
    "detector": "impossible_travel",
    "ts_start": "2025-01-01T08:00:00Z",
    "ts_end": "2025-01-01T09:30:00Z",
    "user": "alice@corp.com",
    "severity": "critical",
    "score": 95,
    "title": "Impossible Travel Detected",
    "description": "User logged in from New York and Tokyo within 1.5 hours",
    "evidence": {
      "ips": ["203.0.113.50", "198.51.100.25"],
      "countries": ["US", "JP"],
      "distance_km": 10838,
      "speed_kmh": 7225,
      "hours_between": 1.5
    },
    "related_event_ids": ["evt-001", "evt-002"]
  }
]
```

### cases.md

```markdown
# Case RPT-001 — alice@corp.com — CRITICAL

## Summary
High-severity security incident detected for user alice@corp.com involving 
impossible travel patterns suggesting potential account compromise.

## Alerts

| Detector | Severity | Score | Time Range |
|----------|----------|-------|------------|
| impossible_travel | critical | 95 | 08:00 - 09:30 UTC |

## Timeline

- **08:00:00 UTC** | SUCCESS | 203.0.113.50 | New York, US | Chrome/Windows
- **09:30:00 UTC** | SUCCESS | 198.51.100.25 | Tokyo, JP | Chrome/Windows

## Evidence

- Distance: 10,838 km
- Time between: 1.5 hours
- Required speed: 7,225 km/h (impossible)

## Recommended Actions

- [ ] Contact user to verify login activity
- [ ] Reset user credentials
- [ ] Enable/verify MFA enrollment
- [ ] Review conditional access policies
- [ ] Block suspicious source IPs
```

## Testing

```bash
# Run all tests
make test

# Or with pytest directly
pytest tests/ -v

# With coverage
pytest tests/ --cov=src/log_detective
```

## How to Demo in Interview

1. **Run the demo:**
   ```bash
   make demo
   ```

2. **Show the case report:**
   ```bash
   cat out/cases.md
   ```

3. **Explain one case timeline:**
   - Point to the impossible travel case
   - Show NYC → Tokyo in 1.5 hours = 7,225 km/h
   - Explain this is physically impossible (planes max ~900 km/h)

4. **Explain the detection approach:**
   - "I implemented three rule-based detectors targeting common attack patterns"
   - "Each detector uses configurable thresholds for tuning"
   - "Alerts are correlated into cases by user and time proximity"
   - "The scoring system combines base severity with contextual bonuses"

5. **Launch the UI (optional):**
   ```bash
   make ui
   ```
   - Upload a file
   - Adjust thresholds
   - Show real-time analysis

## Project Structure

```
SOC-Style Log Detective/
├── src/
│   └── log_detective/
│       ├── __init__.py
│       ├── __main__.py
│       ├── schema.py          # Pydantic models
│       ├── ingest.py          # JSONL parsing
│       ├── detectors/
│       │   ├── __init__.py
│       │   ├── impossible_travel.py
│       │   ├── fail_success_chain.py
│       │   └── new_device_ua.py
│       ├── correlate.py       # Case correlation
│       ├── scoring.py         # Severity scoring
│       ├── report.py          # Report generation
│       ├── cli.py             # Typer CLI
│       └── ui_streamlit.py    # Streamlit UI
├── samples/
│   └── sample_auth_logs.jsonl
├── tests/
│   ├── conftest.py
│   ├── test_ingest.py
│   ├── test_detectors.py
│   ├── test_report.py
│   └── test_e2e.py
├── out/                       # Generated outputs
├── pyproject.toml
├── Makefile
└── README.md
```

## License

MIT License - See LICENSE file for details.

## Contributing

This is a solo project for learning and demonstration purposes. Feel free to fork and adapt for your own use cases.
