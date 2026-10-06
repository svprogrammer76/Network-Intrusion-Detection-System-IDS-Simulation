# Network Intrusion Detection System (IDS) Simulation

A lightweight Python/Flask dashboard that simulates common network intrusion patterns and visualizes recent detections in a SOC-style interface.

## Features

- Simulated IDS event generation for a range of threats
- Real-time dashboard metrics for total, blocked, and critical events
- Breakdown of attack categories and severity levels
- Quick scenario buttons for port scanning, brute-force login attempts, DDoS bursts, beaconing, and exfiltration
- REST API endpoints for health checks, summary data, and event retrieval

## Quick start

1. Create and activate a virtual environment if desired.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Start the app:

```bash
python app.py
```

4. Open the browser at `http://localhost:5000`.

## API endpoints

- `GET /api/health` — service health check
- `GET /api/summary` — aggregate alert metadata
- `GET /api/events` — latest IDS events
- `GET /api/simulate?scenario=<name>&count=<n>` — generate new simulated events

## Included scenarios

- `port_scan`
- `brute_force`
- `ddos`
- `beaconing`
- `exfiltration`
