from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import random
from typing import Any

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

SCENARIOS = {
    "port_scan": {
        "signature": "PORT_SCAN_DETECTED",
        "category": "Reconnaissance",
        "status": "blocked",
        "severity": "high",
        "details": "Multiple connection attempts across a large port range from a single source IP.",
    },
    "brute_force": {
        "signature": "CREDENTIAL_STUFFING",
        "category": "Authentication Abuse",
        "status": "blocked",
        "severity": "critical",
        "details": "Repeated failed authentication attempts against privileged accounts.",
    },
    "ddos": {
        "signature": "DISTRIBUTED_DENIAL_OF_SERVICE",
        "category": "Availability Attack",
        "status": "rate_limited",
        "severity": "critical",
        "details": "High-rate traffic burst from distributed sources targeted a critical endpoint.",
    },
    "beaconing": {
        "signature": "MALWARE_BEACONING",
        "category": "Command and Control",
        "status": "quarantined",
        "severity": "medium",
        "details": "Periodic outbound communication to a suspicious external endpoint.",
    },
    "exfiltration": {
        "signature": "DATA_EXFILTRATION",
        "category": "Sensitive Data Loss",
        "status": "investigating",
        "severity": "critical",
        "details": "Unusual outbound transfer volume exceeds the normal daily baseline.",
    },
}

SYSTEM_PREFIXES = ["10.0.0.", "172.16.0.", "192.168.1.", "198.51.100."]
EXTERNAL_PREFIXES = ["8.8.8.", "203.0.113.", "45.79.120.", "54.87.33."]
TARGETS = [
    "auth.service.internal",
    "gateway.edge.internal",
    "db.primary.internal",
    "web.frontend.internal",
    "api.internal",
    "mailrelay.internal",
]


def _random_ip(prefixes: list[str]) -> str:
    prefix = random.choice(prefixes)
    return f"{prefix}{random.randint(1, 254)}"


def _make_event(scenario_name: str, index: int) -> dict[str, Any]:
    scenario = SCENARIOS[scenario_name]
    if scenario_name == "port_scan":
        source_ip = _random_ip(SYSTEM_PREFIXES)
        destination_ip = _random_ip(SYSTEM_PREFIXES)
        target = random.choice(TARGETS)
    elif scenario_name == "ddos":
        source_ip = _random_ip(EXTERNAL_PREFIXES)
        destination_ip = _random_ip(SYSTEM_PREFIXES)
        target = random.choice(["api.internal", "gateway.edge.internal"])
    elif scenario_name == "beaconing":
        source_ip = _random_ip(SYSTEM_PREFIXES)
        destination_ip = _random_ip(EXTERNAL_PREFIXES)
        target = "cdn.update-node.net"
    elif scenario_name == "exfiltration":
        source_ip = _random_ip(SYSTEM_PREFIXES)
        destination_ip = _random_ip(EXTERNAL_PREFIXES)
        target = "archive.shadow-bucket.net"
    else:
        source_ip = _random_ip(EXTERNAL_PREFIXES)
        destination_ip = _random_ip(SYSTEM_PREFIXES)
        target = random.choice(TARGETS)

    timestamp = (datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 180), seconds=random.randint(0, 59))).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "id": f"IDS-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{index:04d}",
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "target": target,
        "signature": scenario["signature"],
        "category": scenario["category"],
        "severity": scenario["severity"],
        "status": scenario["status"],
        "details": scenario["details"],
    }


def generate_events(scenario_name: str | None = None, count: int = 25) -> list[dict[str, Any]]:
    if count < 1:
        count = 1
    if count > 250:
        count = 250

    names = list(SCENARIOS)
    scenarios = [scenario_name] if scenario_name in SCENARIOS else random.choices(names, k=count)
    events = []
    for idx in range(count):
        selected = scenario_name if scenario_name in SCENARIOS else scenarios[idx]
        events.append(_make_event(selected, idx))
    return sorted(events, key=lambda item: item["timestamp"], reverse=True)


def summarize_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    severity_counts = Counter(event["severity"] for event in events)
    category_counts = Counter(event["category"] for event in events)
    blocked_count = sum(1 for event in events if event["status"] in {"blocked", "quarantined", "rate_limited"})
    critical_count = severity_counts.get("critical", 0)

    if critical_count >= 2 or severity_counts.get("high", 0) >= 5:
        risk_level = "Critical"
    elif critical_count >= 1 or severity_counts.get("high", 0) >= 2:
        risk_level = "High"
    elif severity_counts.get("medium", 0) >= 3:
        risk_level = "Elevated"
    else:
        risk_level = "Normal"

    latest = max(events, key=lambda event: event["timestamp"]) if events else {"timestamp": "N/A"}

    return {
        "total_events": len(events),
        "blocked_events": blocked_count,
        "critical_events": critical_count,
        "risk_level": risk_level,
        "severity_breakdown": {
            "low": severity_counts.get("low", 0),
            "medium": severity_counts.get("medium", 0),
            "high": severity_counts.get("high", 0),
            "critical": critical_count,
        },
        "top_attack_types": dict(category_counts.most_common(5)),
        "last_updated": latest.get("timestamp", "N/A"),
    }


app.config["IDS_EVENTS"] = generate_events(count=30)


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/api/health")
def health() -> Any:
    return jsonify({
        "status": "ok",
        "service": "network-ids-simulator",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })


@app.route("/api/summary")
def summary() -> Any:
    return jsonify(summarize_events(app.config["IDS_EVENTS"]))


@app.route("/api/events")
def events() -> Any:
    return jsonify({"events": app.config["IDS_EVENTS"][:20]})


@app.route("/api/simulate")
def simulate() -> Any:
    scenario_name = request.args.get("scenario")
    count = int(request.args.get("count", 10))
    generated = generate_events(scenario_name=scenario_name, count=count)
    app.config["IDS_EVENTS"] = generated + app.config["IDS_EVENTS"]
    return jsonify({
        "scenario": scenario_name or "mixed",
        "generated": len(generated),
        "summary": summarize_events(app.config["IDS_EVENTS"]),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
