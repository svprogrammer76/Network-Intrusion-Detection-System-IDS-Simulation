from __future__ import annotations

from app import app


def test_health_check() -> None:
    client = app.test_client()
    response = client.get('/api/health')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'ok'
    assert data['service'] == 'network-ids-simulator'


def test_summary_has_expected_metrics() -> None:
    client = app.test_client()
    response = client.get('/api/summary')
    assert response.status_code == 200
    data = response.get_json()
    assert 'total_events' in data
    assert 'blocked_events' in data
    assert 'critical_events' in data
    assert 'risk_level' in data
    assert data['total_events'] > 0


def test_simulate_endpoint_generates_new_events() -> None:
    client = app.test_client()
    response = client.get('/api/simulate?scenario=port_scan&count=5')
    assert response.status_code == 200
    data = response.get_json()
    assert data['scenario'] == 'port_scan'
    assert data['generated'] == 5
    assert data['summary']['total_events'] > 0


def test_recent_events_are_returned() -> None:
    client = app.test_client()
    response = client.get('/api/events')
    assert response.status_code == 200
    data = response.get_json()
    assert 'events' in data
    assert len(data['events']) > 0
    assert 'signature' in data['events'][0]
