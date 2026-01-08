"""Pytest fixtures for Log Detective tests."""

import json
import pytest
from datetime import datetime, timedelta
from pathlib import Path


@pytest.fixture
def sample_event_data():
    """Return a sample event dict."""
    return {
        "event_id": "test-001",
        "ts": "2025-01-01T08:00:00Z",
        "provider": "azure",
        "user": "test@corp.com",
        "action": "login_attempt",
        "source_ip": "192.168.1.1",
        "country": "US",
        "city": "New York",
        "lat": 40.7128,
        "lon": -74.006,
        "user_agent": "Mozilla/5.0 Chrome/120.0",
        "device_id": "dev-test-001",
        "auth_method": "password",
        "result": "success",
        "failure_reason": None,
    }


@pytest.fixture
def tmp_jsonl(tmp_path, sample_event_data):
    """Create a temporary JSONL file."""
    file_path = tmp_path / "test_logs.jsonl"
    with open(file_path, "w") as f:
        f.write(json.dumps(sample_event_data) + "\n")
    return file_path


@pytest.fixture
def impossible_travel_events():
    """Events for impossible travel detection."""
    return [
        {
            "event_id": "it-001",
            "ts": "2025-01-01T08:00:00Z",
            "user": "travel@corp.com",
            "source_ip": "1.1.1.1",
            "country": "US",
            "city": "New York",
            "lat": 40.7128,
            "lon": -74.006,
            "result": "success",
        },
        {
            "event_id": "it-002",
            "ts": "2025-01-01T09:30:00Z",
            "user": "travel@corp.com",
            "source_ip": "2.2.2.2",
            "country": "JP",
            "city": "Tokyo",
            "lat": 35.6762,
            "lon": 139.6503,
            "result": "success",
        },
    ]


@pytest.fixture
def brute_force_events():
    """Events for brute force detection."""
    events = []
    base_time = datetime(2025, 1, 1, 10, 0, 0)
    
    # 10 failures
    for i in range(10):
        events.append({
            "event_id": f"bf-{i:03d}",
            "ts": (base_time + timedelta(minutes=i)).isoformat() + "Z",
            "user": "brute@corp.com",
            "source_ip": "10.0.0.1",
            "country": "US",
            "result": "failure",
            "failure_reason": "invalid_password",
        })
    
    # Success after failures
    events.append({
        "event_id": "bf-success",
        "ts": (base_time + timedelta(minutes=11)).isoformat() + "Z",
        "user": "brute@corp.com",
        "source_ip": "10.0.0.1",
        "country": "US",
        "result": "success",
    })
    
    return events


@pytest.fixture
def new_device_events():
    """Events for new device detection."""
    base_time = datetime(2025, 1, 1, 8, 0, 0)
    
    return [
        # Baseline login
        {
            "event_id": "nd-001",
            "ts": base_time.isoformat() + "Z",
            "user": "newdev@corp.com",
            "source_ip": "192.168.1.1",
            "country": "US",
            "device_id": "dev-known-001",
            "user_agent": "Mozilla/5.0 Chrome/120.0",
            "result": "success",
        },
        # New device login
        {
            "event_id": "nd-002",
            "ts": (base_time + timedelta(hours=2)).isoformat() + "Z",
            "user": "newdev@corp.com",
            "source_ip": "10.10.10.10",
            "country": "RU",
            "device_id": "dev-new-suspicious",
            "user_agent": "Mozilla/5.0 Safari/604.1",
            "result": "success",
        },
    ]
