"""Tests for detection algorithms."""

import json
import pytest
from datetime import datetime

from log_detective.schema import AuthEvent
from log_detective.detectors.impossible_travel import detect_impossible_travel
from log_detective.detectors.fail_success_chain import detect_fail_success_chain
from log_detective.detectors.new_device_ua import detect_new_device


def _make_event(data: dict) -> AuthEvent:
    """Create AuthEvent from dict with defaults."""
    defaults = {
        "provider": "test",
        "action": "login_attempt",
        "user_agent": None,
        "device_id": None,
        "auth_method": "password",
        "failure_reason": None,
        "city": None,
        "lat": None,
        "lon": None,
        "country": None,
    }
    return AuthEvent(**{**defaults, **data})


class TestImpossibleTravel:
    """Tests for impossible travel detector."""
    
    def test_detects_impossible_travel(self, impossible_travel_events):
        """Test detection of impossible travel pattern."""
        events = [_make_event(e) for e in impossible_travel_events]
        alerts = detect_impossible_travel(events)
        
        assert len(alerts) == 1
        assert alerts[0].detector == "impossible_travel"
        assert alerts[0].user == "travel@corp.com"
        assert alerts[0].severity in ["high", "critical"]
    
    def test_populates_related_event_ids(self, impossible_travel_events):
        """Test that related_event_ids is populated."""
        events = [_make_event(e) for e in impossible_travel_events]
        alerts = detect_impossible_travel(events)
        
        assert len(alerts[0].related_event_ids) == 2
        assert "it-001" in alerts[0].related_event_ids
        assert "it-002" in alerts[0].related_event_ids
    
    def test_populates_standardized_evidence(self, impossible_travel_events):
        """Test evidence has standardized keys."""
        events = [_make_event(e) for e in impossible_travel_events]
        alerts = detect_impossible_travel(events)
        
        evidence = alerts[0].evidence
        assert "ips" in evidence
        assert "device_ids" in evidence
        assert "countries" in evidence
        assert "distance_km" in evidence
        assert "speed_kmh" in evidence
    
    def test_no_alert_for_normal_travel(self):
        """Test no alert for plausible travel."""
        events = [
            _make_event({
                "event_id": "nt-001",
                "ts": "2025-01-01T08:00:00Z",
                "user": "normal@corp.com",
                "source_ip": "1.1.1.1",
                "lat": 40.7128,
                "lon": -74.006,
                "result": "success",
            }),
            _make_event({
                "event_id": "nt-002",
                "ts": "2025-01-01T20:00:00Z",  # 12 hours later
                "user": "normal@corp.com",
                "source_ip": "2.2.2.2",
                "lat": 51.5074,
                "lon": -0.1278,  # London
                "result": "success",
            }),
        ]
        
        alerts = detect_impossible_travel(events, max_hours=6)
        assert len(alerts) == 0


class TestFailSuccessChain:
    """Tests for fail→success chain detector."""
    
    def test_detects_brute_force(self, brute_force_events):
        """Test detection of brute force pattern."""
        events = [_make_event(e) for e in brute_force_events]
        alerts = detect_fail_success_chain(events, min_failures_same_ip=8)
        
        assert len(alerts) >= 1
        assert alerts[0].detector == "fail_success_chain"
        assert alerts[0].user == "brute@corp.com"
    
    def test_populates_related_event_ids(self, brute_force_events):
        """Test that related_event_ids includes failures + success."""
        events = [_make_event(e) for e in brute_force_events]
        alerts = detect_fail_success_chain(events, min_failures_same_ip=8)
        
        # Should include all failures + success
        assert len(alerts[0].related_event_ids) >= 10
        assert "bf-success" in alerts[0].related_event_ids
    
    def test_populates_standardized_evidence(self, brute_force_events):
        """Test evidence has standardized keys."""
        events = [_make_event(e) for e in brute_force_events]
        alerts = detect_fail_success_chain(events, min_failures_same_ip=8)
        
        evidence = alerts[0].evidence
        assert "ips" in evidence
        assert "device_ids" in evidence
        assert "countries" in evidence
        assert "failure_count" in evidence
    
    def test_no_alert_below_threshold(self):
        """Test no alert when failures below threshold."""
        events = [
            _make_event({
                "event_id": f"f-{i}",
                "ts": f"2025-01-01T10:{i:02d}:00Z",
                "user": "test@corp.com",
                "source_ip": "10.0.0.1",
                "result": "failure",
            })
            for i in range(3)  # Only 3 failures
        ]
        events.append(_make_event({
            "event_id": "s-001",
            "ts": "2025-01-01T10:05:00Z",
            "user": "test@corp.com",
            "source_ip": "10.0.0.1",
            "result": "success",
        }))
        
        alerts = detect_fail_success_chain(events, min_failures_same_ip=8)
        assert len(alerts) == 0


class TestNewDevice:
    """Tests for new device detector."""
    
    def test_detects_new_device(self, new_device_events):
        """Test detection of new device."""
        events = [_make_event(e) for e in new_device_events]
        alerts = detect_new_device(events)
        
        assert len(alerts) >= 1
        assert alerts[0].detector == "new_device_ua"
        assert alerts[0].user == "newdev@corp.com"
    
    def test_populates_related_event_ids(self, new_device_events):
        """Test that related_event_ids is populated."""
        events = [_make_event(e) for e in new_device_events]
        alerts = detect_new_device(events)
        
        assert len(alerts[0].related_event_ids) >= 1
        assert "nd-002" in alerts[0].related_event_ids
    
    def test_populates_standardized_evidence(self, new_device_events):
        """Test evidence has standardized keys."""
        events = [_make_event(e) for e in new_device_events]
        alerts = detect_new_device(events)
        
        evidence = alerts[0].evidence
        assert "ips" in evidence
        assert "device_ids" in evidence
        assert "countries" in evidence
    
    def test_severity_high_for_new_country(self, new_device_events):
        """Test high severity when new device + new country."""
        events = [_make_event(e) for e in new_device_events]
        alerts = detect_new_device(events)
        
        # Should be high because new device from Russia (new country)
        assert alerts[0].severity == "high"
