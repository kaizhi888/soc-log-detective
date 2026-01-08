"""Tests for report generation."""

import json
import pytest
from datetime import datetime
from pathlib import Path

from log_detective.schema import Alert, Case, AuthEvent
from log_detective.report import generate_alerts_json, generate_cases_json, generate_cases_md
from log_detective.correlate import correlate_cases


@pytest.fixture
def sample_alert():
    """Create a sample alert."""
    return Alert(
        alert_id="TEST-001",
        detector="impossible_travel",
        ts_start=datetime(2025, 1, 1, 8, 0, 0),
        ts_end=datetime(2025, 1, 1, 9, 30, 0),
        user="test@corp.com",
        severity="high",
        score=75,
        title="Test Alert",
        description="Test description",
        evidence={
            "ips": ["1.1.1.1", "2.2.2.2"],
            "device_ids": ["dev-001"],
            "countries": ["US", "JP"],
            "distance_km": 10000,
            "speed_kmh": 6666,
        },
        mitre=["T1078"],
        related_event_ids=["evt-001", "evt-002"],
    )


@pytest.fixture
def sample_case(sample_alert):
    """Create a sample case."""
    return Case(
        case_id="CASE-001",
        user="test@corp.com",
        ts_start=datetime(2025, 1, 1, 8, 0, 0),
        ts_end=datetime(2025, 1, 1, 9, 30, 0),
        alerts=[sample_alert],
        overall_severity="high",
        overall_score=75,
        summary="Test case summary",
        recommended_actions=["Action 1", "Action 2"],
        timeline=[],
    )


class TestGenerateAlertsJson:
    """Tests for alerts JSON generation."""
    
    def test_creates_valid_json(self, tmp_path, sample_alert):
        """Test that valid JSON is created."""
        output_path = tmp_path / "alerts.json"
        generate_alerts_json([sample_alert], output_path)
        
        assert output_path.exists()
        
        with open(output_path) as f:
            data = json.load(f)
        
        assert len(data) == 1
        assert data[0]["alert_id"] == "TEST-001"
    
    def test_creates_output_directory(self, tmp_path, sample_alert):
        """Test that output directory is created."""
        output_path = tmp_path / "subdir" / "alerts.json"
        generate_alerts_json([sample_alert], output_path)
        
        assert output_path.exists()


class TestGenerateCasesJson:
    """Tests for cases JSON generation."""
    
    def test_creates_valid_json(self, tmp_path, sample_case):
        """Test that valid JSON is created."""
        output_path = tmp_path / "cases.json"
        generate_cases_json([sample_case], output_path)
        
        assert output_path.exists()
        
        with open(output_path) as f:
            data = json.load(f)
        
        assert len(data) == 1
        assert data[0]["case_id"] == "CASE-001"


class TestGenerateCasesMd:
    """Tests for cases Markdown generation."""
    
    def test_creates_markdown_file(self, tmp_path, sample_case):
        """Test that Markdown file is created."""
        output_path = tmp_path / "cases.md"
        generate_cases_md([sample_case], output_path)
        
        assert output_path.exists()
    
    def test_contains_case_header(self, tmp_path, sample_case):
        """Test that Markdown contains case header."""
        output_path = tmp_path / "cases.md"
        generate_cases_md([sample_case], output_path)
        
        content = output_path.read_text()
        assert "CASE-001" in content
        assert "test@corp.com" in content
        assert "HIGH" in content
    
    def test_contains_summary_section(self, tmp_path, sample_case):
        """Test that Markdown contains summary."""
        output_path = tmp_path / "cases.md"
        generate_cases_md([sample_case], output_path)
        
        content = output_path.read_text()
        assert "Summary" in content
        assert "Test case summary" in content
    
    def test_contains_recommended_actions(self, tmp_path, sample_case):
        """Test that Markdown contains recommended actions."""
        output_path = tmp_path / "cases.md"
        generate_cases_md([sample_case], output_path)
        
        content = output_path.read_text()
        assert "Recommended Actions" in content
        assert "Action 1" in content
        assert "Action 2" in content


class TestCorrelation:
    """Tests for alert correlation."""
    
    def test_correlates_same_user_alerts(self, sample_alert):
        """Test that alerts for same user are correlated."""
        alert1 = sample_alert.model_copy()
        alert1.alert_id = "A1"
        
        alert2 = sample_alert.model_copy()
        alert2.alert_id = "A2"
        alert2.ts_start = datetime(2025, 1, 1, 9, 0, 0)
        alert2.ts_end = datetime(2025, 1, 1, 10, 0, 0)
        
        cases = correlate_cases([alert1, alert2], {}, window_hours=8)
        
        # Should merge into one case
        assert len(cases) == 1
        assert len(cases[0].alerts) == 2
    
    def test_separates_different_user_alerts(self, sample_alert):
        """Test that alerts for different users are separated."""
        alert1 = sample_alert.model_copy()
        alert1.alert_id = "A1"
        alert1.user = "user1@corp.com"
        
        alert2 = sample_alert.model_copy()
        alert2.alert_id = "A2"
        alert2.user = "user2@corp.com"
        
        cases = correlate_cases([alert1, alert2], {}, window_hours=8)
        
        # Should be separate cases
        assert len(cases) == 2
