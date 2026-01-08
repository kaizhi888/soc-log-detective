"""End-to-end tests for Log Detective."""

import json
import pytest
from pathlib import Path

from log_detective.ingest import parse_jsonl
from log_detective.detectors import run_all_detectors
from log_detective.correlate import correlate_cases
from log_detective.report import generate_alerts_json, generate_cases_json, generate_cases_md


class TestEndToEnd:
    """End-to-end integration tests."""
    
    @pytest.fixture
    def sample_file(self):
        """Get path to sample JSONL file."""
        paths = [
            Path("samples/sample_auth_logs.jsonl"),
            Path(__file__).parent.parent / "samples" / "sample_auth_logs.jsonl",
        ]
        for path in paths:
            if path.exists():
                return path
        pytest.skip("Sample file not found")
    
    def test_full_pipeline(self, sample_file, tmp_path):
        """Test full analysis pipeline."""
        # Ingest
        events, event_index = parse_jsonl(sample_file)
        assert len(events) > 0
        
        # Detect
        alerts = run_all_detectors(events)
        assert len(alerts) >= 3  # At least one per detector type
        
        # Correlate
        cases = correlate_cases(alerts, event_index)
        assert len(cases) >= 1
        
        # Generate reports
        alerts_path = tmp_path / "alerts.json"
        cases_json_path = tmp_path / "cases.json"
        cases_md_path = tmp_path / "cases.md"
        
        generate_alerts_json(alerts, alerts_path)
        generate_cases_json(cases, cases_json_path)
        generate_cases_md(cases, cases_md_path)
        
        # Verify outputs exist and are valid
        assert alerts_path.exists()
        assert cases_json_path.exists()
        assert cases_md_path.exists()
        
        # Verify JSON is parseable
        with open(alerts_path) as f:
            alerts_data = json.load(f)
        assert len(alerts_data) >= 3
        
        with open(cases_json_path) as f:
            cases_data = json.load(f)
        assert len(cases_data) >= 1
        
        # Verify Markdown contains expected content
        md_content = cases_md_path.read_text(encoding='utf-8')
        assert "Case" in md_content
        assert "Summary" in md_content
    
    def test_detects_all_scenarios(self, sample_file):
        """Test that all attack scenarios are detected."""
        events, event_index = parse_jsonl(sample_file)
        alerts = run_all_detectors(events)
        
        detectors_found = {a.detector for a in alerts}
        
        # Should detect all three scenarios
        assert "impossible_travel" in detectors_found
        assert "fail_success_chain" in detectors_found
        assert "new_device_ua" in detectors_found
