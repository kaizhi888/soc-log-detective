"""Tests for log ingestion."""

import json
import pytest
from pathlib import Path

from log_detective.ingest import parse_jsonl, parse_jsonl_from_string, _generate_fingerprint
from log_detective.schema import AuthEvent


class TestParseJsonl:
    """Tests for JSONL parsing."""
    
    def test_parse_valid_jsonl(self, tmp_jsonl):
        """Test parsing a valid JSONL file."""
        events, event_index = parse_jsonl(tmp_jsonl)
        
        assert len(events) == 1
        assert len(event_index) == 1
        assert events[0].event_id == "test-001"
        assert events[0].user == "test@corp.com"
        assert events[0].result == "success"
    
    def test_parse_jsonl_creates_event_index(self, tmp_jsonl):
        """Test that event_index maps event_id to AuthEvent."""
        events, event_index = parse_jsonl(tmp_jsonl)
        
        assert "test-001" in event_index
        assert event_index["test-001"].user == "test@corp.com"
    
    def test_parse_jsonl_handles_multiple_events(self, tmp_path, sample_event_data):
        """Test parsing multiple events."""
        file_path = tmp_path / "multi.jsonl"
        
        with open(file_path, "w") as f:
            for i in range(5):
                data = sample_event_data.copy()
                data["event_id"] = f"evt-{i:03d}"
                f.write(json.dumps(data) + "\n")
        
        events, event_index = parse_jsonl(file_path)
        
        assert len(events) == 5
        assert len(event_index) == 5
    
    def test_parse_jsonl_file_not_found(self):
        """Test error when file doesn't exist."""
        with pytest.raises(FileNotFoundError):
            parse_jsonl(Path("/nonexistent/file.jsonl"))
    
    def test_parse_jsonl_skips_malformed_lines(self, tmp_path):
        """Test that malformed JSON lines are skipped."""
        file_path = tmp_path / "malformed.jsonl"
        
        with open(file_path, "w") as f:
            f.write('{"event_id":"valid","ts":"2025-01-01T00:00:00Z","user":"u","source_ip":"1.1.1.1","result":"success"}\n')
            f.write('not valid json\n')
            f.write('{"event_id":"valid2","ts":"2025-01-01T00:00:00Z","user":"u","source_ip":"1.1.1.1","result":"success"}\n')
        
        events, _ = parse_jsonl(file_path)
        assert len(events) == 2


class TestParseJsonlFromString:
    """Tests for string-based JSONL parsing."""
    
    def test_parse_from_string(self, sample_event_data):
        """Test parsing JSONL from string content."""
        content = json.dumps(sample_event_data)
        events, event_index = parse_jsonl_from_string(content)
        
        assert len(events) == 1
        assert events[0].event_id == "test-001"


class TestDeviceFingerprint:
    """Tests for device fingerprint generation."""
    
    def test_fingerprint_generation(self):
        """Test fingerprint is generated deterministically."""
        fp1 = _generate_fingerprint("Mozilla/5.0 Chrome", "192.168.1.100")
        fp2 = _generate_fingerprint("Mozilla/5.0 Chrome", "192.168.1.100")
        
        assert fp1 == fp2
        assert fp1.startswith("fp-")
        assert len(fp1) == 15  # "fp-" + 12 hex chars
    
    def test_fingerprint_uses_ip_prefix(self):
        """Test fingerprint uses /24 network."""
        fp1 = _generate_fingerprint("UA", "192.168.1.100")
        fp2 = _generate_fingerprint("UA", "192.168.1.200")
        
        # Same /24, should be same fingerprint
        assert fp1 == fp2
    
    def test_fingerprint_differs_for_different_networks(self):
        """Test fingerprint differs for different /24 networks."""
        fp1 = _generate_fingerprint("UA", "192.168.1.100")
        fp2 = _generate_fingerprint("UA", "192.168.2.100")
        
        assert fp1 != fp2
