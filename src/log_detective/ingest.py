"""JSONL log ingestion and parsing.

This module handles parsing of JSONL authentication logs into
normalized AuthEvent objects with device fingerprint derivation.
"""

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path

from log_detective.schema import AuthEvent

logger = logging.getLogger(__name__)


def parse_jsonl(path: Path | str) -> tuple[list[AuthEvent], dict[str, AuthEvent]]:
    """Parse a JSONL file into AuthEvent objects.
    
    Args:
        path: Path to the JSONL file.
        
    Returns:
        Tuple of (events_list, event_index).
        - events_list: List of AuthEvent objects in file order.
        - event_index: Dict mapping event_id to AuthEvent for quick lookup.
        
    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If a line contains invalid JSON or missing required fields.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")
    
    events: list[AuthEvent] = []
    event_index: dict[str, AuthEvent] = {}
    
    content = path.read_text(encoding="utf-8")
    lines = content.strip().split("\n")
    
    for line_num, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
            
        try:
            data = json.loads(line)
        except json.JSONDecodeError as e:
            logger.warning(f"Skipping malformed JSON on line {line_num}: {e}")
            continue
        
        # Store raw data
        data["raw"] = data.copy()
        
        # Parse timestamp if it's a string
        if isinstance(data.get("ts"), str):
            data["ts"] = _parse_timestamp(data["ts"])
        
        # Derive device_id if missing
        if not data.get("device_id"):
            data["device_id"] = _generate_fingerprint(
                data.get("user_agent", ""),
                data.get("source_ip", "")
            )
        
        try:
            event = AuthEvent(**data)
            events.append(event)
            event_index[event.event_id] = event
            logger.debug(f"Parsed event {event.event_id} for user {event.user}")
        except Exception as e:
            logger.warning(f"Skipping invalid event on line {line_num}: {e}")
            continue
    
    logger.info(f"Parsed {len(events)} events from {path}")
    return events, event_index


def _parse_timestamp(ts_str: str) -> datetime:
    """Parse timestamp string to datetime.
    
    Supports ISO 8601 formats with or without timezone.
    
    Args:
        ts_str: Timestamp string.
        
    Returns:
        Parsed datetime object.
    """
    # Try common formats
    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    
    # Fallback: try fromisoformat (Python 3.11+)
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"Cannot parse timestamp: {ts_str}")


def _generate_fingerprint(user_agent: str, source_ip: str) -> str:
    """Generate a stable device fingerprint from UA and IP prefix.
    
    Uses the first three octets of the IP (/24 network) and the
    user agent string to create a deterministic identifier.
    
    Args:
        user_agent: User agent string.
        source_ip: Source IP address.
        
    Returns:
        12-character hex fingerprint.
    """
    # Extract /24 network (first 3 octets)
    parts = source_ip.split(".")
    if len(parts) >= 3:
        ip_prefix = ".".join(parts[:3])
    else:
        ip_prefix = source_ip
    
    # Create deterministic hash
    fingerprint_input = f"{user_agent}:{ip_prefix}"
    hash_digest = hashlib.md5(fingerprint_input.encode()).hexdigest()
    
    return f"fp-{hash_digest[:12]}"


def parse_jsonl_from_string(content: str) -> tuple[list[AuthEvent], dict[str, AuthEvent]]:
    """Parse JSONL content from a string (for Streamlit file uploads).
    
    Args:
        content: JSONL content as a string.
        
    Returns:
        Tuple of (events_list, event_index).
    """
    events: list[AuthEvent] = []
    event_index: dict[str, AuthEvent] = {}
    
    lines = content.strip().split("\n")
    
    for line_num, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
            
        try:
            data = json.loads(line)
        except json.JSONDecodeError as e:
            logger.warning(f"Skipping malformed JSON on line {line_num}: {e}")
            continue
        
        data["raw"] = data.copy()
        
        if isinstance(data.get("ts"), str):
            data["ts"] = _parse_timestamp(data["ts"])
        
        if not data.get("device_id"):
            data["device_id"] = _generate_fingerprint(
                data.get("user_agent", ""),
                data.get("source_ip", "")
            )
        
        try:
            event = AuthEvent(**data)
            events.append(event)
            event_index[event.event_id] = event
        except Exception as e:
            logger.warning(f"Skipping invalid event on line {line_num}: {e}")
            continue
    
    logger.info(f"Parsed {len(events)} events from string content")
    return events, event_index
