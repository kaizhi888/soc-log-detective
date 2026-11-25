"""JSONL log ingestion and parsing.

This module handles parsing of JSONL authentication logs into
normalized AuthEvent objects with device fingerprint derivation.
"""

import hashlib
import json
import logging
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from log_detective.schema import AuthEvent

logger = logging.getLogger(__name__)


def parse_jsonl(path: Path | str) -> tuple[list[AuthEvent], dict[str, AuthEvent]]:
    """Parse a JSONL file into AuthEvent objects.

    Invalid records are skipped with a warning that includes the line number.
    
    Args:
        path: Path to the JSONL file.
        
    Returns:
        Tuple of (events_list, event_index).
        - events_list: List of AuthEvent objects in file order.
        - event_index: Dict mapping event_id to AuthEvent for quick lookup.
        
    Raises:
        FileNotFoundError: If the file doesn't exist.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")
    
    with path.open(encoding="utf-8") as lines:
        events, event_index = _parse_lines(lines)

    logger.info(f"Parsed {len(events)} events from {path}")
    return events, event_index


def parse_jsonl_from_string(content: str) -> tuple[list[AuthEvent], dict[str, AuthEvent]]:
    """Parse a JSONL upload, warning and skipping any invalid records."""
    events, event_index = _parse_lines(content.split("\n"))
    logger.info(f"Parsed {len(events)} events from string content")
    return events, event_index


def _parse_lines(lines: Iterable[str]) -> tuple[list[AuthEvent], dict[str, AuthEvent]]:
    events: list[AuthEvent] = []
    event_index: dict[str, AuthEvent] = {}

    for line_num, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError as error:
            logger.warning("Skipping malformed JSON on line %d: %s", line_num, error)
            continue

        if not isinstance(data, dict):
            logger.warning("Skipping invalid event on line %d: expected a JSON object", line_num)
            continue

        data["raw"] = data.copy()
        try:
            if isinstance(data.get("ts"), str):
                data["ts"] = _parse_timestamp(data["ts"])
            event = AuthEvent(**data)
        except ValueError as error:
            logger.warning("Skipping invalid event on line %d: %s", line_num, error)
            continue

        if not event.device_id:
            event.device_id = _generate_fingerprint(
                data.get("user_agent", ""), event.source_ip
            )

        events.append(event)
        event_index[event.event_id] = event
        logger.debug("Parsed event %s for user %s", event.event_id, event.user)

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


def _generate_fingerprint(user_agent: str | None, source_ip: str) -> str:
    """Generate a stable device fingerprint from UA and IP prefix.
    
    Uses the first three octets of the IP (/24 network) and the
    user agent string to create a deterministic identifier.
    
    Args:
        user_agent: User agent string, if provided.
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
