"""New Device / User-Agent Anomaly Detector.

Detects successful logins from devices or user agents that have not
been seen before for a given user, potentially indicating account
compromise or unauthorized access.
"""

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import NamedTuple

from log_detective.schema import Alert, AuthEvent

logger = logging.getLogger(__name__)

# Try to import user-agents library for UA parsing
try:
    from user_agents import parse as parse_ua
    HAS_USER_AGENTS = True
except ImportError:
    HAS_USER_AGENTS = False
    logger.warning("user-agents library not available, UA family detection disabled")


class DeviceBaseline(NamedTuple):
    """Baseline device information for a user."""
    device_ids: set[str]
    ua_families: set[str]
    countries: set[str]
    last_seen: datetime | None


def detect_new_device(
    events: list[AuthEvent],
    lookback_days: int = 30,
) -> list[Alert]:
    """Detect logins from new devices or user agents.
    
    Builds a baseline of known devices and UA families for each user
    from historical events, then flags successful logins from new
    devices not in the baseline.
    
    Args:
        events: List of AuthEvent objects.
        lookback_days: Days to use for baseline calculation.
        
    Returns:
        List of Alert objects for detected new device anomalies.
    """
    alerts: list[Alert] = []
    
    # Sort all events by timestamp
    sorted_events = sorted(events, key=lambda e: e.ts)
    
    if not sorted_events:
        return alerts
    
    # Group events by user
    user_events: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in sorted_events:
        user_events[event.user].append(event)
    
    # Process each user
    for user, user_evts in user_events.items():
        # Build baseline progressively
        baseline = DeviceBaseline(
            device_ids=set(),
            ua_families=set(),
            countries=set(),
            last_seen=None,
        )
        
        for event in user_evts:
            # Only check success events for anomalies
            if event.result == "success":
                # Check against current baseline (before updating)
                if baseline.device_ids:  # Only check if we have baseline data
                    alert = _check_for_anomaly(event, baseline, user)
                    if alert:
                        alerts.append(alert)
                        logger.info(
                            f"New device detected for {user}: {event.device_id}"
                        )
            
            # Update baseline with this event (success or failure)
            # This simulates "learning" the user's normal devices over time
            if event.device_id:
                baseline = DeviceBaseline(
                    device_ids=baseline.device_ids | {event.device_id},
                    ua_families=baseline.ua_families | {_get_ua_family(event.user_agent)},
                    countries=baseline.countries | ({event.country} if event.country else set()),
                    last_seen=event.ts,
                )
    
    return alerts


def _check_for_anomaly(
    event: AuthEvent,
    baseline: DeviceBaseline,
    user: str,
) -> Alert | None:
    """Check if an event represents a device anomaly.
    
    Args:
        event: The event to check.
        baseline: User's device baseline.
        user: User identifier.
        
    Returns:
        Alert if anomaly detected, None otherwise.
    """
    is_new_device = event.device_id and event.device_id not in baseline.device_ids
    is_new_ua_family = False
    new_ua_family = None
    
    if event.user_agent and baseline.ua_families:
        current_family = _get_ua_family(event.user_agent)
        if current_family and current_family not in baseline.ua_families:
            is_new_ua_family = True
            new_ua_family = current_family
    
    is_new_country = (
        event.country is not None 
        and baseline.countries 
        and event.country not in baseline.countries
    )
    
    # Only alert if we have a new device or dramatically different UA
    if not is_new_device and not is_new_ua_family:
        return None
    
    # Determine severity
    # High if new device AND new country
    if (is_new_device or is_new_ua_family) and is_new_country:
        severity = "high"
    else:
        severity = "medium"
    
    # Base scores
    score_map = {"low": 25, "medium": 50, "high": 75, "critical": 95}
    score = score_map[severity]
    
    # Bonus for new device + new country
    if is_new_device and is_new_country:
        score = min(100, score + 10)
    
    # Build description
    anomaly_parts = []
    if is_new_device:
        anomaly_parts.append(f"new device ID ({event.device_id})")
    if is_new_ua_family:
        anomaly_parts.append(f"new user agent family ({new_ua_family})")
    if is_new_country:
        anomaly_parts.append(f"new country ({event.country})")
    
    anomaly_desc = " and ".join(anomaly_parts)
    
    return Alert(
        alert_id=f"ND-{uuid.uuid4().hex[:8].upper()}",
        detector="new_device_ua",
        ts_start=event.ts,
        ts_end=event.ts,
        user=user,
        severity=severity,
        score=score,
        title="New Device / User-Agent Anomaly",
        description=(
            f"User {user} successfully authenticated from a {anomaly_desc}. "
            f"This device/configuration has not been seen in the user's history. "
            f"Known devices: {len(baseline.device_ids)}, Known UA families: {len(baseline.ua_families)}."
        ),
        evidence={
            # Standardized keys
            "ips": [event.source_ip],
            "device_ids": [event.device_id] if event.device_id else [],
            "countries": [event.country] if event.country else [],
            # Detector-specific keys
            "is_new_device": is_new_device,
            "is_new_ua_family": is_new_ua_family,
            "is_new_country": is_new_country,
            "new_device_id": event.device_id,
            "new_ua": event.user_agent,
            "new_ua_family": new_ua_family,
            "known_devices_count": len(baseline.device_ids),
            "known_ua_families": list(baseline.ua_families),
            "known_countries": list(baseline.countries),
            "event_ts": event.ts.isoformat(),
            "time_since_last_seen": (
                str(event.ts - baseline.last_seen) if baseline.last_seen else None
            ),
        },
        mitre=["T1078"],  # Valid Accounts
        related_event_ids=[event.event_id],
    )


def _get_ua_family(user_agent: str | None) -> str:
    """Extract UA family from user agent string.
    
    Args:
        user_agent: User agent string.
        
    Returns:
        UA family string (e.g., "Chrome on Windows").
    """
    if not user_agent:
        return "Unknown"
    
    if HAS_USER_AGENTS:
        try:
            ua = parse_ua(user_agent)
            browser = ua.browser.family or "Unknown"
            os = ua.os.family or "Unknown"
            return f"{browser} on {os}"
        except Exception:
            pass
    
    # Fallback: simple pattern matching
    ua_lower = user_agent.lower()
    
    if "chrome" in ua_lower and "safari" in ua_lower and "edg" not in ua_lower:
        browser = "Chrome"
    elif "firefox" in ua_lower:
        browser = "Firefox"
    elif "safari" in ua_lower and "chrome" not in ua_lower:
        browser = "Safari"
    elif "edg" in ua_lower:
        browser = "Edge"
    else:
        browser = "Other"
    
    if "windows" in ua_lower:
        os = "Windows"
    elif "mac" in ua_lower or "iphone" in ua_lower or "ipad" in ua_lower:
        os = "Apple"
    elif "android" in ua_lower:
        os = "Android"
    elif "linux" in ua_lower:
        os = "Linux"
    else:
        os = "Other"
    
    return f"{browser} on {os}"
