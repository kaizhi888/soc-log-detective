"""Impossible Travel Detector.

Detects when a user successfully authenticates from two geographically
distant locations within a timeframe that would require impossible
travel speeds.
"""

import logging
import uuid
from collections import defaultdict
from datetime import datetime

from haversine import haversine, Unit

from log_detective.schema import Alert, AuthEvent

logger = logging.getLogger(__name__)


def detect_impossible_travel(
    events: list[AuthEvent],
    speed_threshold_kmh: float = 900,
    max_hours: float = 6,
) -> list[Alert]:
    """Detect impossible travel patterns.
    
    Compares consecutive successful logins for each user and flags
    when the required travel speed exceeds the threshold.
    
    Args:
        events: List of AuthEvent objects.
        speed_threshold_kmh: Speed threshold in km/h. Default 900 (max aircraft speed).
        max_hours: Maximum hours between logins to consider. Default 6.
        
    Returns:
        List of Alert objects for detected impossible travel.
    """
    alerts: list[Alert] = []
    
    # Filter success events with location data
    success_events = [
        e for e in events
        if e.result == "success" and e.lat is not None and e.lon is not None
    ]
    
    # Group by user
    user_events: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in success_events:
        user_events[event.user].append(event)
    
    # Sort each user's events by timestamp
    for user, user_evts in user_events.items():
        user_evts.sort(key=lambda e: e.ts)
        
        # Compare consecutive pairs
        for i in range(len(user_evts) - 1):
            event1 = user_evts[i]
            event2 = user_evts[i + 1]
            
            # Calculate time difference in hours
            time_delta = (event2.ts - event1.ts).total_seconds() / 3600
            
            # Skip if time is too long
            if time_delta > max_hours or time_delta <= 0:
                continue
            
            # Calculate distance using haversine
            loc1 = (event1.lat, event1.lon)
            loc2 = (event2.lat, event2.lon)
            distance_km = haversine(loc1, loc2, unit=Unit.KILOMETERS)
            
            # Calculate required speed
            speed_kmh = distance_km / time_delta if time_delta > 0 else float("inf")
            
            # Check if speed exceeds threshold
            if speed_kmh > speed_threshold_kmh:
                alert = _create_alert(
                    event1, event2, distance_km, time_delta, speed_kmh
                )
                alerts.append(alert)
                logger.info(
                    f"Impossible travel detected for {user}: "
                    f"{distance_km:.0f}km in {time_delta:.1f}h = {speed_kmh:.0f}km/h"
                )
    
    return alerts


def _create_alert(
    event1: AuthEvent,
    event2: AuthEvent,
    distance_km: float,
    hours_between: float,
    speed_kmh: float,
) -> Alert:
    """Create an Alert object for impossible travel detection.
    
    Args:
        event1: First login event.
        event2: Second login event.
        distance_km: Distance between locations in km.
        hours_between: Time between events in hours.
        speed_kmh: Calculated travel speed in km/h.
        
    Returns:
        Alert object with evidence.
    """
    # Determine severity
    if speed_kmh > 2000 and hours_between < 2:
        severity = "critical"
    elif speed_kmh > 900 and hours_between < 6:
        severity = "high"
    else:
        severity = "medium"
    
    # Base scores
    score_map = {"low": 25, "medium": 50, "high": 75, "critical": 95}
    score = score_map[severity]
    
    # Build location strings
    loc1_str = _format_location(event1)
    loc2_str = _format_location(event2)
    
    # Collect IPs, device_ids, countries (standardized evidence keys)
    ips = list({event1.source_ip, event2.source_ip})
    device_ids = list({event1.device_id, event2.device_id} - {None})
    countries = list({event1.country, event2.country} - {None})
    
    return Alert(
        alert_id=f"IT-{uuid.uuid4().hex[:8].upper()}",
        detector="impossible_travel",
        ts_start=min(event1.ts, event2.ts),
        ts_end=max(event1.ts, event2.ts),
        user=event1.user,
        severity=severity,
        score=score,
        title="Impossible Travel Detected",
        description=(
            f"User {event1.user} logged in from {loc1_str} and {loc2_str} "
            f"within {hours_between:.1f} hours. Required speed: {speed_kmh:.0f} km/h "
            f"(distance: {distance_km:.0f} km). This exceeds the maximum possible "
            f"travel speed of {900} km/h."
        ),
        evidence={
            # Standardized keys
            "ips": ips,
            "device_ids": device_ids,
            "countries": countries,
            # Detector-specific keys
            "location_1": loc1_str,
            "location_2": loc2_str,
            "lat_1": event1.lat,
            "lon_1": event1.lon,
            "lat_2": event2.lat,
            "lon_2": event2.lon,
            "distance_km": round(distance_km, 2),
            "hours_between": round(hours_between, 2),
            "speed_kmh": round(speed_kmh, 2),
            "event_1_ts": event1.ts.isoformat(),
            "event_2_ts": event2.ts.isoformat(),
        },
        mitre=["T1078", "T1078.004"],  # Valid Accounts, Cloud Accounts
        related_event_ids=[event1.event_id, event2.event_id],
    )


def _format_location(event: AuthEvent) -> str:
    """Format location string from event.
    
    Args:
        event: AuthEvent with location data.
        
    Returns:
        Formatted location string.
    """
    parts = []
    if event.city:
        parts.append(event.city)
    if event.country:
        parts.append(event.country)
    
    if parts:
        return ", ".join(parts)
    return f"({event.lat}, {event.lon})"
