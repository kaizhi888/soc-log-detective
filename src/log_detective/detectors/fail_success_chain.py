"""Failure → Success Chain Detector.

Detects brute force and credential stuffing attacks by identifying
patterns where multiple failed login attempts are followed by a
successful authentication.
"""

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta

from log_detective.schema import Alert, AuthEvent

logger = logging.getLogger(__name__)


def detect_fail_success_chain(
    events: list[AuthEvent],
    window_minutes: int = 20,
    min_failures_same_ip: int = 8,
    min_failures_multi_ip: int = 15,
) -> list[Alert]:
    """Detect failure→success authentication chains.
    
    Identifies patterns where multiple failed logins are followed by
    a successful authentication, indicating potential brute force or
    credential stuffing attacks.
    
    Args:
        events: List of AuthEvent objects.
        window_minutes: Time window to look back for failures (minutes).
        min_failures_same_ip: Minimum failures from same IP to trigger.
        min_failures_multi_ip: Minimum failures across IPs to trigger.
        
    Returns:
        List of Alert objects for detected chains.
    """
    alerts: list[Alert] = []
    
    # Group events by user
    user_events: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        user_events[event.user].append(event)
    
    # Sort events by timestamp for each user
    for user, user_evts in user_events.items():
        user_evts.sort(key=lambda e: e.ts)
        
        # Find success events
        for i, event in enumerate(user_evts):
            if event.result != "success":
                continue
            
            # Look back for failures within window
            window_start = event.ts - timedelta(minutes=window_minutes)
            
            failures: list[AuthEvent] = []
            for j in range(i - 1, -1, -1):
                prev_event = user_evts[j]
                if prev_event.ts < window_start:
                    break
                if prev_event.result == "failure":
                    failures.append(prev_event)
            
            if not failures:
                continue
            
            # Analyze failures
            ip_counts: dict[str, int] = defaultdict(int)
            for f in failures:
                ip_counts[f.source_ip] += 1
            
            total_failures = len(failures)
            max_same_ip_failures = max(ip_counts.values()) if ip_counts else 0
            distinct_ips = len(ip_counts)
            
            # Check thresholds
            alert = None
            
            # Same-IP attack pattern
            if max_same_ip_failures >= min_failures_same_ip:
                alert = _create_alert(
                    user=user,
                    failures=failures,
                    success=event,
                    ip_counts=ip_counts,
                    attack_type="same_ip",
                    threshold_used=min_failures_same_ip,
                )
            # Multi-IP attack pattern (distributed)
            elif total_failures >= min_failures_multi_ip:
                alert = _create_alert(
                    user=user,
                    failures=failures,
                    success=event,
                    ip_counts=ip_counts,
                    attack_type="multi_ip",
                    threshold_used=min_failures_multi_ip,
                )
            
            if alert:
                alerts.append(alert)
                logger.info(
                    f"Fail→Success chain detected for {user}: "
                    f"{total_failures} failures from {distinct_ips} IPs"
                )
    
    return alerts


def _create_alert(
    user: str,
    failures: list[AuthEvent],
    success: AuthEvent,
    ip_counts: dict[str, int],
    attack_type: str,
    threshold_used: int,
) -> Alert:
    """Create an Alert object for failure→success chain detection.
    
    Args:
        user: User identifier.
        failures: List of failure events.
        success: The successful login event.
        ip_counts: Dict of IP → failure count.
        attack_type: "same_ip" or "multi_ip".
        threshold_used: The threshold that was exceeded.
        
    Returns:
        Alert object with evidence.
    """
    total_failures = len(failures)
    distinct_ips = len(ip_counts)
    max_same_ip = max(ip_counts.values()) if ip_counts else 0
    
    # Determine severity
    if attack_type == "same_ip" and max_same_ip >= 12:
        severity = "high"
    elif total_failures >= threshold_used:
        severity = "medium"
    else:
        severity = "low"
    
    # Base scores
    score_map = {"low": 25, "medium": 50, "high": 75, "critical": 95}
    score = score_map[severity]
    
    # Bonus for success after many failures
    if total_failures >= 10:
        score = min(100, score + 10)
    
    # Sort failures by timestamp
    failures_sorted = sorted(failures, key=lambda e: e.ts)
    first_failure = failures_sorted[0]
    last_failure = failures_sorted[-1]
    
    # Top IPs by failure count
    top_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:5]
    
    # Collect standardized evidence keys
    all_ips = list(ip_counts.keys()) + [success.source_ip]
    all_ips = list(set(all_ips))
    
    device_ids = list({f.device_id for f in failures} | {success.device_id}) 
    device_ids = [d for d in device_ids if d is not None]
    
    countries = list({f.country for f in failures} | {success.country})
    countries = [c for c in countries if c is not None]
    
    # All related event IDs
    related_ids = [f.event_id for f in failures] + [success.event_id]
    
    # Description
    if attack_type == "same_ip":
        desc = (
            f"Detected {max_same_ip} failed login attempts from the same IP "
            f"({list(ip_counts.keys())[0]}) followed by a successful login for user {user}. "
            f"This pattern is consistent with brute force or credential stuffing attacks."
        )
    else:
        desc = (
            f"Detected {total_failures} failed login attempts from {distinct_ips} different IPs "
            f"followed by a successful login for user {user}. "
            f"This distributed pattern suggests a credential stuffing attack."
        )
    
    return Alert(
        alert_id=f"FSC-{uuid.uuid4().hex[:8].upper()}",
        detector="fail_success_chain",
        ts_start=first_failure.ts,
        ts_end=success.ts,
        user=user,
        severity=severity,
        score=score,
        title="Brute Force / Credential Stuffing Detected",
        description=desc,
        evidence={
            # Standardized keys
            "ips": all_ips,
            "device_ids": device_ids,
            "countries": countries,
            # Detector-specific keys
            "failure_count": total_failures,
            "distinct_ips": distinct_ips,
            "max_same_ip_failures": max_same_ip,
            "top_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
            "attack_type": attack_type,
            "threshold_used": threshold_used,
            "first_failure_ts": first_failure.ts.isoformat(),
            "last_failure_ts": last_failure.ts.isoformat(),
            "success_ts": success.ts.isoformat(),
            "success_ip": success.source_ip,
            "time_span_minutes": round(
                (success.ts - first_failure.ts).total_seconds() / 60, 1
            ),
        },
        mitre=["T1110", "T1110.001", "T1110.004"],  # Brute Force techniques
        related_event_ids=related_ids,
    )
