"""Case correlation and incident bundling.

This module groups related alerts into unified security cases (incidents)
based on user, time proximity, and shared indicators.
"""

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta

from log_detective.schema import Alert, AuthEvent, Case
from log_detective.scoring import calculate_case_score

logger = logging.getLogger(__name__)


def correlate_cases(
    alerts: list[Alert],
    event_index: dict[str, AuthEvent],
    window_hours: float = 8,
) -> list[Case]:
    """Correlate alerts into security cases.
    
    Groups alerts by:
    1. Same user within time window
    2. Shared IPs or device IDs (from evidence)
    
    Args:
        alerts: List of Alert objects to correlate.
        event_index: Dict mapping event_id to AuthEvent.
        window_hours: Time window for correlation (hours).
        
    Returns:
        List of Case objects.
    """
    if not alerts:
        return []
    
    cases: list[Case] = []
    
    # Group alerts by user
    user_alerts: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        user_alerts[alert.user].append(alert)
    
    # Process each user's alerts
    for user, user_alert_list in user_alerts.items():
        # Sort by start timestamp
        user_alert_list.sort(key=lambda a: a.ts_start)
        
        # Merge alerts into cases
        user_cases = _merge_alerts_into_cases(
            user, user_alert_list, window_hours
        )
        
        # Build each case
        for case_alerts in user_cases:
            case = _build_case(user, case_alerts, event_index)
            cases.append(case)
            logger.info(
                f"Created case {case.case_id} for {user} with "
                f"{len(case_alerts)} alerts, severity: {case.overall_severity}"
            )
    
    # Sort cases by severity (critical first) then by timestamp
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    cases.sort(key=lambda c: (severity_order.get(c.overall_severity, 4), c.ts_start))
    
    return cases


def _merge_alerts_into_cases(
    user: str,
    alerts: list[Alert],
    window_hours: float,
) -> list[list[Alert]]:
    """Merge alerts into case groups based on time and indicators.
    
    Args:
        user: User identifier.
        alerts: Sorted list of alerts for this user.
        window_hours: Time window for grouping.
        
    Returns:
        List of alert groups (each group becomes a case).
    """
    if not alerts:
        return []
    
    window = timedelta(hours=window_hours)
    groups: list[list[Alert]] = []
    current_group: list[Alert] = [alerts[0]]
    
    for alert in alerts[1:]:
        # Check if this alert should merge with current group
        should_merge = False
        
        # Check time overlap with any alert in current group
        for existing in current_group:
            # Time proximity check
            if alert.ts_start <= existing.ts_end + window:
                should_merge = True
                break
            
            # Check for shared indicators
            if _share_indicators(alert, existing):
                should_merge = True
                break
        
        if should_merge:
            current_group.append(alert)
        else:
            # Start new group
            groups.append(current_group)
            current_group = [alert]
    
    # Don't forget the last group
    groups.append(current_group)
    
    return groups


def _share_indicators(alert1: Alert, alert2: Alert) -> bool:
    """Check if two alerts share IPs or device IDs.
    
    Args:
        alert1: First alert.
        alert2: Second alert.
        
    Returns:
        True if alerts share indicators.
    """
    # Get standardized evidence keys
    ips1 = set(alert1.evidence.get("ips", []))
    ips2 = set(alert2.evidence.get("ips", []))
    
    device_ids1 = set(alert1.evidence.get("device_ids", []))
    device_ids2 = set(alert2.evidence.get("device_ids", []))
    
    # Check for intersection
    if ips1 & ips2:
        return True
    if device_ids1 & device_ids2:
        return True
    
    return False


def _build_case(
    user: str,
    alerts: list[Alert],
    event_index: dict[str, AuthEvent],
) -> Case:
    """Build a Case object from a group of alerts.
    
    Args:
        user: User identifier.
        alerts: List of alerts for this case.
        event_index: Dict mapping event_id to AuthEvent.
        
    Returns:
        Constructed Case object.
    """
    # Calculate time range
    ts_start = min(a.ts_start for a in alerts)
    ts_end = max(a.ts_end for a in alerts)
    
    # Calculate overall score and severity
    overall_score, overall_severity = calculate_case_score(alerts)
    
    # Build timeline from related event IDs
    timeline = _build_timeline(alerts, event_index)
    
    # Generate summary
    summary = _generate_summary(user, alerts, overall_severity, timeline)
    
    # Generate recommended actions
    recommended_actions = _generate_recommendations(alerts)
    
    return Case(
        case_id=f"CASE-{uuid.uuid4().hex[:8].upper()}",
        user=user,
        ts_start=ts_start,
        ts_end=ts_end,
        alerts=alerts,
        overall_severity=overall_severity,
        overall_score=overall_score,
        summary=summary,
        recommended_actions=recommended_actions,
        timeline=timeline,
    )


def _build_timeline(
    alerts: list[Alert],
    event_index: dict[str, AuthEvent],
) -> list[AuthEvent]:
    """Build an ordered timeline of events from alerts.
    
    Args:
        alerts: List of alerts.
        event_index: Dict mapping event_id to AuthEvent.
        
    Returns:
        Ordered list of AuthEvent objects.
    """
    # Collect all unique event IDs
    event_ids: set[str] = set()
    for alert in alerts:
        event_ids.update(alert.related_event_ids)
    
    # Look up events
    events: list[AuthEvent] = []
    for event_id in event_ids:
        if event_id in event_index:
            events.append(event_index[event_id])
        else:
            logger.warning(f"Event {event_id} not found in index")
    
    # Sort by timestamp
    events.sort(key=lambda e: e.ts)
    
    return events


def _generate_summary(
    user: str,
    alerts: list[Alert],
    severity: str,
    timeline: list[AuthEvent],
) -> str:
    """Generate a human-readable case summary.
    
    Args:
        user: User identifier.
        alerts: List of alerts.
        severity: Overall case severity.
        timeline: Timeline of events.
        
    Returns:
        Summary paragraph.
    """
    detector_names = {
        "impossible_travel": "impossible travel patterns",
        "fail_success_chain": "brute force/credential stuffing attempts",
        "new_device_ua": "new device anomalies",
    }
    
    detectors = {a.detector for a in alerts}
    detector_descriptions = [
        detector_names.get(d, d) for d in sorted(detectors)
    ]
    
    if len(detector_descriptions) > 1:
        detection_text = ", ".join(detector_descriptions[:-1]) + f" and {detector_descriptions[-1]}"
    else:
        detection_text = detector_descriptions[0] if detector_descriptions else "suspicious activity"
    
    # Count key metrics
    success_count = sum(1 for e in timeline if e.result == "success")
    failure_count = sum(1 for e in timeline if e.result == "failure")
    unique_ips = len({e.source_ip for e in timeline})
    unique_countries = len({e.country for e in timeline if e.country})
    
    summary = (
        f"A {severity.upper()}-severity security incident was detected for user {user} "
        f"involving {detection_text}. "
        f"The incident spans {len(alerts)} alert(s) and {len(timeline)} authentication event(s). "
    )
    
    if failure_count > 0:
        summary += f"There were {failure_count} failed and {success_count} successful login attempts. "
    
    if unique_ips > 1:
        summary += f"Activity originated from {unique_ips} distinct IP addresses"
        if unique_countries > 1:
            summary += f" across {unique_countries} countries"
        summary += ". "
    
    summary += "Immediate investigation is recommended."
    
    return summary


def _generate_recommendations(alerts: list[Alert]) -> list[str]:
    """Generate recommended response actions based on alert types.
    
    Args:
        alerts: List of alerts.
        
    Returns:
        List of recommended action strings.
    """
    recommendations: list[str] = []
    detectors = {a.detector for a in alerts}
    
    # Common recommendations
    recommendations.append("Contact user to verify recent login activity")
    
    if "impossible_travel" in detectors:
        recommendations.append("Verify user's actual location and travel history")
        recommendations.append("Check for VPN or proxy usage")
    
    if "fail_success_chain" in detectors:
        recommendations.append("Reset user credentials immediately")
        recommendations.append("Enable or verify MFA enrollment")
        recommendations.append("Review and block suspicious source IPs")
    
    if "new_device_ua" in detectors:
        recommendations.append("Confirm new device is authorized by user")
        recommendations.append("Review device enrollment policies")
    
    # Always recommend these
    recommendations.append("Review conditional access policies")
    recommendations.append("Check for data exfiltration or account changes")
    recommendations.append("Document incident for compliance records")
    
    return recommendations
