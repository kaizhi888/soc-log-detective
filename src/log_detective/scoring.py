"""Severity scoring for alerts and cases.

This module provides scoring logic to convert alert severities
into numeric scores and calculate overall case severity.
"""

from log_detective.schema import Alert, Case


# Base scores for each severity level
BASE_SCORES: dict[str, int] = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 95,
}


def get_base_score(severity: str) -> int:
    """Get base score for a severity level.
    
    Args:
        severity: Severity string (low/medium/high/critical).
        
    Returns:
        Base score (0-100).
    """
    return BASE_SCORES.get(severity, 25)


def severity_from_score(score: int) -> str:
    """Determine severity level from numeric score.
    
    Args:
        score: Numeric score (0-100).
        
    Returns:
        Severity string.
    """
    if score >= 90:
        return "critical"
    elif score >= 70:
        return "high"
    elif score >= 40:
        return "medium"
    else:
        return "low"


def calculate_case_score(alerts: list[Alert]) -> tuple[int, str]:
    """Calculate overall case score and severity.
    
    Combines individual alert scores with bonuses for:
    - Success after many failures (+10)
    - New device AND new country (+10)
    - Multiple detector types in same case (+15)
    
    Args:
        alerts: List of alerts in the case.
        
    Returns:
        Tuple of (score, severity).
    """
    if not alerts:
        return 0, "low"
    
    # Start with max alert severity
    base_score = max(get_base_score(a.severity) for a in alerts)
    bonus = 0
    
    # Check for compound patterns
    detector_types = {a.detector for a in alerts}
    
    # +15 if multiple detector types
    if len(detector_types) > 1:
        bonus += 15
    
    # Check individual alerts for additional bonuses
    for alert in alerts:
        evidence = alert.evidence
        
        # +10 if success after many failures (fail_success_chain)
        if alert.detector == "fail_success_chain":
            failure_count = evidence.get("failure_count", 0)
            if failure_count >= 10:
                bonus += 10
                break  # Only apply once
        
        # +10 if new device AND new country
        if alert.detector == "new_device_ua":
            is_new_device = evidence.get("is_new_device", False)
            is_new_country = evidence.get("is_new_country", False)
            if is_new_device and is_new_country:
                bonus += 10
                break  # Only apply once
    
    # Calculate final score (capped at 100)
    final_score = min(100, base_score + bonus)
    
    # Determine severity from score
    severity = severity_from_score(final_score)
    
    return final_score, severity


def recalculate_alert_scores(alerts: list[Alert]) -> list[Alert]:
    """Recalculate scores for alerts based on context.
    
    Args:
        alerts: List of alerts.
        
    Returns:
        Alerts with updated scores.
    """
    # Currently just returns alerts as-is
    # Could be extended for contextual scoring
    return alerts
