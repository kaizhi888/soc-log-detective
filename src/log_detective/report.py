"""Report generation for alerts and cases.

This module generates machine-readable (JSON) and human-readable (Markdown)
reports from detection results.
"""

import json
import logging
from datetime import datetime
from pathlib import Path

from log_detective.schema import Alert, AuthEvent, Case

logger = logging.getLogger(__name__)


def _fmt_num(value, fmt: str = ",.0f", default: str = "N/A") -> str:
    """Format a number safely, returning default if not a number."""
    if isinstance(value, (int, float)):
        return f"{value:{fmt}}"
    return str(default)


def generate_alerts_json(alerts: list[Alert], path: Path) -> None:
    """Write alerts to a JSON file.
    
    Args:
        alerts: List of Alert objects.
        path: Output file path.
    """
    data = [_alert_to_dict(a) for a in alerts]
    
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, default=str),
        encoding="utf-8"
    )
    
    logger.info(f"Wrote {len(alerts)} alerts to {path}")


def generate_cases_json(cases: list[Case], path: Path) -> None:
    """Write cases to a JSON file.
    
    Args:
        cases: List of Case objects.
        path: Output file path.
    """
    data = [_case_to_dict(c) for c in cases]
    
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, default=str),
        encoding="utf-8"
    )
    
    logger.info(f"Wrote {len(cases)} cases to {path}")


def generate_cases_md(cases: list[Case], path: Path) -> None:
    """Generate a Markdown report for cases.
    
    Args:
        cases: List of Case objects.
        path: Output file path.
    """
    lines: list[str] = []
    
    # Header
    lines.append("# Security Incident Report")
    lines.append("")
    lines.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    lines.append(f"**Total Cases:** {len(cases)}")
    
    # Summary stats
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for case in cases:
        severity_counts[case.overall_severity] += 1
    
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["critical", "high", "medium", "low"]:
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[sev]
        lines.append(f"| {emoji} {sev.upper()} | {severity_counts[sev]} |")
    
    lines.append("")
    lines.append("---")
    
    # Individual cases
    for case in cases:
        lines.extend(_format_case_section(case))
        lines.append("")
        lines.append("---")
    
    # Write file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    
    logger.info(f"Wrote case report to {path}")


def _format_case_section(case: Case) -> list[str]:
    """Format a single case as Markdown section.
    
    Args:
        case: Case object.
        
    Returns:
        List of Markdown lines.
    """
    lines: list[str] = []
    
    # Header with severity indicator
    severity_emoji = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
    }[case.overall_severity]
    
    lines.append("")
    lines.append(f"## {severity_emoji} Case {case.case_id} — {case.user} — {case.overall_severity.upper()}")
    lines.append("")
    lines.append(f"**Score:** {case.overall_score}/100")
    lines.append(f"**Time Range:** {_format_ts(case.ts_start)} → {_format_ts(case.ts_end)}")
    lines.append("")
    
    # Summary
    lines.append("### Summary")
    lines.append("")
    lines.append(case.summary)
    lines.append("")
    
    # Alerts table
    lines.append("### Alerts")
    lines.append("")
    lines.append("| Detector | Severity | Score | Time Range |")
    lines.append("|----------|----------|-------|------------|")
    
    for alert in case.alerts:
        time_range = f"{_format_ts(alert.ts_start)} → {_format_ts(alert.ts_end)}"
        lines.append(
            f"| {alert.detector} | {alert.severity} | {alert.score} | {time_range} |"
        )
    
    lines.append("")
    
    # Timeline
    if case.timeline:
        lines.append("### Timeline")
        lines.append("")
        
        for event in case.timeline:
            result_emoji = "✅" if event.result == "success" else "❌"
            location = _format_location(event)
            device = event.device_id or "unknown"
            
            lines.append(
                f"- **{_format_ts(event.ts)}** | {result_emoji} {event.result.upper()} | "
                f"`{event.source_ip}` | {location} | Device: `{device[:12]}...`"
            )
        
        lines.append("")
    
    # Evidence highlights
    lines.append("### Evidence Highlights")
    lines.append("")
    
    for alert in case.alerts:
        lines.append(f"**{alert.detector}:**")
        evidence = alert.evidence
        
        if alert.detector == "impossible_travel":
            lines.append(f"- Distance: {_fmt_num(evidence.get('distance_km'), ',.0f')} km")
            lines.append(f"- Time between: {_fmt_num(evidence.get('hours_between'), '.1f')} hours")
            lines.append(f"- Required speed: {_fmt_num(evidence.get('speed_kmh'), ',.0f')} km/h (impossible)")
            lines.append(f"- Locations: {evidence.get('location_1', 'N/A')} -> {evidence.get('location_2', 'N/A')}")
        
        elif alert.detector == "fail_success_chain":
            lines.append(f"- Failure count: {evidence.get('failure_count', 'N/A')}")
            lines.append(f"- Distinct IPs: {evidence.get('distinct_ips', 'N/A')}")
            lines.append(f"- Attack type: {evidence.get('attack_type', 'N/A')}")
            lines.append(f"- Time span: {_fmt_num(evidence.get('time_span_minutes'), '.1f')} minutes")
        
        elif alert.detector == "new_device_ua":
            lines.append(f"- New device: {evidence.get('new_device_id', 'N/A')}")
            lines.append(f"- New UA family: {evidence.get('new_ua_family', 'N/A')}")
            lines.append(f"- New country: {evidence.get('is_new_country', False)}")
            lines.append(f"- Known devices: {evidence.get('known_devices_count', 'N/A')}")
        
        lines.append("")
    
    # Recommended actions
    lines.append("### Recommended Actions")
    lines.append("")
    
    for action in case.recommended_actions:
        lines.append(f"- [ ] {action}")
    
    return lines


def _format_ts(ts: datetime) -> str:
    """Format timestamp for display.
    
    Args:
        ts: Datetime object.
        
    Returns:
        Formatted string.
    """
    return ts.strftime("%Y-%m-%d %H:%M:%S UTC")


def _format_location(event: AuthEvent) -> str:
    """Format location from event.
    
    Args:
        event: AuthEvent object.
        
    Returns:
        Location string.
    """
    parts = []
    if event.city:
        parts.append(event.city)
    if event.country:
        parts.append(event.country)
    
    if parts:
        return ", ".join(parts)
    return "Unknown"


def _alert_to_dict(alert: Alert) -> dict:
    """Convert Alert to dictionary for JSON serialization.
    
    Args:
        alert: Alert object.
        
    Returns:
        Dictionary representation.
    """
    return {
        "alert_id": alert.alert_id,
        "detector": alert.detector,
        "ts_start": alert.ts_start.isoformat(),
        "ts_end": alert.ts_end.isoformat(),
        "user": alert.user,
        "severity": alert.severity,
        "score": alert.score,
        "title": alert.title,
        "description": alert.description,
        "evidence": alert.evidence,
        "mitre": alert.mitre,
        "related_event_ids": alert.related_event_ids,
    }


def _case_to_dict(case: Case) -> dict:
    """Convert Case to dictionary for JSON serialization.
    
    Args:
        case: Case object.
        
    Returns:
        Dictionary representation.
    """
    return {
        "case_id": case.case_id,
        "user": case.user,
        "ts_start": case.ts_start.isoformat(),
        "ts_end": case.ts_end.isoformat(),
        "overall_severity": case.overall_severity,
        "overall_score": case.overall_score,
        "summary": case.summary,
        "recommended_actions": case.recommended_actions,
        "alerts": [_alert_to_dict(a) for a in case.alerts],
        "timeline": [
            {
                "event_id": e.event_id,
                "ts": e.ts.isoformat(),
                "user": e.user,
                "action": e.action,
                "result": e.result,
                "source_ip": e.source_ip,
                "country": e.country,
                "city": e.city,
                "device_id": e.device_id,
            }
            for e in case.timeline
        ],
    }
