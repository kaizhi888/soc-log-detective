"""Detector registry and utilities.

This module provides a unified interface to run all detection algorithms
and exports individual detector functions.
"""

from typing import Any

from log_detective.schema import Alert, AuthEvent
from log_detective.detectors.impossible_travel import detect_impossible_travel
from log_detective.detectors.fail_success_chain import detect_fail_success_chain
from log_detective.detectors.new_device_ua import detect_new_device

__all__ = [
    "detect_impossible_travel",
    "detect_fail_success_chain",
    "detect_new_device",
    "run_all_detectors",
]


def run_all_detectors(
    events: list[AuthEvent],
    speed_threshold_kmh: float = 900,
    max_travel_hours: float = 6,
    failure_window_minutes: int = 20,
    min_failures_same_ip: int = 8,
    min_failures_multi_ip: int = 15,
    device_lookback_days: int = 30,
    **kwargs: Any,
) -> list[Alert]:
    """Run all detectors on the event list.
    
    Args:
        events: List of AuthEvent objects to analyze.
        speed_threshold_kmh: Impossible travel speed threshold (km/h).
        max_travel_hours: Max hours for travel detection.
        failure_window_minutes: Failure chain detection window (minutes).
        min_failures_same_ip: Min failures from same IP.
        min_failures_multi_ip: Min failures across multiple IPs.
        device_lookback_days: Days to look back for device baseline.
        **kwargs: Additional arguments passed to detectors.
        
    Returns:
        Combined list of alerts from all detectors.
    """
    alerts: list[Alert] = []
    
    # Detector 1: Impossible Travel
    alerts.extend(
        detect_impossible_travel(
            events,
            speed_threshold_kmh=speed_threshold_kmh,
            max_hours=max_travel_hours,
        )
    )
    
    # Detector 2: Failure → Success Chain
    alerts.extend(
        detect_fail_success_chain(
            events,
            window_minutes=failure_window_minutes,
            min_failures_same_ip=min_failures_same_ip,
            min_failures_multi_ip=min_failures_multi_ip,
        )
    )
    
    # Detector 3: New Device Anomaly
    alerts.extend(
        detect_new_device(
            events,
            lookback_days=device_lookback_days,
        )
    )
    
    return alerts
