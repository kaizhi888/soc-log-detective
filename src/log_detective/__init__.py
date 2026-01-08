"""SOC-Style Log Detective: Suspicious Login Detector + Case Report Generator.

A Python-based cybersecurity tool that ingests authentication logs,
detects suspicious patterns using rule-based detectors, and generates
professional incident reports.
"""

__version__ = "0.1.0"
__author__ = "SOC Analyst"

from log_detective.schema import AuthEvent, Alert, Case

__all__ = ["AuthEvent", "Alert", "Case", "__version__"]
