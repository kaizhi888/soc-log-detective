"""Streamlit UI for Log Detective.

This module provides an interactive web interface for analyzing
authentication logs and viewing security cases.
"""

import sys
from pathlib import Path

# Add src directory to path for Streamlit Cloud deployment
# ui_streamlit.py is at: src/log_detective/ui_streamlit.py
# parent = src/log_detective, parent.parent = src
src_path = Path(__file__).resolve().parent.parent
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

import json

import pandas as pd
import streamlit as st

from log_detective import __version__
from log_detective.ingest import parse_jsonl_from_string
from log_detective.detectors import run_all_detectors
from log_detective.correlate import correlate_cases
from log_detective.schema import Alert, Case


# Page config
st.set_page_config(
    page_title="Log Detective",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)


def main():
    """Main Streamlit application."""
    
    # Header
    st.title("🔍 SOC-Style Log Detective")
    st.caption(f"Suspicious Login Detector + Case Report Generator | v{__version__}")
    
    # Sidebar
    with st.sidebar:
        st.header("Configuration")
        
        # File upload
        uploaded_file = st.file_uploader(
            "Upload JSONL Log File",
            type=["jsonl", "json", "txt"],
            help="Upload a JSONL file with authentication events",
        )
        
        # Or use sample data
        use_sample = st.checkbox("Use sample data", value=False)
        
        st.divider()
        
        # Thresholds
        st.subheader("Detection Thresholds")
        
        speed_threshold = st.slider(
            "Impossible Travel Speed (km/h)",
            min_value=500,
            max_value=2000,
            value=900,
            step=100,
            help="Speed threshold for impossible travel detection",
        )
        
        max_travel_hours = st.slider(
            "Max Travel Hours",
            min_value=1,
            max_value=24,
            value=6,
            help="Maximum hours between logins for travel detection",
        )
        
        failure_window = st.slider(
            "Failure Window (minutes)",
            min_value=5,
            max_value=60,
            value=20,
            help="Time window for brute force detection",
        )
        
        min_failures = st.slider(
            "Min Failures",
            min_value=3,
            max_value=20,
            value=8,
            help="Minimum failures before success to trigger alert",
        )
        
        case_window = st.slider(
            "Case Window (hours)",
            min_value=1,
            max_value=24,
            value=8,
            help="Time window for correlating alerts into cases",
        )
        
        st.divider()
        
        # Run analysis button
        run_analysis = st.button(
            "🚀 Run Analysis",
            type="primary",
            use_container_width=True,
        )
    
    # Main content
    if not uploaded_file and not use_sample:
        st.info("👈 Upload a JSONL file or enable sample data, then click 'Run Analysis'")
        
        # Show expected format
        st.subheader("Expected Log Format")
        st.code('''
{
  "event_id": "evt-001",
  "ts": "2025-01-01T08:00:00Z",
  "user": "alice@corp.com",
  "source_ip": "203.0.113.50",
  "result": "success",
  "country": "US",
  "city": "New York",
  "lat": 40.7128,
  "lon": -74.0060,
  "user_agent": "Mozilla/5.0 ...",
  "device_id": "dev-abc123"
}
        ''', language="json")
        return
    
    # Load data
    content = None
    
    if use_sample:
        sample_paths = [
            Path("samples/sample_auth_logs.jsonl"),
            Path(__file__).parent.parent.parent / "samples" / "sample_auth_logs.jsonl",
        ]
        for path in sample_paths:
            if path.exists():
                content = path.read_text(encoding="utf-8")
                break
        
        if not content:
            st.error("Sample file not found. Please upload a file instead.")
            return
    elif uploaded_file:
        content = uploaded_file.read().decode("utf-8")
    
    if not content:
        st.warning("No data to analyze.")
        return
    
    # Parse events
    try:
        events, event_index = parse_jsonl_from_string(content)
    except Exception as e:
        st.error(f"Error parsing log file: {e}")
        return
    
    if not events:
        st.warning("No valid events found in the file.")
        return
    
    # Store in session state
    if "events" not in st.session_state or run_analysis:
        st.session_state["events"] = events
        st.session_state["event_index"] = event_index
        st.session_state["alerts"] = None
        st.session_state["cases"] = None
    
    # Run analysis if button clicked
    if run_analysis:
        with st.spinner("Running detection algorithms..."):
            alerts = run_all_detectors(
                events,
                speed_threshold_kmh=speed_threshold,
                max_travel_hours=max_travel_hours,
                failure_window_minutes=failure_window,
                min_failures_same_ip=min_failures,
            )
            st.session_state["alerts"] = alerts
        
        with st.spinner("Correlating alerts into cases..."):
            cases = correlate_cases(
                alerts,
                event_index,
                window_hours=case_window,
            )
            st.session_state["cases"] = cases
    
    alerts = st.session_state.get("alerts", [])
    cases = st.session_state.get("cases", [])
    
    # KPI Cards
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Events", len(events))
    
    with col2:
        st.metric("Total Alerts", len(alerts) if alerts else 0)
    
    with col3:
        st.metric("Total Cases", len(cases) if cases else 0)
    
    with col4:
        if cases:
            max_severity = max(
                cases,
                key=lambda c: {"critical": 4, "high": 3, "medium": 2, "low": 1}[c.overall_severity]
            ).overall_severity.upper()
            severity_color = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🟢",
            }
            st.metric("Max Severity", f"{severity_color.get(max_severity, '')} {max_severity}")
        else:
            st.metric("Max Severity", "N/A")
    
    if not alerts and not run_analysis:
        st.info("Click 'Run Analysis' to detect suspicious patterns.")
        return
    
    if not alerts:
        st.success("✅ No suspicious patterns detected!")
        return
    
    # Tabs for different views
    tab1, tab2, tab3 = st.tabs(["📊 Alerts", "📁 Cases", "📜 Raw Events"])
    
    with tab1:
        st.subheader("Detected Alerts")
        
        # Filters
        col1, col2, col3 = st.columns(3)
        
        with col1:
            detector_filter = st.multiselect(
                "Filter by Detector",
                options=list({a.detector for a in alerts}),
                default=list({a.detector for a in alerts}),
            )
        
        with col2:
            severity_filter = st.multiselect(
                "Filter by Severity",
                options=["critical", "high", "medium", "low"],
                default=["critical", "high", "medium", "low"],
            )
        
        with col3:
            user_filter = st.multiselect(
                "Filter by User",
                options=list({a.user for a in alerts}),
                default=list({a.user for a in alerts}),
            )
        
        # Filter alerts
        filtered_alerts = [
            a for a in alerts
            if a.detector in detector_filter
            and a.severity in severity_filter
            and a.user in user_filter
        ]
        
        # Alerts table
        if filtered_alerts:
            alert_data = []
            for a in filtered_alerts:
                severity_emoji = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🟢",
                }[a.severity]
                
                alert_data.append({
                    "Severity": f"{severity_emoji} {a.severity.upper()}",
                    "Detector": a.detector,
                    "User": a.user,
                    "Score": a.score,
                    "Title": a.title,
                    "Time Range": f"{a.ts_start.strftime('%H:%M:%S')} - {a.ts_end.strftime('%H:%M:%S')}",
                    "Alert ID": a.alert_id,
                })
            
            df = pd.DataFrame(alert_data)
            st.dataframe(df, use_container_width=True, hide_index=True)
            
            # Alert details
            st.subheader("Alert Details")
            selected_alert_id = st.selectbox(
                "Select an alert to view details",
                options=[a.alert_id for a in filtered_alerts],
                format_func=lambda x: f"{x} - {next(a.title for a in filtered_alerts if a.alert_id == x)}",
            )
            
            if selected_alert_id:
                alert = next(a for a in filtered_alerts if a.alert_id == selected_alert_id)
                
                st.markdown(f"**{alert.title}**")
                st.write(alert.description)
                
                st.markdown("**Evidence:**")
                st.json(alert.evidence)
        else:
            st.info("No alerts match the current filters.")
    
    with tab2:
        st.subheader("Security Cases")
        
        if cases:
            # Case selector
            case_options = [
                f"{c.case_id} | {c.user} | {c.overall_severity.upper()}"
                for c in cases
            ]
            selected_case_idx = st.selectbox(
                "Select a case to view",
                options=range(len(cases)),
                format_func=lambda i: case_options[i],
            )
            
            case = cases[selected_case_idx]
            
            # Case header
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
            }[case.overall_severity]
            
            st.markdown(f"### {severity_emoji} {case.case_id}")
            st.markdown(f"**User:** {case.user} | **Score:** {case.overall_score}/100")
            st.markdown(f"**Time Range:** {case.ts_start.strftime('%Y-%m-%d %H:%M:%S')} → {case.ts_end.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Summary
            st.markdown("#### Summary")
            st.write(case.summary)
            
            # Alerts in case
            st.markdown("#### Alerts")
            case_alert_data = []
            for a in case.alerts:
                case_alert_data.append({
                    "Detector": a.detector,
                    "Severity": a.severity,
                    "Score": a.score,
                    "Title": a.title,
                })
            st.dataframe(pd.DataFrame(case_alert_data), use_container_width=True, hide_index=True)
            
            # Timeline
            st.markdown("#### Timeline")
            for event in case.timeline:
                result_emoji = "✅" if event.result == "success" else "❌"
                location = f"{event.city}, {event.country}" if event.city and event.country else (event.country or "Unknown")
                st.markdown(
                    f"- **{event.ts.strftime('%H:%M:%S')}** | {result_emoji} {event.result.upper()} | "
                    f"`{event.source_ip}` | {location}"
                )
            
            # Recommended actions
            st.markdown("#### Recommended Actions")
            for action in case.recommended_actions:
                st.markdown(f"- [ ] {action}")
        else:
            st.info("No cases created. Run analysis first.")
    
    with tab3:
        st.subheader("Raw Events")
        
        # Event table
        event_data = []
        for e in events[:100]:  # Limit to 100 for performance
            event_data.append({
                "Timestamp": e.ts.strftime("%Y-%m-%d %H:%M:%S"),
                "User": e.user,
                "Result": e.result,
                "IP": e.source_ip,
                "Country": e.country or "N/A",
                "Device ID": e.device_id[:12] + "..." if e.device_id and len(e.device_id) > 12 else e.device_id,
            })
        
        df = pd.DataFrame(event_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        if len(events) > 100:
            st.caption(f"Showing first 100 of {len(events)} events")


if __name__ == "__main__":
    main()
