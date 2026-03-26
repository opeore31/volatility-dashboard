from flask import Flask, render_template, request, send_file, jsonify
from plugins import run_plugin, PLUGINS
from rules import detect_suspicious

import os
import json
import datetime
import threading
import time
import tempfile
import uuid

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

app = Flask(__name__)

# -------------------------------
# Project folders
# -------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "dumps")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "outputs")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# -------------------------------
# Global state
# -------------------------------

timeline_events = []

latest_results = None
latest_alerts = None
latest_summary = None
latest_file = None
latest_report = None

analysis_status = {
    "running": False,
    "current_plugin": "Idle",
    "progress": 0,
    "job_id": None
}

# -------------------------------
# Helper functions
# -------------------------------

def shorten_plugin_name(plugin_name):
    """
    Return the short plugin name used in the UI.
    Example: windows.malfind.Malfind -> Malfind
    """
    if "." in plugin_name:
        return plugin_name.split(".")[-1]
    return plugin_name


def plugin_has_error(plugin_output):
    """
    Check whether a plugin returned an error or unsupported output.
    """
    rows = plugin_output.get("rows", [])

    if plugin_output.get("error"):
        return True

    if plugin_output.get("columns") == ["error"]:
        return True

    if len(rows) == 1 and isinstance(rows[0], list) and len(rows[0]) == 1:
        value = str(rows[0][0]).lower()
        if "failed" in value or "not supported" in value or "error" in value:
            return True

    return False


def plugin_status_label(plugin_output):
    """
    Convert plugin health into a short status label for reports.
    """
    if plugin_has_error(plugin_output):
        return "Unsupported"
    return "OK"


def safe_row_count(results, plugin_name):
    """
    Count result rows only if the plugin output is valid.
    """
    plugin_output = results.get(plugin_name, {})

    if plugin_has_error(plugin_output):
        return 0

    return len(plugin_output.get("rows", []))


def allowed_memory_dump(filename):
    """
    Check whether the uploaded file has an allowed memory dump extension.
    """
    allowed_extensions = {".raw", ".mem", ".dmp", ".img", ".bin"}
    extension = os.path.splitext(filename)[1].lower()
    return extension in allowed_extensions


def load_report_file(path):
    """
    Load one saved report safely.
    """
    try:
        with open(path, "r") as f:
            data = json.load(f)

        # Add defaults in case older reports do not contain newer fields
        data.setdefault("investigation_notes", "")
        data.setdefault("pinned_findings", [])
        data.setdefault("review_status", "Not Reviewed")

        return data
    except Exception:
        return None


def save_report_file(path, data):
    """
    Save one report safely.
    """
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


def get_report_path_by_job_id(job_id):
    """
    Find a saved report using its job ID.
    """
    for filename in os.listdir(OUTPUT_FOLDER):
        if not filename.endswith(".json"):
            continue

        path = os.path.join(OUTPUT_FOLDER, filename)
        data = load_report_file(path)

        if data and data.get("job_id") == job_id:
            return path

    return None


def reset_latest_state_if_deleted(path):
    """
    Clear current in-memory state if the active report was deleted.
    """
    global latest_results, latest_alerts, latest_summary, latest_file, latest_report

    if latest_file == path:
        latest_results = None
        latest_alerts = None
        latest_summary = None
        latest_file = None
        latest_report = None


def build_report_data(
    results,
    alerts,
    summary,
    timestamp,
    source_filename,
    selected_plugins,
    analysis_duration,
    score_breakdown,
    top_contributors,
    top_affected_processes,
    job_id
):
    """
    Build the full structured report used by:
    - the results page
    - the JSON export
    - the PDF export
    """
    info_rows = results.get("windows.info.Info", {}).get("rows", [])

    system_time = "Unknown"
    build_lab = "Unknown"
    nt_system_root = "Unknown"
    is_64_bit = "Unknown"

    for row in info_rows:
        if len(row) > 1 and row[1] == "SystemTime":
            system_time = row[0]
        if len(row) > 1 and row[1] == "NTBuildLab":
            build_lab = row[0]
        if len(row) > 1 and row[1] == "NtSystemRoot":
            nt_system_root = row[0]
        if len(row) > 1 and row[1] == "Is64Bit":
            is_64_bit = row[0]

    # Count alerts by severity
    high_count = 0
    medium_count = 0
    low_count = 0

    for alert in alerts:
        if alert.startswith("HIGH:"):
            high_count += 1
        elif alert.startswith("MEDIUM:"):
            medium_count += 1
        else:
            low_count += 1

    risk_score = summary.get("risk_score", 0)
    raw_total = score_breakdown.get("raw_total", risk_score)
    capped_total = score_breakdown.get("capped_total", risk_score)
    was_capped = score_breakdown.get("was_capped", False)

    # Create a short executive summary based on score
    if risk_score >= 80:
        executive_summary = (
            "High-risk indicators were detected in this memory image and the dump "
            "should be prioritized for investigation."
        )
    elif risk_score >= 40:
        executive_summary = (
            "Moderate suspicious activity was detected in this memory image and the findings "
            "should be reviewed carefully."
        )
    else:
        executive_summary = (
            "Limited suspicious activity was detected in this memory image, but the findings "
            "should still be reviewed in context."
        )

    # Track whether each main plugin worked
    plugin_status = {
        "Info": plugin_status_label(results.get("windows.info.Info", {})),
        "PsList": plugin_status_label(results.get("windows.pslist.PsList", {})),
        "PsTree": plugin_status_label(results.get("windows.pstree.PsTree", {})),
        "CmdLine": plugin_status_label(results.get("windows.cmdline.CmdLine", {})),
        "DllList": plugin_status_label(results.get("windows.dlllist.DllList", {})),
        "Malfind": plugin_status_label(results.get("windows.malfind.Malfind", {})),
        "VadInfo": plugin_status_label(results.get("windows.vadinfo.VadInfo", {})),
        "NetScan": plugin_status_label(results.get("windows.netscan.NetScan", {}))
    }

    # Extract a smaller list of strong evidence points for the report
    high_priority_evidence = []

    ps = results.get("windows.pslist.PsList", {})
    if not plugin_has_error(ps):
        for row in ps.get("rows", []):
            row_text = str(row).lower()
            image_name = row[4] if len(row) > 4 else "Unknown"
            pid = row[6] if len(row) > 6 else "Unknown"

            if any(name in row_text for name in [
                "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"
            ]):
                high_priority_evidence.append(
                    f"Suspicious process detected: {image_name} (PID: {pid})"
                )

    cmd = results.get("windows.cmdline.CmdLine", {})
    if not plugin_has_error(cmd):
        for row in cmd.get("rows", []):
            row_text = str(row).lower()

            reason = None
            if "temp" in row_text:
                reason = "Temp"
            elif "appdata" in row_text:
                reason = "AppData"
            elif "downloads" in row_text:
                reason = "Downloads"

            if reason:
                process_name = row[2] if len(row) > 2 else "Unknown"
                pid = row[1] if len(row) > 1 else "Unknown"

                high_priority_evidence.append(
                    f"Suspicious path activity: {process_name} (PID: {pid}) referenced {reason}"
                )

    mal = results.get("windows.malfind.Malfind", {})
    if not plugin_has_error(mal):
        mal_rows = mal.get("rows", [])

        for row in mal_rows[:5]:
            process_name = row[8] if len(row) > 8 else "Unknown"
            protection = row[9] if len(row) > 9 else "Unknown"
            start_vpn = row[10] if len(row) > 10 else "Unknown"
            tag = row[11] if len(row) > 11 else "Unknown"
            pid = row[6] if len(row) > 6 else "Unknown"

            if isinstance(start_vpn, int):
                start_vpn = hex(start_vpn)

            high_priority_evidence.append(
                f"Injected memory evidence: {process_name} (PID: {pid}) had an executable writable "
                f"region at {start_vpn} with protection {protection} [{tag}]"
            )

    net = results.get("windows.netscan.NetScan", {})
    if not plugin_has_error(net):
        for row in net.get("rows", []):
            row_text = str(row)

            if any(port in row_text for port in ["4444", "1337", "5555", "6666", "8080"]):
                high_priority_evidence.append(f"Suspicious network entry: {row}")

    # Build a small list of processes hit by more than one indicator
    correlated_findings = []

    for proc in top_affected_processes:
        if proc.get("indicator_count", 0) >= 2:
            correlated_findings.append(
                f"{proc['name']} (PID {proc['pid']}) was flagged by multiple indicators: "
                f"{', '.join(proc.get('reasons', []))}."
            )

    # Highlight the main sections analysts usually review
    commonly_reviewed_sections = [
        {
            "title": "Processes",
            "plugin": "PsList",
            "status": plugin_status["PsList"],
            "count": summary.get("processes", 0),
            "note": "Review running processes, suspicious image names, parent-child relationships, and shell activity."
        },
        {
            "title": "Process Tree",
            "plugin": "PsTree",
            "status": plugin_status["PsTree"],
            "count": safe_row_count(results, "windows.pstree.PsTree"),
            "note": "Review parent-child relationships to identify suspicious process spawning."
        },
        {
            "title": "Command Lines",
            "plugin": "CmdLine",
            "status": plugin_status["CmdLine"],
            "count": safe_row_count(results, "windows.cmdline.CmdLine"),
            "note": "Review executed paths, Temp/AppData/Downloads usage, and suspicious command invocations."
        },
        {
            "title": "Injected Memory",
            "plugin": "Malfind",
            "status": plugin_status["Malfind"],
            "count": summary.get("injected_regions", 0),
            "note": "Review executable writable memory regions and repeated hits in the same process."
        },
        {
            "title": "Network Activity",
            "plugin": "NetScan",
            "status": plugin_status["NetScan"],
            "count": summary.get("network_connections", 0),
            "note": "Review suspicious ports, remote addresses, and associated processes."
        },
        {
            "title": "DLL Review",
            "plugin": "DllList",
            "status": plugin_status["DllList"],
            "count": safe_row_count(results, "windows.dlllist.DllList"),
            "note": "Review loaded DLLs for unusual modules and unexpected injection artifacts."
        },
        {
            "title": "VAD Review",
            "plugin": "VadInfo",
            "status": plugin_status["VadInfo"],
            "count": safe_row_count(results, "windows.vadinfo.VadInfo"),
            "note": "Review memory regions and protections for anomalous mappings."
        }
    ]

    # Assign a triage label based on score
    if risk_score >= 80:
        triage_level = "High Priority Investigation"
    elif risk_score >= 40:
        triage_level = "Needs Review"
    else:
        triage_level = "Low Concern"

    # Build an explanation block for the score
    score_explanation = {
        "score": risk_score,
        "max_score": 100,
        "raw_total": raw_total,
        "capped_total": capped_total,
        "was_capped": was_capped,
        "triage_level": triage_level,
        "summary": executive_summary,
        "how_it_works": [
            "High-severity findings contribute the most to the score.",
            "Medium-severity findings contribute moderately.",
            "Low-severity findings contribute lightly.",
            "Injected memory and repeated suspicious behaviour can increase the score significantly.",
            "The final score is capped at 100."
        ]
    }

    # Suggest useful next steps for the analyst
    recommendations = []

    if risk_score >= 80:
        recommendations.append("Prioritize this memory image for immediate analyst review.")

    if top_affected_processes:
        recommendations.append(
            f"Prioritize investigation of {top_affected_processes[0]['name']} "
            f"(PID {top_affected_processes[0]['pid']}) due to highest cumulative risk contribution."
        )

    if plugin_status["Malfind"] == "OK" and summary.get("injected_regions", 0) > 0:
        recommendations.append(
            "Investigate injected-memory hits in Malfind and correlate them with the affected processes."
        )

    if plugin_status["NetScan"] != "OK":
        recommendations.append(
            "Network visibility was limited because NetScan was unsupported for this dump."
        )

    if plugin_status["PsTree"] == "OK":
        recommendations.append(
            "Review the process tree to confirm suspicious parent-child execution chains."
        )

    if not recommendations:
        recommendations.append(
            "Review the full plugin output to confirm whether any low-signal findings require escalation."
        )

    # Build short headline findings for the report
    key_findings = [
        f"Source file analyzed: {source_filename}",
        f"System build identified as {build_lab}",
        f"System root identified as {nt_system_root}",
        f"64-bit operating system: {is_64_bit}",
        f"Memory snapshot system time was {system_time}",
        f"Total processes observed: {summary.get('processes', 0)}",
        f"Total network connections observed: {summary.get('network_connections', 0)}",
        f"Total injected regions observed: {summary.get('injected_regions', 0)}",
        f"High severity alerts: {high_count}",
        f"Medium severity alerts: {medium_count}",
        f"Low severity alerts: {low_count}",
        f"Triage level: {triage_level}"
    ]

    if was_capped:
        key_findings.append(
            f"Raw score contribution reached {raw_total}, so the final threat score was capped at {capped_total}."
        )

    if plugin_status["NetScan"] != "OK":
        key_findings.append(
            "NetScan was unsupported for this dump, so connection counts were not derived from valid NetScan data."
        )

    if plugin_status["Malfind"] != "OK":
        key_findings.append(
            "Malfind was unsupported for this dump, so injected-region counts were not derived from valid Malfind data."
        )

    if plugin_status["PsList"] != "OK":
        key_findings.append(
            "PsList was unsupported for this dump, so process counts were not derived from valid PsList data."
        )

    generated_dt = datetime.datetime.strptime(timestamp, "%Y%m%d_%H%M%S")

    return {
        "job_id": job_id,
        "report_title": "Memory Forensics Report",
        "generated_at": generated_dt.strftime("%d %B %Y, %H:%M"),
        "source_file": source_filename,
        "selected_plugins": [shorten_plugin_name(p) for p in selected_plugins],
        "analysis_duration_seconds": analysis_duration,
        "executive_summary": executive_summary,
        "system_details": {
            "build_lab": build_lab,
            "system_time": system_time,
            "system_root": nt_system_root,
            "is_64_bit": is_64_bit
        },
        "summary": summary,
        "severity_counts": {
            "high": high_count,
            "medium": medium_count,
            "low": low_count
        },
        "score_breakdown": score_breakdown,
        "top_contributors": top_contributors,
        "score_explanation": score_explanation,
        "plugin_status": plugin_status,
        "alerts": alerts,
        "key_findings": key_findings,
        "high_priority_evidence": high_priority_evidence,
        "commonly_reviewed_sections": commonly_reviewed_sections,
        "top_affected_processes": top_affected_processes,
        "correlated_findings": correlated_findings,
        "recommendations": recommendations,
        "investigation_notes": "",
        "pinned_findings": [],
        "review_status": "Not Reviewed"
    }

# -------------------------------
# Routes
# -------------------------------

@app.route("/")
def index():
    return render_template("index.html", plugins=PLUGINS)


@app.route("/settings")
def settings():
    return render_template("settings.html")


@app.route("/timeline")
def timeline():
    return render_template("timeline.html", events=timeline_events)


@app.route("/complete")
def complete():
    return render_template("complete.html")


@app.route("/status")
def status():
    return jsonify(analysis_status)


@app.route("/results")
def results():
    if latest_results is None and latest_report is None:
        return "No analysis yet."

    return render_template(
        "results.html",
        results=latest_results or {},
        alerts=latest_alerts or [],
        summary=latest_summary or {},
        file=latest_file,
        report=latest_report or {}
    )


@app.route("/download_json/<path:file>")
def download_json(file):
    return send_file(file, as_attachment=True)


@app.route("/download_pdf")
def download_pdf():
    """
    Build and return a PDF version of the latest report.
    """
    if latest_report is None:
        return "No analysis yet."

    pdf_path = os.path.join(OUTPUT_FOLDER, "analysis_report.pdf")

    doc = SimpleDocTemplate(pdf_path)
    styles = getSampleStyleSheet()
    content = []

    summary = latest_report.get("summary", {})
    alerts = latest_report.get("alerts", [])
    key_findings = latest_report.get("key_findings", [])
    severity_counts = latest_report.get("severity_counts", {})
    system_details = latest_report.get("system_details", {})
    high_priority_evidence = latest_report.get("high_priority_evidence", [])
    plugin_status = latest_report.get("plugin_status", {})
    commonly_reviewed_sections = latest_report.get("commonly_reviewed_sections", [])
    score_breakdown = latest_report.get("score_breakdown", {})
    top_contributors = latest_report.get("top_contributors", [])
    score_explanation = latest_report.get("score_explanation", {})
    top_affected_processes = latest_report.get("top_affected_processes", [])
    correlated_findings = latest_report.get("correlated_findings", [])
    recommendations = latest_report.get("recommendations", [])
    investigation_notes = latest_report.get("investigation_notes", "")
    pinned_findings = latest_report.get("pinned_findings", [])
    review_status = latest_report.get("review_status", "Not Reviewed")

    content.append(Paragraph(latest_report.get("report_title", "Memory Forensics Report"), styles["Title"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Report Overview", styles["Heading2"]))
    content.append(Paragraph(f"Job ID: {latest_report.get('job_id', 'Unknown')}", styles["Normal"]))
    content.append(Paragraph(f"Source File: {latest_report.get('source_file', 'Unknown')}", styles["Normal"]))
    content.append(Paragraph(f"Generated At: {latest_report.get('generated_at', 'Unknown')}", styles["Normal"]))
    content.append(Paragraph(f"Analysis Duration: {latest_report.get('analysis_duration_seconds', 0)} seconds", styles["Normal"]))
    content.append(Paragraph(f"Selected Plugins: {', '.join(latest_report.get('selected_plugins', []))}", styles["Normal"]))
    content.append(Paragraph(f"Review Status: {review_status}", styles["Normal"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Executive Summary", styles["Heading2"]))
    content.append(Paragraph(latest_report.get("executive_summary", "No executive summary available."), styles["Normal"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Risk Summary", styles["Heading2"]))
    content.append(Paragraph(f"Threat Score: {summary.get('risk_score', 0)} / 100", styles["Normal"]))
    content.append(Paragraph(f"Raw Score Contribution: {score_explanation.get('raw_total', summary.get('risk_score', 0))}", styles["Normal"]))
    content.append(Paragraph(f"Triage Level: {score_explanation.get('triage_level', 'Unknown')}", styles["Normal"]))
    content.append(Paragraph(f"High Alerts: {severity_counts.get('high', 0)}", styles["Normal"]))
    content.append(Paragraph(f"Medium Alerts: {severity_counts.get('medium', 0)}", styles["Normal"]))
    content.append(Paragraph(f"Low Alerts: {severity_counts.get('low', 0)}", styles["Normal"]))

    if score_explanation.get("was_capped"):
        content.append(
            Paragraph(
                f"Note: Raw score contribution exceeded 100 and was capped to {score_explanation.get('capped_total', 100)}.",
                styles["Normal"]
            )
        )

    content.append(Spacer(1, 12))

    content.append(Paragraph("Threat Score Explanation", styles["Heading2"]))
    for line in score_explanation.get("how_it_works", []):
        content.append(Paragraph(f"- {line}", styles["Normal"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Top Contributing Factors", styles["Heading2"]))
    if top_contributors:
        for item in top_contributors:
            content.append(
                Paragraph(
                    f"{item.get('message', 'Unknown finding')} "
                    f"(Score Impact: {item.get('score', 0)}, Category: {item.get('category', 'unknown')})",
                    styles["Normal"]
                )
            )
    else:
        content.append(Paragraph("No major score contributors were recorded.", styles["Normal"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Pinned Findings", styles["Heading2"]))
    if pinned_findings:
        for item in pinned_findings:
            content.append(Paragraph(f"- {item}", styles["Normal"]))
    else:
        content.append(Paragraph("No pinned findings saved.", styles["Normal"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Score Breakdown", styles["Heading2"]))
    content.append(Paragraph(f"Processes: {score_breakdown.get('processes', 0)}", styles["Normal"]))
    content.append(Paragraph(f"Paths: {score_breakdown.get('paths', 0)}", styles["Normal"]))
    content.append(Paragraph(f"Injection: {score_breakdown.get('injection', 0)}", styles["Normal"]))
    content.append(Paragraph(f"Network: {score_breakdown.get('network', 0)}", styles["Normal"]))
    content.append(Paragraph(f"Stability: {score_breakdown.get('stability', 0)}", styles["Normal"]))
    content.append(Paragraph(f"Raw Total: {score_breakdown.get('raw_total', 0)}", styles["Normal"]))
    content.append(Paragraph(f"Capped Total: {score_breakdown.get('capped_total', 0)}", styles["Normal"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Top Affected Processes", styles["Heading2"]))
    if top_affected_processes:
        for proc in top_affected_processes:
            content.append(
                Paragraph(
                    f"{proc.get('name', 'Unknown')} (PID {proc.get('pid', 'Unknown')}): "
                    f"score {proc.get('score', 0)}, {proc.get('indicator_count', 0)} indicators",
                    styles["Normal"]
                )
            )
            for reason in proc.get("reasons", []):
                content.append(Paragraph(f"  - {reason}", styles["Normal"]))
    else:
        content.append(Paragraph("No top affected processes were derived.", styles["Normal"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Correlated Findings", styles["Heading2"]))
    if correlated_findings:
        for item in correlated_findings:
            content.append(Paragraph(item, styles["Normal"]))
    else:
        content.append(Paragraph("No multi-indicator correlated findings were derived.", styles["Normal"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("System Details", styles["Heading2"]))
    content.append(Paragraph(f"Build Lab: {system_details.get('build_lab', 'Unknown')}", styles["Normal"]))
    content.append(Paragraph(f"System Time: {system_details.get('system_time', 'Unknown')}", styles["Normal"]))
    content.append(Paragraph(f"System Root: {system_details.get('system_root', 'Unknown')}", styles["Normal"]))
    content.append(Paragraph(f"64-bit OS: {system_details.get('is_64_bit', 'Unknown')}", styles["Normal"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Core Counts", styles["Heading2"]))
    content.append(Paragraph(f"Processes: {summary.get('processes', 0)}", styles["Normal"]))
    content.append(Paragraph(f"Connections: {summary.get('network_connections', 0)}", styles["Normal"]))
    content.append(Paragraph(f"Injected Regions: {summary.get('injected_regions', 0)}", styles["Normal"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Commonly Reviewed Areas", styles["Heading2"]))
    for section in commonly_reviewed_sections:
        content.append(
            Paragraph(
                f"{section.get('title', 'Unknown')}: {section.get('status', 'Unknown')} "
                f"(Rows: {section.get('count', 0)}) - {section.get('note', '')}",
                styles["Normal"]
            )
        )
    content.append(Spacer(1, 12))

    content.append(Paragraph("Limitations / Plugin Status", styles["Heading2"]))
    for plugin_name, status in plugin_status.items():
        content.append(Paragraph(f"{plugin_name}: {status}", styles["Normal"]))

    if plugin_status.get("NetScan") != "OK" or plugin_status.get("Malfind") != "OK" or plugin_status.get("PsList") != "OK":
        content.append(
            Paragraph(
                "Note: Unsupported plugins mean some counts or findings may be lower or unavailable for this dump.",
                styles["Normal"]
            )
        )

    content.append(Spacer(1, 12))

    content.append(Paragraph("High Priority Evidence", styles["Heading2"]))
    if high_priority_evidence:
        for item in high_priority_evidence:
            content.append(Paragraph(item, styles["Normal"]))
    else:
        content.append(Paragraph("No high priority evidence extracted.", styles["Normal"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Detection Alerts", styles["Heading2"]))
    if alerts:
        for alert in alerts:
            content.append(Paragraph(alert, styles["Normal"]))
    else:
        content.append(Paragraph("No suspicious findings detected.", styles["Normal"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Recommended Next Steps", styles["Heading2"]))
    for item in recommendations:
        content.append(Paragraph(f"- {item}", styles["Normal"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Investigation Notes", styles["Heading2"]))
    if investigation_notes.strip():
        content.append(Paragraph(investigation_notes, styles["Normal"]))
    else:
        content.append(Paragraph("No investigation notes saved.", styles["Normal"]))
    content.append(Spacer(1, 12))

    content.append(Paragraph("Key Findings", styles["Heading2"]))
    for finding in key_findings:
        content.append(Paragraph(finding, styles["Normal"]))

    doc.build(content)

    return send_file(pdf_path, as_attachment=True)

# -------------------------------
# History routes
# -------------------------------

@app.route("/history")
def history():
    print("HISTORY PAGE HIT")

    files = []

    for file in os.listdir(OUTPUT_FOLDER):
        if file.endswith(".json"):
            path = os.path.join(OUTPUT_FOLDER, file)

            report_data = load_report_file(path)

            if report_data is None:
                report_data = {}

            files.append({
                "name": file,
                "job_id": report_data.get("job_id", ""),
                "time": datetime.datetime.fromtimestamp(
                    os.path.getmtime(path)
                ).strftime("%Y-%m-%d %H:%M:%S"),
                "source_file": report_data.get("source_file", "Unknown"),
                "risk_score": report_data.get("summary", {}).get("risk_score", 0),
                "triage_level": report_data.get("score_explanation", {}).get("triage_level", ""),
                "review_status": report_data.get("review_status", "Not Reviewed"),
                "executive_summary": report_data.get("executive_summary", "No summary available.")
            })

    files.sort(key=lambda x: x["time"], reverse=True)

    return render_template("history.html", files=files)


@app.route("/history/view/<filename>")
def view_history(filename):
    global latest_results, latest_alerts, latest_summary, latest_file, latest_report

    path = os.path.join(OUTPUT_FOLDER, filename)

    if not os.path.exists(path):
        return "File not found"

    data = load_report_file(path)

    if data is None:
        return "Unable to load report"

    latest_results = {}
    latest_alerts = data.get("alerts", [])
    latest_summary = data.get("summary", {})
    latest_file = path
    latest_report = data

    analysis_status["job_id"] = data.get("job_id")

    return render_template(
        "results.html",
        results=latest_results,
        alerts=latest_alerts,
        summary=latest_summary,
        file=path,
        report=latest_report
    )


@app.route("/history/mark_reviewed/<filename>", methods=["POST"])
def mark_report_reviewed(filename):
    """
    Mark a saved report as reviewed.
    """
    path = os.path.join(OUTPUT_FOLDER, filename)

    if not os.path.exists(path):
        return jsonify({"error": "Report not found."}), 404

    data = load_report_file(path)

    if data is None:
        return jsonify({"error": "Unable to load report."}), 500

    data["review_status"] = "Reviewed"
    save_report_file(path, data)

    global latest_report
    if latest_file == path and latest_report is not None:
        latest_report["review_status"] = "Reviewed"

    return jsonify({"message": "Report marked as reviewed."}), 200


@app.route("/history/delete/<filename>", methods=["POST"])
def delete_report(filename):
    """
    Delete a saved report file.
    """
    path = os.path.join(OUTPUT_FOLDER, filename)

    if not os.path.exists(path):
        return jsonify({"error": "Report not found."}), 404

    try:
        os.remove(path)
        reset_latest_state_if_deleted(path)
        return jsonify({"message": "Report deleted successfully."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -------------------------------
# Report data API
# -------------------------------

@app.route("/api/report/<job_id>/notes", methods=["GET", "POST"])
def report_notes(job_id):
    """
    Read or update investigation notes for a saved report.
    """
    path = get_report_path_by_job_id(job_id)

    if not path:
        return jsonify({"error": "Report not found."}), 404

    data = load_report_file(path)

    if data is None:
        return jsonify({"error": "Unable to load report."}), 500

    if request.method == "GET":
        return jsonify({
            "job_id": job_id,
            "investigation_notes": data.get("investigation_notes", "")
        }), 200

    payload = request.get_json(silent=True) or {}
    notes = payload.get("investigation_notes", "")

    data["investigation_notes"] = notes
    save_report_file(path, data)

    global latest_report
    if latest_report is not None and latest_report.get("job_id") == job_id:
        latest_report["investigation_notes"] = notes

    return jsonify({"message": "Notes saved successfully."}), 200


@app.route("/api/report/<job_id>/pins", methods=["GET", "POST", "DELETE"])
def report_pins(job_id):
    """
    Read, add, or remove pinned findings for a saved report.
    """
    path = get_report_path_by_job_id(job_id)

    if not path:
        return jsonify({"error": "Report not found."}), 404

    data = load_report_file(path)

    if data is None:
        return jsonify({"error": "Unable to load report."}), 500

    pins = data.get("pinned_findings", [])

    if request.method == "GET":
        return jsonify({
            "job_id": job_id,
            "pinned_findings": pins
        }), 200

    payload = request.get_json(silent=True) or {}
    finding = payload.get("finding", "").strip()

    if request.method == "POST":
        if not finding:
            return jsonify({"error": "No finding was provided."}), 400

        if finding not in pins:
            pins.append(finding)

        data["pinned_findings"] = pins
        save_report_file(path, data)

        global latest_report
        if latest_report is not None and latest_report.get("job_id") == job_id:
            latest_report["pinned_findings"] = pins

        return jsonify({
            "message": "Pinned finding saved.",
            "pinned_findings": pins
        }), 200

    if not finding:
        return jsonify({"error": "No finding was provided."}), 400

    pins = [item for item in pins if item != finding]
    data["pinned_findings"] = pins
    save_report_file(path, data)

    if latest_report is not None and latest_report.get("job_id") == job_id:
        latest_report["pinned_findings"] = pins

    return jsonify({
        "message": "Pinned finding removed.",
        "pinned_findings": pins
    }), 200

# -------------------------------
# Background analysis
# -------------------------------

def run_analysis_background(filepath, selected_plugins, original_filename, job_id):
    """
    Run selected plugins in the background, apply rules,
    and save the final report.
    """
    global latest_results, latest_alerts, latest_summary, latest_file, latest_report

    print("Background thread started")

    analysis_start = time.time()

    results = {}
    total = len(selected_plugins)

    analysis_status["running"] = True
    analysis_status["progress"] = 0
    analysis_status["current_plugin"] = "Initializing..."
    analysis_status["job_id"] = job_id

    for i, plugin in enumerate(selected_plugins):
        print("Running plugin:", plugin)

        analysis_status["current_plugin"] = shorten_plugin_name(plugin)

        start = time.time()

        try:
            output = run_plugin(filepath, plugin)
        except Exception as e:
            output = {"error": str(e)}

        end = time.time()
        duration = round(end - start, 2)

        results[plugin] = output

        timeline_events.append({
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "description": f"{plugin} completed ({duration}s)"
        })

        analysis_status["progress"] = int(((i + 1) / total) * 100)

    analysis_status["current_plugin"] = "Finalizing..."

    # Apply the rules engine after all plugins finish
    try:
        alerts, risk_score, score_breakdown, top_contributors, top_affected_processes = detect_suspicious(results)
    except Exception as e:
        print("detect_suspicious failed:", repr(e))
        alerts, risk_score, score_breakdown, top_contributors, top_affected_processes = [], 0, {
            "processes": 0,
            "paths": 0,
            "injection": 0,
            "network": 0,
            "stability": 0,
            "raw_total": 0,
            "capped_total": 0,
            "was_capped": False
        }, [], []

    summary = {
        "processes": safe_row_count(results, "windows.pslist.PsList"),
        "network_connections": safe_row_count(results, "windows.netscan.NetScan"),
        "injected_regions": safe_row_count(results, "windows.malfind.Malfind"),
        "risk_score": risk_score
    }

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    analysis_duration = round(time.time() - analysis_start, 2)

    report_data = build_report_data(
        results,
        alerts,
        summary,
        timestamp,
        original_filename,
        selected_plugins,
        analysis_duration,
        score_breakdown,
        top_contributors,
        top_affected_processes,
        job_id
    )

    output_file = os.path.join(
        OUTPUT_FOLDER,
        f"analysis_{timestamp}.json"
    )

    with open(output_file, "w") as f:
        json.dump(report_data, f, indent=4)

    latest_results = results
    latest_alerts = alerts
    latest_summary = summary
    latest_file = output_file
    latest_report = report_data

    if os.path.exists(filepath):
        os.remove(filepath)

    analysis_status["running"] = False
    analysis_status["current_plugin"] = "Completed"
    analysis_status["progress"] = 100
    analysis_status["job_id"] = job_id

    print("Analysis finished")

# -------------------------------
# Run analysis route
# -------------------------------

@app.route("/run", methods=["POST"])
def run_analysis():
    """
    Validate the upload, start the background analysis,
    and return a job ID to the frontend.
    """
    print("RUN ENDPOINT HIT")

    uploaded = request.files.get("dumpfile")

    if not uploaded or uploaded.filename.strip() == "":
        print("NO FILE UPLOADED")
        return jsonify({
            "error": "Please upload a memory dump before starting analysis."
        }), 400

    original_filename = uploaded.filename

    if not allowed_memory_dump(original_filename):
        return jsonify({
            "error": "Unsupported file type. Please upload a valid memory dump (.raw, .mem, .dmp, .img, .bin)."
        }), 400

    job_id = str(uuid.uuid4())[:8]

    suffix = os.path.splitext(uploaded.filename)[1]
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    uploaded.save(temp_file.name)
    temp_file.close()

    filepath = temp_file.name

    print("FILE SAVED:", filepath)

    selected_plugins = request.form.getlist("plugins")

    if not selected_plugins:
        selected_plugins = PLUGINS

    analysis_status["progress"] = 0
    analysis_status["current_plugin"] = "Queued..."
    analysis_status["running"] = True
    analysis_status["job_id"] = job_id

    thread = threading.Thread(
        target=run_analysis_background,
        args=(filepath, selected_plugins, original_filename, job_id)
    )

    thread.start()

    return jsonify({"job_id": job_id}), 200

# -------------------------------
# Main entry point
# -------------------------------

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)