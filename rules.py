def detect_suspicious(results):
    alerts = []
    risk_score = 0
    seen_alerts = set()

    # Keep score totals by category so the UI can show a breakdown
    score_breakdown = {
        "processes": 0,
        "paths": 0,
        "injection": 0,
        "network": 0,
        "stability": 0,
        "raw_total": 0,
        "capped_total": 0,
        "was_capped": False
    }

    # Store the strongest findings for reporting
    top_contributors = []
    process_scores = {}
    process_reasons = {}

    # Suspicious process names and their score weight
    suspicious_processes = {
        "powershell.exe": 15,
        "cmd.exe": 12,
        "wscript.exe": 15,
        "cscript.exe": 15,
        "mshta.exe": 18
    }

    # Suspicious path keywords to look for in command lines
    suspicious_paths = [
        "temp",
        "appdata",
        "downloads"
    ]

    # Suspicious ports and their score weight
    suspicious_ports = {
        "4444": 12,
        "1337": 10,
        "5555": 10,
        "6666": 12,
        "8080": 6
    }

    # Common paths/processes that may look suspicious but are usually expected
    known_benign_temp_patterns = [
        "searchprotocolhost.exe",
        "searchindexer.exe",
        "usgthrsvc",
        "dumpit.exe"
    ]

    # Check whether a plugin returned an error or unsupported output
    def plugin_has_error(plugin_output):
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

    # Track how much score a process contributed and why it was flagged
    def add_process_score(process_name, pid, score, reason):
        if not process_name:
            process_name = "Unknown"

        if pid is None or pid == "":
            pid = "Unknown"

        key = f"{process_name}|{pid}"
        process_scores[key] = process_scores.get(key, 0) + score

        if key not in process_reasons:
            process_reasons[key] = []

        if reason not in process_reasons[key]:
            process_reasons[key].append(reason)

    # Add a new alert once, update score totals, and optionally link it to a process
    def add_alert(message, score, category, process_name=None, pid=None, reason=None):
        nonlocal risk_score

        if message not in seen_alerts:
            seen_alerts.add(message)
            alerts.append(message)
            risk_score += score
            score_breakdown[category] += score

            top_contributors.append({
                "message": message,
                "score": score,
                "category": category
            })

            if process_name is not None:
                add_process_score(process_name, pid, score, reason or message)

    # -------------------------------
    # Process detection
    # -------------------------------
    ps = results.get("windows.pslist.PsList", {})
    process_counts = {}
    werfault_count = 0

    if not plugin_has_error(ps):
        for row in ps.get("rows", []):
            row_text = str(row).lower()

            image_name = ""
            handles = 0
            pid = "Unknown"

            if len(row) > 4:
                image_name = str(row[4]).lower()

            if len(row) > 6:
                pid = row[6]

            if len(row) > 3:
                try:
                    handles = int(row[3])
                except:
                    handles = 0

            if image_name:
                process_counts[image_name] = process_counts.get(image_name, 0) + 1

            if image_name == "werfault.exe":
                werfault_count += 1

            # Flag known suspicious process names
            for name, score in suspicious_processes.items():
                if name in row_text:
                    add_alert(
                        f"HIGH: Suspicious process detected ({name}, PID {pid})",
                        score,
                        "processes",
                        process_name=image_name or name,
                        pid=pid,
                        reason="Suspicious process name detected"
                    )

            # Flag abnormal handle counts as a stability concern
            if handles > 100000:
                add_alert(
                    f"HIGH: Extreme handle count detected for {image_name or 'unknown process'} ({handles})",
                    25,
                    "stability",
                    process_name=image_name or "unknown process",
                    pid=pid,
                    reason="Extreme handle count"
                )
            elif handles > 10000:
                add_alert(
                    f"MEDIUM: Abnormal handle count detected for {image_name or 'unknown process'} ({handles})",
                    15,
                    "stability",
                    process_name=image_name or "unknown process",
                    pid=pid,
                    reason="Abnormal handle count"
                )

        # Flag repeated crash-reporting processes if they appear too often
        if werfault_count >= 3:
            add_alert(
                f"MEDIUM: Multiple WerFault.exe processes detected ({werfault_count})",
                10,
                "stability"
            )

        # Flag repeated process instances, excluding very common svchost usage
        for process_name, count in process_counts.items():
            if count >= 8 and process_name != "svchost.exe":
                add_alert(
                    f"MEDIUM: Repeated process instances detected for {process_name} ({count})",
                    8,
                    "stability",
                    process_name=process_name,
                    pid="Unknown",
                    reason="Repeated process instances"
                )

    # -------------------------------
    # Command line detection
    # -------------------------------
    cmd = results.get("windows.cmdline.CmdLine", {})

    if not plugin_has_error(cmd):
        for row in cmd.get("rows", []):
            row_text = str(row).lower()

            # Skip known benign temp-related activity
            if any(pattern in row_text for pattern in known_benign_temp_patterns):
                continue

            process_name = "Unknown"
            pid = "Unknown"

            if len(row) > 2:
                process_name = row[2]

            if len(row) > 1:
                pid = row[1]

            # Flag execution from suspicious user paths
            for path in suspicious_paths:
                if path in row_text:
                    if path == "downloads":
                        add_alert(
                            f"LOW: Execution from user download path detected ({process_name}, PID {pid})",
                            4,
                            "paths",
                            process_name=process_name,
                            pid=pid,
                            reason="Execution from Downloads"
                        )
                    else:
                        add_alert(
                            f"MEDIUM: Execution from suspicious path detected ({path}, {process_name}, PID {pid})",
                            8,
                            "paths",
                            process_name=process_name,
                            pid=pid,
                            reason=f"Execution from {path}"
                        )

    # -------------------------------
    # Memory injection detection
    # -------------------------------
    mal = results.get("windows.malfind.Malfind", {})

    if not plugin_has_error(mal):
        mal_rows = mal.get("rows", [])
        injected = len(mal_rows)

        # Add a base alert if any injected regions were found
        if injected > 0:
            add_alert(
                f"HIGH: {injected} injected memory regions detected",
                min(injected * 6, 35),
                "injection"
            )

            affected_processes = {}

            for row in mal_rows:
                process_name = "Unknown"
                pid = "Unknown"

                if len(row) > 8:
                    process_name = str(row[8])

                if len(row) > 6:
                    pid = row[6]

                key = f"{process_name}|{pid}"
                affected_processes[key] = affected_processes.get(key, 0) + 1

            # Add an extra alert when the same process has multiple injected regions
            for key, count in affected_processes.items():
                process_name, pid = key.split("|", 1)

                if count >= 2:
                    add_alert(
                        f"HIGH: Multiple injected memory regions found in {process_name} (PID {pid}, {count})",
                        min(10 + count, 20),
                        "injection",
                        process_name=process_name,
                        pid=pid,
                        reason=f"Multiple injected memory regions ({count})"
                    )

    # -------------------------------
    # Network detection
    # -------------------------------
    net = results.get("windows.netscan.NetScan", {})

    if not plugin_has_error(net):
        for row in net.get("rows", []):
            row_text = str(row)

            # Flag suspicious ports found in network scan results
            for port, score in suspicious_ports.items():
                if port in row_text:
                    add_alert(
                        f"MEDIUM: Suspicious network port detected ({port})",
                        score,
                        "network"
                    )

    # -------------------------------
    # Final score handling
    # -------------------------------
    raw_total = (
        score_breakdown["processes"] +
        score_breakdown["paths"] +
        score_breakdown["injection"] +
        score_breakdown["network"] +
        score_breakdown["stability"]
    )

    score_breakdown["raw_total"] = raw_total
    score_breakdown["capped_total"] = min(raw_total, 100)
    score_breakdown["was_capped"] = raw_total > 100

    # Cap the final threat score so the UI stays easy to interpret
    if risk_score > 100:
        risk_score = 100

    # Keep only the strongest contributing findings
    top_contributors = sorted(
        top_contributors,
        key=lambda x: x["score"],
        reverse=True
    )[:5]

    # Build a ranked list of the most affected processes
    top_affected_processes = []

    for key, total_score in process_scores.items():
        process_name, pid = key.split("|", 1)

        top_affected_processes.append({
            "name": process_name,
            "pid": pid,
            "score": total_score,
            "indicator_count": len(process_reasons.get(key, [])),
            "reasons": process_reasons.get(key, [])
        })

    top_affected_processes = sorted(
        top_affected_processes,
        key=lambda x: (x["score"], x["indicator_count"]),
        reverse=True
    )[:5]

    return alerts, risk_score, score_breakdown, top_contributors, top_affected_processes