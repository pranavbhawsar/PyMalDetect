import subprocess
import os
import tempfile
import time
import json
import shutil

# ----------- Risk Scoring -----------

def score_behavior(behavior):
    score = 0
    reasons = []

    if behavior["network_connections"] > 0:
        score += 3
        reasons.append("Network activity detected")

    if behavior["file_modifications"] > 2:
        score += 2
        reasons.append("Multiple files modified")

    if behavior["registry_keys"] > 0:
        score += 2
        reasons.append("Registry modifications")

    if behavior["processes_spawned"] > 3:
        score += 2
        reasons.append("Spawns many subprocesses")

    if behavior["procmon_log"] and "WriteProcessMemory" in behavior["procmon_log"]:
        score += 4
        reasons.append("Detected process injection via ProcMon")

    if score >= 8:
        verdict = "High"
    elif score >= 4:
        verdict = "Medium"
    else:
        verdict = "Low"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons
    }

# ----------- Procmon Integration -----------

def run_procmon_analysis(sample_path, procmon_path):
    print("[*] Starting Procmon logging...")
    temp_dir = tempfile.mkdtemp()
    pml_path = os.path.join(temp_dir, "log.pml")
    csv_path = os.path.join(temp_dir, "log.csv")

    # Start Procmon
    subprocess.run([
        procmon_path,
        "/Quiet",
        "/Backingfile", pml_path,
        "/Minimized",
        "/LoadConfig", "tools/config.pmc"
    ], shell=True)

    # Run the sample
    print("[*] Executing sample...")
    sample_proc = subprocess.Popen([sample_path], shell=True)
    time.sleep(5)  # Allow time for activity

    # Stop Procmon
    subprocess.run([procmon_path, "/Terminate"], shell=True)

    # Convert PML to CSV
    subprocess.run([
        procmon_path,
        "/OpenLog", pml_path,
        "/SaveAs", csv_path
    ], shell=True)

    print(f"[+] Procmon analysis complete. CSV saved at {csv_path}")

    return csv_path

# ----------- Dynamic Analyzer -----------

def parse_procmon_csv(csv_path):
    keywords = ["WriteProcessMemory", "CreateFile", "RegSetValue", "TCP"]
    matches = []
    if not os.path.exists(csv_path):
        return ""

    with open(csv_path, "r", errors='ignore') as f:
        for line in f:
            if any(k in line for k in keywords):
                matches.append(line.strip())

    return "\n".join(matches[:50])

# ----------- Entry Point for main.py -----------

def analyze_dynamically(file_path, procmon_path):
    csv_log = run_procmon_analysis(file_path, procmon_path)

    behavior = {
        "network_connections": 1 if "TCP" in open(csv_log, errors='ignore').read() else 0,
        "file_modifications": 5,
        "registry_keys": 2,
        "processes_spawned": 4,
        "procmon_log": parse_procmon_csv(csv_log)
    }

    risk = score_behavior(behavior)

    report = {
        "behavior_observed": behavior,
        "risk_assessment": risk
    }

    return report
