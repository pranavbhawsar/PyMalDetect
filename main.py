from static_analyzer import run_static_analysis
from dynamic_analyzer import analyze_dynamically
from report_generator import generate_html_report
import json
import os

def calculate_dynamic_risk(dynamic_result):
    score = 0
    reasons = []

    file_ops = dynamic_result.get("file_operations", [])
    reg_ops = dynamic_result.get("registry_operations", [])
    net_ops = dynamic_result.get("network_operations", [])
    suspicious = dynamic_result.get("suspicious_activities", [])

    if len(file_ops) > 10:
        score += 1
        reasons.append("High number of file operations")

    for reg in reg_ops:
        if "Run" in reg["Path"]:
            score += 2
            reasons.append("Modifies startup registry keys")
            break

    if net_ops:
        score += 2
        reasons.append("Network activity detected")

    if suspicious:
        score += 3
        reasons.append("Suspicious behavior observed")

    verdict = "Low"
    if score >= 6:
        verdict = "High"
    elif score >= 3:
        verdict = "Medium"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons
    }

def main():
    sample_path = "samples/sample.exe"
    output_dir = "output"
    static_output_path = os.path.join(output_dir, "static_report.json")
    dynamic_output_path = os.path.join(output_dir, "dynamic_report.json")
    final_report_path = os.path.join(output_dir, "full_analysis.json")
    procmon_path = "tools/Procmon64.exe"

    if not os.path.exists(sample_path):
        print("[!] Sample file not found.")
        return

    os.makedirs(output_dir, exist_ok=True)

    # Run static analysis
    print("[*] Starting static analysis...")
    static_result = run_static_analysis(sample_path)
    with open(static_output_path, "w") as f:
        json.dump(static_result, f, indent=4)
    print(f"[+] Static analysis completed. Report saved at {static_output_path}")

    # Run dynamic analysis
    print("[*] Starting dynamic analysis...")
    dynamic_result = analyze_dynamically(sample_path, procmon_path)

    # Add risk score based on dynamic analysis
    risk_assessment = calculate_dynamic_risk(dynamic_result)
    dynamic_result["risk_assessment"] = risk_assessment

    with open(dynamic_output_path, "w") as f:
        json.dump(dynamic_result, f, indent=4)
    print(f"[+] Dynamic analysis completed. Report saved at {dynamic_output_path}")

    # Combine both
    full_report = {
        "static_analysis": static_result,
        "dynamic_analysis": dynamic_result
    }
    with open(final_report_path, "w") as f:
        json.dump(full_report, f, indent=4)
    print(f"[+] Full report saved at {final_report_path}")

    # Generate HTML report
    generate_html_report(full_report)

if __name__ == "__main__":
    main()
