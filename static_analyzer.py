import pefile
import hashlib
import os
import time
import json
import re

# ------------------ Risk Scoring System ------------------

def get_string_risk_score(string):
    high_risk = ["CreateRemoteThread", "WriteProcessMemory"]
    medium_risk = ["RegSetValueExA", "RegOpenKeyA", "VirtualAllocEx", "LoadLibraryA"]
    low_risk = ["GetProcAddress", "ShellExecuteA", "WinExec", "InternetOpenA", "WS2_32.dll"]
    very_low = ["KERNEL32.dll", "USER32.dll", "ADVAPI32.dll", "MSVCRT.dll", "GDI32.dll"]

    if string in high_risk:
        return 3
    elif string in medium_risk:
        return 2
    elif string in low_risk:
        return 1
    elif string in very_low:
        return 0.5
    else:
        return 1

def analyze_risk(suspicious_strings):
    detailed_scores = {}
    total_score = 0

    for s in suspicious_strings:
        score = get_string_risk_score(s)
        detailed_scores[s] = score
        total_score += score

    if total_score >= 10:
        verdict = "High"
        emoji = "🔴"
    elif total_score >= 5:
        verdict = "Medium"
        emoji = "🟡"
    else:
        verdict = "Low"
        emoji = "🟢"

    return {
        "string_scores": detailed_scores,
        "total_score": total_score,
        "risk_level": verdict,
        "color_meter": emoji
    }

# ------------------ Static Analyzer ------------------

def compute_hashes(file_path):
    hashes = {"md5": "", "sha1": "", "sha256": ""}
    with open(file_path, "rb") as f:
        data = f.read()
        hashes["md5"] = hashlib.md5(data).hexdigest()
        hashes["sha1"] = hashlib.sha1(data).hexdigest()
        hashes["sha256"] = hashlib.sha256(data).hexdigest()
    return hashes

def extract_pe_info(pe):
    try:
        compile_time = pe.FILE_HEADER.TimeDateStamp
        return {
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "number_of_sections": len(pe.sections),
            "compile_time": compile_time,
            "compile_time_utc": time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(compile_time))
        }
    except Exception as e:
        return {"error": str(e)}

def extract_version_info(pe):
    try:
        infos = {}
        for fileinfo in pe.FileInfo:
            for entry in fileinfo:
                if hasattr(entry, 'StringTable'):
                    for st in entry.StringTable:
                        for k, v in st.entries.items():
                            infos[k.decode(errors='ignore')] = v.decode(errors='ignore')
        return infos
    except Exception as e:
        return {"error": str(e)}

def extract_imports(pe):
    imports = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="ignore")
            imports[dll_name] = len(entry.imports)
    return imports

def extract_strings(file_path, min_length=4):
    with open(file_path, "rb") as f:
        data = f.read()
    strings = re.findall(rb"[ -~]{%d,}" % min_length, data)
    return list(set([s.decode(errors="ignore") for s in strings]))

def find_suspicious_strings(strings):
    suspicious_keywords = [
        "CreateFileA", "DeleteFileA", "RegOpenKeyA", "RegSetValueExA",
        "GetModuleHandleA", "FindResourceA", "GetProcAddress", "LoadLibraryA",
        "CloseHandle", "InternetOpenA", "ShellExecuteA", "VirtualAllocEx",
        "CreateRemoteThread", "WriteProcessMemory"
    ]
    return [s for s in strings if any(kw in s for kw in suspicious_keywords)]

def analyze_file(file_path):
    pe = pefile.PE(file_path)
    strings = extract_strings(file_path)
    suspicious = find_suspicious_strings(strings)

    report = {
        "metadata": {
            "file_name": os.path.basename(file_path),
            "file_size_bytes": os.path.getsize(file_path)
        },
        "hashes": compute_hashes(file_path),
        "pe_info": extract_pe_info(pe),
        "version_info": extract_version_info(pe),
        "imported_libraries": extract_imports(pe),
        "suspicious_api_calls": suspicious,
        "capability_inference": [
            "registry manipulation / privilege escalation" if any(k in suspicious for k in ["RegOpenKeyA", "RegSetValueExA"]) else "",
            "file access or memory manipulation" if any(k in suspicious for k in ["CreateFileA", "DeleteFileA", "WriteProcessMemory"]) else ""
        ],
        "suspicious_strings": [s for s in strings if any(kw in s for kw in ["dll", "exe", "http", "%SystemRoot%", "ShellExecute"])],
        "yara_hits": [],
        "risk_meter": analyze_risk(suspicious)
    }
    return report

# ------------------ Entry Point for main.py ------------------

def run_static_analysis(file_path):
    return analyze_file(file_path)
