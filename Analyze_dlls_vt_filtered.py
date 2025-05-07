import json
import sys
from datetime import datetime
import os
import requests
import time

VT_API_KEY = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
VT_URL = "https://www.virustotal.com/api/v3/files/"

def vt_check_md5(md5):
    headers = {
        "x-apikey": VT_API_KEY
    }
    try:
        response = requests.get(VT_URL + md5, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            mal_count = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            permalink = f"https://www.virustotal.com/gui/file/{md5}/detection"
            return f"{mal_count} rilevazioni su {total}", permalink
        elif response.status_code == 404:
            return "Not found on VirusTotal", ""
        else:
            return f"API error: {response.status_code}", ""
    except Exception as e:
        return f"VirusTotal request error: {str(e)}", ""

def is_suspicious(dll):
    reasons = []
    safe_paths = [
        r"c:\windows\system32",
        r"c:\windows\syswow64",
        r"c:\windows",
        r"c:\program files",
        r"c:\program files (x86)"
    ]
    system_dlls = {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
        "advapi32.dll", "msvcrt.dll", "sechost.dll", "rpcrt4.dll",
        "bcrypt.dll", "wldap32.dll", "ucrtbase.dll"
    }
    suspicious_paths = [
        "\\temp\\", "\\tmp\\", "\\downloads\\", "\\appdata\\local\\temp\\"
    ]
    path = dll.get("DllPath", "").lower()
    name = dll.get("DllName", "").lower()

    if not any(path.startswith(p) for p in safe_paths):
        if name in system_dlls:
            reasons.append("DLL di sistema in percorso non standard")
        else:
            reasons.append("Path non standard")

    if any(s in path for s in suspicious_paths):
        reasons.append("Directory sospetta")

    if not dll.get("Company"):
        reasons.append("Produttore non specificato")

    if dll.get("FileVersion") in ["0.0.0.0", "", None]:
        reasons.append("Versione file sospetta")

    if "Errore" in dll.get("MD5Hash", "") or dll.get("MD5Hash") in ["File non trovato", "File in uso", None]:
        reasons.append("Hash non calcolabile")

    if dll.get("FileSize", 0) < 1000:
        reasons.append("Dimensione file sospetta")

    return reasons

def main():
    if len(sys.argv) != 2:
        print("Uso: python analyze_dlls_vt.py <percorso_file_json>")
        sys.exit(1)

    json_path = sys.argv[1]
    print(f"Analisi sospetti con VirusTotal: {json_path}")

    try:
        with open(json_path, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)

        suspicious = []
        for dll in data.get("dlls", []):
            reasons = is_suspicious(dll)
            if reasons:
                suspicious.append((dll, reasons))

        report_lines = []
        report_lines.append("Suspicious DLLs Analysis with VirusTotal")
        report_lines.append("=" * 100)
        report_lines.append(f"Analyzed file: {json_path}")
        report_lines.append(f"Analysis date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Total DLLs analyzed: {len(data.get('dlls', []))}")
        report_lines.append(f"Total suspicious entries: {len(suspicious)}")
        report_lines.append("")

        for i, (dll, reasons) in enumerate(suspicious):
            md5 = dll.get("MD5Hash")
            nome = dll.get("DllName")
            path = dll.get("DllPath")
            process = f"{dll.get('ProcessName')} ({dll.get('ProcessId')})"
            vt_result, vt_link = ("N/A", "")
            if md5 and len(md5) == 32:
                vt_result, vt_link = vt_check_md5(md5)
                time.sleep(1.2)  # rispetta rate limit
            report_lines.append(f"[{i+1}] {nome}")
            report_lines.append(f"Process: {process}")
            report_lines.append(f"Path: {path}")
            report_lines.append(f"Reasons: {', '.join(reasons)}")
            report_lines.append(f"MD5: {md5}")
            report_lines.append(f"VirusTotal result: {vt_result}")
            if vt_link:
                report_lines.append(f"Link: {vt_link}")
            report_lines.append("-" * 80)

        desktop_path = os.path.join(os.path.expanduser('~'), 'Desktop')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"VirusTotal_Sospetti_Report_{timestamp}.txt"
        output_path = os.path.join(desktop_path, output_filename)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report_lines))

        print(f"\nReport salvato in: {output_path}")

    except Exception as e:
        print(f"Error during processing: {str(e)}")
        raise

if __name__ == "__main__":
    main()
