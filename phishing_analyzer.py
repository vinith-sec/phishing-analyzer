"""
Phishing Email Analyzer
========================
Parses raw .eml files, extracts IOCs, checks authentication headers,
and generates structured triage reports for SOC investigation.

Author : Vinith Kumaragurubaran | github.com/vinith-sec
License: MIT
"""

import os
import re
import email
import email.policy
import argparse
import datetime
import json
import requests
import base64
import urllib.parse
from pathlib import Path
from email import message_from_file
from email.header import decode_header


VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_DELAY   = 15


# ── Header parsing ────────────────────────────────────────────────────────────
def decode_mime_header(value: str) -> str:
    if not value:
        return ""
    parts = decode_header(value)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(part)
    return " ".join(decoded)


def parse_email(path: str) -> dict:
    """Parse a .eml file and extract all relevant headers and body."""
    with open(path, "r", errors="replace") as f:
        msg = email.message_from_file(f, policy=email.policy.default)

    headers = {
        "from":         decode_mime_header(msg.get("From", "")),
        "reply_to":     decode_mime_header(msg.get("Reply-To", "")),
        "to":           decode_mime_header(msg.get("To", "")),
        "subject":      decode_mime_header(msg.get("Subject", "")),
        "date":         msg.get("Date", ""),
        "message_id":   msg.get("Message-ID", ""),
        "x_mailer":     msg.get("X-Mailer", ""),
        "x_originating_ip": msg.get("X-Originating-IP", ""),
        "received":     msg.get_all("Received", []),
        "authentication_results": msg.get("Authentication-Results", ""),
        "dkim_signature": "Present" if msg.get("DKIM-Signature") else "Absent",
    }

    # Extract body text
    body_text = ""
    body_html = ""
    attachments = []
    for part in msg.walk():
        content_type = part.get_content_type()
        disposition  = str(part.get("Content-Disposition", ""))
        if "attachment" in disposition:
            attachments.append({
                "filename":     part.get_filename() or "unnamed",
                "content_type": content_type,
                "size":         len(part.get_payload(decode=True) or b""),
            })
        elif content_type == "text/plain":
            payload = part.get_payload(decode=True)
            if payload:
                body_text += payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        elif content_type == "text/html":
            payload = part.get_payload(decode=True)
            if payload:
                body_html += payload.decode(part.get_content_charset() or "utf-8", errors="replace")

    return {
        "headers":     headers,
        "body_text":   body_text,
        "body_html":   body_html,
        "attachments": attachments,
    }


# ── Authentication checks ─────────────────────────────────────────────────────
def check_spf(auth_results: str) -> str:
    if not auth_results:
        return "Not checked"
    lower = auth_results.lower()
    if "spf=pass" in lower:
        return "PASS"
    if "spf=fail" in lower:
        return "FAIL"
    if "spf=softfail" in lower:
        return "SOFTFAIL"
    if "spf=neutral" in lower:
        return "NEUTRAL"
    return "Not found"


def check_dkim(auth_results: str, dkim_sig: str) -> str:
    if dkim_sig == "Absent":
        return "FAIL (no signature)"
    if not auth_results:
        return "Signature present, result not checked"
    lower = auth_results.lower()
    if "dkim=pass" in lower:
        return "PASS"
    if "dkim=fail" in lower:
        return "FAIL"
    return "Indeterminate"


def check_dmarc(auth_results: str) -> str:
    if not auth_results:
        return "Not checked"
    lower = auth_results.lower()
    if "dmarc=pass" in lower:
        return "PASS"
    if "dmarc=fail" in lower:
        return "FAIL"
    return "Not found"


def analyze_sender(from_addr: str, reply_to: str) -> dict:
    """Check for display name spoofing and reply-to mismatch."""
    findings = []
    from_domain   = re.search(r'@([\w.-]+)', from_addr)
    reply_domain  = re.search(r'@([\w.-]+)', reply_to) if reply_to else None

    if from_domain and reply_domain:
        if from_domain.group(1).lower() != reply_domain.group(1).lower():
            findings.append(
                f"Reply-To domain mismatch: FROM={from_domain.group(1)} vs REPLY-TO={reply_domain.group(1)}"
            )
    # Check for lookalike domains
    lookalike_patterns = ["0", "rn", "vv", "ii", "1l"]
    if from_domain:
        domain = from_domain.group(1).lower()
        for pat in lookalike_patterns:
            if pat in domain:
                findings.append(f"Potential lookalike domain character detected: '{pat}' in {domain}")
                break
    return {"suspicious_indicators": findings, "is_suspicious": len(findings) > 0}


# ── IOC extraction ────────────────────────────────────────────────────────────
URL_RE  = re.compile(r'https?://[^\s\'"<>\]]+')
IP_RE   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
HASH_RE = re.compile(r'\b[0-9a-fA-F]{32,64}\b')

def extract_iocs(text: str) -> dict:
    urls   = list(set(URL_RE.findall(text)))
    ips    = list(set(IP_RE.findall(text)))
    hashes = list(set(HASH_RE.findall(text)))
    return {"urls": urls, "ips": ips, "hashes": hashes}


def check_suspicious_attachment(filename: str) -> bool:
    """Flag high-risk attachment extensions."""
    high_risk = {
        ".exe", ".bat", ".cmd", ".vbs", ".js", ".jar", ".ps1",
        ".hta", ".scr", ".msi", ".docm", ".xlsm", ".zip", ".7z", ".rar",
    }
    return any(filename.lower().endswith(ext) for ext in high_risk)


# ── VirusTotal URL check ──────────────────────────────────────────────────────
def vt_check_url(url: str) -> dict:
    if not VT_API_KEY:
        return {"url": url, "error": "VT_API_KEY not set"}
    import time
    url_id   = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers  = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(endpoint, headers=headers, timeout=10)
        time.sleep(VT_DELAY)
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "url":        url,
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
            }
        return {"url": url, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"url": url, "error": str(e)}


# ── Risk scoring ──────────────────────────────────────────────────────────────
def calculate_risk_score(parsed: dict, spf: str, dkim: str, dmarc: str,
                          sender_analysis: dict, iocs: dict, vt_results: list) -> dict:
    score  = 0
    flags  = []

    if spf in ("FAIL", "SOFTFAIL"):
        score += 25; flags.append("SPF failure")
    if "FAIL" in dkim:
        score += 20; flags.append("DKIM failure")
    if dmarc == "FAIL":
        score += 15; flags.append("DMARC failure")
    if sender_analysis["is_suspicious"]:
        score += 20; flags.append("Suspicious sender")
    for att in parsed["attachments"]:
        if check_suspicious_attachment(att["filename"]):
            score += 25; flags.append(f"High-risk attachment: {att['filename']}")
    for vt in vt_results:
        if vt.get("malicious", 0) > 3:
            score += 30; flags.append(f"Malicious URL detected: {vt.get('url','')[:60]}")
        elif vt.get("suspicious", 0) > 3:
            score += 10
    if iocs["urls"]:
        score += min(10, len(iocs["urls"]) * 2)

    score = min(score, 100)
    verdict = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
    return {"score": score, "verdict": verdict, "flags": flags}


# ── Report generation ─────────────────────────────────────────────────────────
def generate_report(path: str, parsed: dict, spf: str, dkim: str, dmarc: str,
                    sender: dict, iocs: dict, vt_results: list, risk: dict) -> str:
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    h   = parsed["headers"]
    lines = [
        "=" * 70,
        "  PHISHING EMAIL ANALYZER — TRIAGE REPORT",
        f"  File      : {path}",
        f"  Generated : {now}",
        "=" * 70,
        "",
        f"  RISK VERDICT : [{risk['verdict']}] (Score: {risk['score']}/100)",
        "",
        "─── EMAIL HEADERS " + "─" * 52,
        f"  From       : {h['from']}",
        f"  Reply-To   : {h['reply_to'] or 'N/A'}",
        f"  To         : {h['to']}",
        f"  Subject    : {h['subject']}",
        f"  Date       : {h['date']}",
        f"  Message-ID : {h['message_id']}",
        f"  X-Originating-IP: {h['x_originating_ip'] or 'N/A'}",
        "",
        "─── AUTHENTICATION " + "─" * 52,
        f"  SPF  : {spf}",
        f"  DKIM : {dkim}",
        f"  DMARC: {dmarc}",
        "",
        "─── SENDER ANALYSIS " + "─" * 51,
    ]
    for ind in sender["suspicious_indicators"]:
        lines.append(f"  [!] {ind}")
    if not sender["suspicious_indicators"]:
        lines.append("  No suspicious sender indicators found")
    lines += [
        "",
        "─── ATTACHMENTS " + "─" * 55,
    ]
    if parsed["attachments"]:
        for att in parsed["attachments"]:
            flag = " ⚠ HIGH-RISK" if check_suspicious_attachment(att["filename"]) else ""
            lines.append(f"  {att['filename']} ({att['content_type']}, {att['size']} bytes){flag}")
    else:
        lines.append("  No attachments")

    lines += [
        "",
        "─── EXTRACTED IOCs " + "─" * 52,
        f"  URLs ({len(iocs['urls'])}):",
    ]
    for url in iocs["urls"][:10]:
        lines.append(f"    {url}")
    lines += [
        f"  IPs ({len(iocs['ips'])}):",
    ]
    for ip in iocs["ips"]:
        lines.append(f"    {ip}")

    lines += [
        "",
        "─── VIRUSTOTAL URL RESULTS " + "─" * 44,
    ]
    for vt in vt_results:
        if "error" in vt:
            lines.append(f"  {vt.get('url','')[:60]} — {vt['error']}")
        else:
            lines.append(
                f"  {vt.get('url','')[:60]}\n"
                f"    Malicious: {vt['malicious']}  Suspicious: {vt['suspicious']}  Harmless: {vt['harmless']}"
            )

    lines += [
        "",
        "─── RISK FLAGS " + "─" * 56,
    ]
    for flag in risk["flags"]:
        lines.append(f"  [!] {flag}")
    if not risk["flags"]:
        lines.append("  No risk flags identified")

    lines += [
        "",
        "─── RECOMMENDATION " + "─" * 52,
        f"  Verdict: {risk['verdict']} — Risk Score {risk['score']}/100",
        "",
    ]
    if risk["score"] >= 80:
        lines += [
            "  ACTION: Block sender, quarantine email, alert user, initiate incident.",
            "  Escalate to Tier 2 for full forensic investigation.",
        ]
    elif risk["score"] >= 60:
        lines += [
            "  ACTION: Move to junk, notify user, monitor for credential submission.",
            "  Check proxy logs for URL access.",
        ]
    elif risk["score"] >= 30:
        lines += [
            "  ACTION: Flag for user awareness. Monitor endpoint for suspicious activity.",
        ]
    else:
        lines.append("  ACTION: Likely legitimate. Continue monitoring.")

    lines += ["", "=" * 70, "  Generated by Phishing Email Analyzer — github.com/vinith-sec", ""]
    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Phishing Email Analyzer — triage .eml files for SOC investigation"
    )
    parser.add_argument("eml_file", help="Path to .eml email file")
    parser.add_argument("--no-vt",  action="store_true", help="Skip VirusTotal URL checks")
    parser.add_argument("--output", help="Save report to file (default: print to terminal)")
    parser.add_argument("--json",   action="store_true", help="Also output raw data as JSON")
    args = parser.parse_args()

    print(f"\n[Phishing Email Analyzer] Parsing: {args.eml_file}\n")
    parsed = parse_email(args.eml_file)
    h      = parsed["headers"]

    spf    = check_spf(h["authentication_results"])
    dkim   = check_dkim(h["authentication_results"], h["dkim_signature"])
    dmarc  = check_dmarc(h["authentication_results"])
    sender = analyze_sender(h["from"], h["reply_to"])

    all_text = parsed["body_text"] + parsed["body_html"]
    iocs = extract_iocs(all_text)

    vt_results = []
    if not args.no_vt and VT_API_KEY:
        print(f"[*] Checking {len(iocs['urls'][:5])} URLs against VirusTotal...")
        for url in iocs["urls"][:5]:
            vt_results.append(vt_check_url(url))

    risk   = calculate_risk_score(parsed, spf, dkim, dmarc, sender, iocs, vt_results)
    report = generate_report(args.eml_file, parsed, spf, dkim, dmarc, sender, iocs, vt_results, risk)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"[✓] Report saved → {args.output}")
    else:
        print(report)

    if args.json:
        data = {
            "file":    args.eml_file,
            "headers": h,
            "spf": spf, "dkim": dkim, "dmarc": dmarc,
            "sender_analysis": sender,
            "iocs":    iocs,
            "vt":      vt_results,
            "risk":    risk,
        }
        json_path = Path(args.eml_file).stem + "_triage.json"
        with open(json_path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[✓] JSON data saved → {json_path}")


if __name__ == "__main__":
    main()
