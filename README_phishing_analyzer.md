# 📧 Phishing Email Analyzer

> **Parse .eml files. Extract IOCs. Check authentication. Generate structured SOC triage reports.**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org)
[![VirusTotal](https://img.shields.io/badge/API-VirusTotal-394EFF)](https://virustotal.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## What it does

Automates the L1 phishing triage workflow: parse the email, check SPF/DKIM/DMARC, extract URLs and IPs, scan with VirusTotal, score the risk, and generate a report ready to paste into your ticketing system.

---

## Features

- **Full header parsing** — From, Reply-To, Received chain, X-Originating-IP, Message-ID
- **Authentication checks** — SPF, DKIM, DMARC pass/fail with detailed output
- **Sender spoofing detection** — display name vs. domain mismatch, lookalike domain patterns
- **IOC extraction** — URLs, IPs, file hashes from email body (plain text and HTML)
- **Attachment risk flagging** — .exe, .ps1, .docm, .zip, and 12 other high-risk extensions
- **VirusTotal URL scanning** — checks up to 5 URLs per email (free-tier compatible)
- **Risk scoring** — 0–100 score with CRITICAL / HIGH / MEDIUM / LOW verdict
- **JSON export** — machine-readable triage data for SOAR integration

---

## Quickstart

```bash
git clone https://github.com/vinith-sec/phishing-analyzer.git
cd phishing-analyzer
pip install -r requirements.txt

# Analyze an email (demo mode — no API key needed)
python phishing_analyzer.py sample_phishing.eml

# With VirusTotal URL scanning
export VT_API_KEY="your_virustotal_free_api_key"
python phishing_analyzer.py sample_phishing.eml

# Save report + JSON
python phishing_analyzer.py sample_phishing.eml --output report.txt --json
```

---

## Example output

```
======================================================================
  PHISHING EMAIL ANALYZER — TRIAGE REPORT
  File      : sample_phishing.eml
  Generated : 2025-04-01 14:33 UTC
======================================================================

  RISK VERDICT : [CRITICAL] (Score: 85/100)

─── AUTHENTICATION ──────────────────────────────────────────────────
  SPF  : FAIL
  DKIM : FAIL (no signature)
  DMARC: FAIL

─── SENDER ANALYSIS ─────────────────────────────────────────────────
  [!] Reply-To domain mismatch: FROM=paypa1.com vs REPLY-TO=attacker.ru
  [!] Potential lookalike domain: '1' in paypa1.com

─── RISK FLAGS ──────────────────────────────────────────────────────
  [!] SPF failure
  [!] DKIM failure
  [!] DMARC failure
  [!] Suspicious sender
  [!] Malicious URL detected: http://paypa1.com/verify-account
```

---

## Risk scoring

| Points | Trigger |
|---|---|
| +25 | SPF fail/softfail |
| +20 | DKIM fail |
| +15 | DMARC fail |
| +20 | Suspicious sender indicators |
| +25 | High-risk attachment (.exe, .ps1, etc.) |
| +30 | VirusTotal: malicious URL (>3 engines) |

---

## Project structure

```
phishing-analyzer/
├── phishing_analyzer.py   # Main engine
├── sample_phishing.eml    # Demo email for testing
├── requirements.txt
└── README.md
```

---

## Author

**Vinith Kumaragurubaran** — SOC Analyst | CompTIA Security+ | Cisco CCNA  
[linkedin.com/in/vinith-kumaragurubaran](https://linkedin.com/in/vinith-kumaragurubaran) · [github.com/vinith-sec](https://github.com/vinith-sec)
