from flask import Flask, render_template, request, jsonify
import os
import re
from datetime import datetime, timedelta
import random
from collections import defaultdict
import math

# ──────────────────────────────────────────────
# Set ENABLE_AI = True AND provide ANTHROPIC_API_KEY env var (or put it here)
# to unlock AI-powered log reports. Runs fine without it.
ENABLE_AI = True # os.environ.get("ENABLE_AI", "false").lower() == "true"
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

# Auto-enable if API key is found
if GEMINI_API_KEY and GEMINI_API_KEY.startswith("AIzaS"):
    ENABLE_AI = True

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
LOG_DIR = "logs"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# ──────────────────────────────────────────────
THREAT_PATTERNS = [
    # Critical (8-10)
    {
        "pattern": r"sql\s*injection|union\s+select|drop\s+table|1=1|or\s+'1'='1|exec\s*\(|xp_cmdshell",
        "severity": 10, "category": "sql_injection", "label": "SQL Injection Attempt",
        "weight": 10
    },
    {
        "pattern": r"<script[\s>]|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie",
        "severity": 9, "category": "xss", "label": "Cross-Site Scripting (XSS)",
        "weight": 9
    },
    {
        "pattern": r"(\.\.\/){2,}|\.\.\\|%2e%2e%2f|%252e%252e|path\s+traversal",
        "severity": 9, "category": "path_traversal", "label": "Path Traversal Attack",
        "weight": 8
    },
    {
        "pattern": r"critical|exploit|backdoor|rootkit|malware|ransomware|command.injection",
        "severity": 10, "category": "critical_system", "label": "Critical System Event",
        "weight": 10
    },
    # High (6-7)
    {
        "pattern": r"failed\s+password|authentication\s+fail|login\s+fail|invalid\s+(user|credentials)|wrong\s+password",
        "severity": 6, "category": "auth_failure", "label": "Authentication Failure",
        "weight": 4
    },
    {
        "pattern": r"unauthorized|403\s|access\s+denied|permission\s+denied|forbidden",
        "severity": 7, "category": "unauthorized_access", "label": "Unauthorized Access",
        "weight": 6
    },
    {
        "pattern": r"sudo|su\s+root|privilege\s+escalat|setuid|sudo:\s+\S+\s*:.*command",
        "severity": 7, "category": "privilege_escalation", "label": "Privilege Escalation",
        "weight": 7
    },
    {
        "pattern": r"port\s+scan|nmap|masscan|syn\s+flood|udp\s+flood|ping\s+sweep",
        "severity": 8, "category": "scanning", "label": "Port Scan / Reconnaissance",
        "weight": 7
    },
    # Medium (3-5)
    {
        "pattern": r"invalid\s+user|unknown\s+user|user\s+not\s+found",
        "severity": 5, "category": "invalid_user", "label": "Invalid User Attempt",
        "weight": 3
    },
    {
        "pattern": r"404|file\s+not\s+found|no\s+such\s+file",
        "severity": 3, "category": "not_found", "label": "Resource Not Found (404)",
        "weight": 1
    },
    {
        "pattern": r"500|internal\s+server\s+error|traceback|exception|stack\s+trace",
        "severity": 5, "category": "server_error", "label": "Server Error (500)",
        "weight": 3
    },
    {
        "pattern": r"brute.?force|too\s+many\s+(attempts|requests|failures)|rate\s+limit",
        "severity": 8, "category": "brute_force", "label": "Brute Force Detected",
        "weight": 8
    },
    # Low (1-2)
    {
        "pattern": r"logout|session\s+(expired|timeout|end)",
        "severity": 1, "category": "session", "label": "Session Event",
        "weight": 0
    },
    {
        "pattern": r"warning|deprecated|configuration\s+error",
        "severity": 2, "category": "warning", "label": "System Warning",
        "weight": 1
    },
]

# Known suspicious IP ranges / bad actors (demo list)
KNOWN_BAD_IP_PREFIXES = [
    "185.220.", "45.33.", "103.21.", "198.199.", "167.99.",
    "192.241.", "46.101.", "178.62.", "139.59."
]

SEVERITY_MAP = {
    range(1, 4):  ("LOW",      "low",      "text-green-400",  "severity-low"),
    range(4, 7):  ("MEDIUM",   "medium",   "text-yellow-400", "severity-medium"),
    range(7, 11): ("HIGH",     "high",     "text-red-400",    "severity-high"),
}

def classify_severity(score):
    for r, meta in SEVERITY_MAP.items():
        if score in r:
            return {"label": meta[0], "key": meta[1], "color": meta[2], "badge": meta[3]}
    return {"label": "LOW", "key": "low", "color": "text-green-400", "badge": "severity-low"}


# ──────────────────────────────────────────────
# Core Analyzer
# ──────────────────────────────────────────────
def analyze_logs(filepath):
    suspicious_events = []
    total_events = 0
    ip_activity = defaultdict(list)   # ip -> list of (line_no, severity)
    category_counts = defaultdict(int)
    ip_fail_counts = defaultdict(int)
    timeline_buckets = defaultdict(int)  # minute -> count
    raw_weights = []

    with open(filepath, "r", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            total_events += 1
            line_lower = line.lower()
            timestamp = extract_timestamp(line)

            # Extract IP from line
            ip = extract_ip(line)

            # Check bad-IP reputation bonus
            ip_reputation_bonus = 0
            if ip and any(ip.startswith(prefix) for prefix in KNOWN_BAD_IP_PREFIXES):
                ip_reputation_bonus = 3

            matched = False
            for p in THREAT_PATTERNS:
                if re.search(p["pattern"], line_lower):
                    sev_score = min(10, p["severity"] + ip_reputation_bonus)
                    sev = classify_severity(sev_score)
                    event = {
                        "line_no": line_no,
                        "timestamp": timestamp,
                        "reason": p["label"],
                        "category": p["category"],
                        "severity_score": sev_score,
                        "severity": sev["label"],
                        "severity_key": sev["key"],
                        "severity_color": sev["color"],
                        "severity_badge": sev["badge"],
                        "log": line.strip(),
                        "ip": ip or "N/A",
                    }
                    suspicious_events.append(event)
                    category_counts[p["category"]] += 1
                    raw_weights.append(p["weight"] + ip_reputation_bonus)
                    if ip:
                        ip_activity[ip].append(line_no)
                        if p["category"] == "auth_failure":
                            ip_fail_counts[ip] += 1

                    # Timeline bucketing
                    if timestamp != "Unknown":
                        try:
                            dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                            bucket = dt.strftime("%H:%M")
                            timeline_buckets[bucket] += 1
                        except:
                            pass
                    matched = True
                    break

    # ── Brute-force burst detection (post-pass) ──────────
    # If any IP has 5+ auth failures, inject a synthetic brute-force event
    for ip, count in ip_fail_counts.items():
        if count >= 5:
            category_counts["brute_force"] += 1
            raw_weights.append(10)
            suspicious_events.append({
                "line_no": 0,
                "timestamp": "Computed",
                "reason": f"Brute Force: {count} auth failures from same IP",
                "category": "brute_force",
                "severity_score": 10,
                "severity": "HIGH",
                "severity_key": "high",
                "severity_color": "text-red-400",
                "severity_badge": "severity-high",
                "log": f"[DETECTED] {count} repeated authentication failures from {ip}",
                "ip": ip,
            })

    # ── Threat Score Algorithm ────────────────────────────
    # Weighted formula:
    #   base = Σ(weight_i) / total_events  (normalised density)
    #   variety_bonus = unique categories * 3
    #   burst_bonus = if any IP > 10 events
    #   score = clamp(base * 60 + variety_bonus + burst_bonus, 0, 100)

    if total_events == 0:
        threat_score = 0
    else:
        weight_sum = sum(raw_weights)
        density = weight_sum / total_events  # 0..∞
        density_score = min(60, density * 60)

        unique_categories = len(category_counts)
        variety_bonus = min(20, unique_categories * 3)

        # Burst bonus: any IP with lots of events
        max_ip_hits = max((len(v) for v in ip_activity.values()), default=0)
        burst_bonus = min(20, max_ip_hits * 0.5)

        threat_score = int(density_score + variety_bonus + burst_bonus)
        threat_score = max(0, min(100, threat_score))

    # ── Severity distribution ─────────────────────────────
    sev_low    = sum(1 for e in suspicious_events if e["severity_key"] == "low")
    sev_medium = sum(1 for e in suspicious_events if e["severity_key"] == "medium")
    sev_high   = sum(1 for e in suspicious_events if e["severity_key"] == "high")

    # ── Top offending IPs ─────────────────────────────────
    top_ips = sorted(ip_activity.items(), key=lambda x: len(x[1]), reverse=True)[:5]
    top_ips = [{"ip": ip, "hits": len(lines)} for ip, lines in top_ips]

    # ── Timeline data for chart ───────────────────────────
    sorted_timeline = sorted(timeline_buckets.items())
    timeline_labels = [t[0] for t in sorted_timeline]
    timeline_values = [t[1] for t in sorted_timeline]

    # ── Category breakdown ────────────────────────────────
    cat_labels = list(category_counts.keys())
    cat_values = [category_counts[k] for k in cat_labels]

    return {
        "total": total_events,
        "suspicious": len(suspicious_events),
        "threat_score": threat_score,
        "severity": {"low": sev_low, "medium": sev_medium, "high": sev_high},
        "details": suspicious_events[:100],
        "top_ips": top_ips,
        "category_counts": dict(category_counts),
        "timeline_labels": timeline_labels,
        "timeline_values": timeline_values,
        "cat_labels": cat_labels,
        "cat_values": cat_values,
        "ai_enabled": ENABLE_AI,
    }


def extract_ip(line):
    match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
    return match.group(1) if match else None


def extract_timestamp(log_line):
    # ISO-like: 2024-01-15 14:23:01
    m = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", log_line)
    if m:
        return m.group(0)
    # Apache/nginx: 15/Jan/2024:14:23:01
    m = re.search(r"\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}", log_line)
    if m:
        return m.group(0)
    return "Unknown"


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/analyze")
def analyze():
    return render_template("upload.html")


@app.route("/results", methods=["POST"])
def results():
    file = request.files["logfile"]
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(filepath)
    analysis = analyze_logs(filepath)
    return render_template("results.html", filename=file.filename, **analysis)


@app.route("/upload", methods=["POST"])
def upload_logs():
    if "logfile" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["logfile"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(filepath)
    result = analyze_logs(filepath)
    return jsonify({
        "filename": file.filename,
        "total_events": result["total"],
        "suspicious_events": result["suspicious"],
        "threat_score": result["threat_score"],
        "severity": result["severity"],
        "details": result["details"],
        "top_ips": result["top_ips"],
    })


# ──────────────────────────────────────────────
# AI Report Endpoint (optional)
# ──────────────────────────────────────────────

### for Gemini
@app.route("/ai-report", methods=["POST"])
def ai_report():
    if not ENABLE_AI:
        return jsonify({
            "enabled": False,
            "message": "AI analysis is disabled. Set ENABLE_AI=true and GEMINI_API_KEY env var."
        })

    try:
        import google.generativeai as genai
    except ImportError:
        return jsonify({
            "enabled": False,
            "message": "google-generativeai not installed. Run: pip install google-generativeai"
        }), 500

    try:
        genai.configure(api_key=GEMINI_API_KEY)
    except Exception as e:
        return jsonify({
            "enabled": False,
            "message": f"Failed to configure Gemini: {str(e)}"
        }), 500

    data = request.json
    summary = data.get("summary", {})
    sample_logs = data.get("sample_logs", [])

    log_snippet = "\n".join([e.get("log", "") for e in sample_logs[:30]])

    prompt = f"""You are a senior cybersecurity analyst. Analyze the following log file summary and suspicious event samples.

## Log File Summary
- Total Events: {summary.get("total", "?")}
- Suspicious Events: {summary.get("suspicious", "?")}
- Threat Score: {summary.get("threat_score", "?")} / 100
- Severity Breakdown: Low={summary.get("severity", {}).get("low", 0)}, Medium={summary.get("severity", {}).get("medium", 0)}, High={summary.get("severity", {}).get("high", 0)}
- Top Attacking IPs: {summary.get("top_ips", [])}
- Attack Categories: {summary.get("category_counts", {})}

## Sample Suspicious Log Entries (up to 30)
{log_snippet}

## Your Task
Produce a structured threat intelligence report with these sections:
1. **Executive Summary** (2-3 sentences)
2. **Attack Pattern Analysis**
3. **High-Risk Events**
4. **Attacker Profile**
5. **Recommendations** (5 concrete steps)
6. **Risk Rating** (CRITICAL / HIGH / MEDIUM / LOW with justification)

Be concise, technical, and actionable. Format with Markdown.
"""

    try:
        model = genai.GenerativeModel("gemini-2.5-flash")

        response = model.generate_content(prompt)

        report_text = response.text if hasattr(response, "text") else str(response)

        return jsonify({
            "enabled": True,
            "report": report_text
        })

    except Exception as e:
        return jsonify({
            "enabled": False,
            "message": f"AI error: {str(e)}"
        }), 500


NORMAL_IPS = ["192.168.1.10", "10.0.0.5", "172.16.0.12", "10.10.1.5"]
ATTACKER_IPS = ["45.33.32.156", "185.220.101.45", "103.21.244.0", "198.199.88.1"]
USERS = ["root", "admin", "john", "alice", "guest", "administrator", "ubuntu"]
URLS = ["/", "/login", "/admin", "/dashboard", "/api/data", "/wp-admin", "/.env"]
METHODS = ["GET", "POST", "PUT"]

NORMAL_LOGS = [
    "INFO {time} User '{user}' logged in successfully from {ip}",
    "INFO {time} {method} {url} 200 from {ip}",
    "INFO {time} Session created for {user} from {ip}",
    "INFO {time} Resource accessed {url} by {user} from {ip}",
]

ATTACK_LOGS = [
    "WARNING {time} Failed password for invalid user {user} from {ip} port 22 ssh2",
    "ERROR {time} Authentication failure for {user} from {ip}",
    "ALERT {time} Unauthorized access attempt to /admin from {ip}",
    "CRITICAL {time} Possible SQL injection attempt detected: union select from {ip}",
    "WARNING {time} Directory traversal attempt ../../etc/passwd from {ip}",
    "ERROR {time} 403 Forbidden {url} from {ip} - {user}",
    "CRITICAL {time} XSS attempt detected: <script>alert(1)</script> from {ip}",
    "WARNING {time} Port scan detected from {ip} on multiple ports",
    "ERROR {time} sudo: {user}: command not allowed ; TTY=pts/0 ; from {ip}",
    "ALERT {time} Rate limit exceeded - too many requests from {ip}",
]


def generate_demo_logs(filename, total_lines, attack_ratio):
    filepath = os.path.join(LOG_DIR, filename)
    start_time = datetime.now() - timedelta(hours=1)
    with open(filepath, "w") as f:
        for i in range(total_lines):
            current_time = start_time + timedelta(seconds=i * 3)
            time_str = current_time.strftime("%Y-%m-%d %H:%M:%S")
            if random.random() < attack_ratio:
                template = random.choice(ATTACK_LOGS)
                ip = random.choice(ATTACKER_IPS)
            else:
                template = random.choice(NORMAL_LOGS)
                ip = random.choice(NORMAL_IPS)
            log = template.format(
                time=time_str, user=random.choice(USERS),
                ip=ip, method=random.choice(METHODS), url=random.choice(URLS)
            )
            f.write(log + "\n")
    return filepath


@app.route("/generator")
def generator():
    return render_template("generator.html")


@app.route("/generate-logs", methods=["POST"])
def generate_logs():
    data = request.json
    filename = data.get("filename", "demo.log")
    total = int(data.get("lines", 200))
    attack = float(data.get("attack_ratio", 0.2))
    filepath = generate_demo_logs(filename, total, attack)
    return jsonify({"message": "Log file generated successfully", "filename": filename, "path": filepath})


if __name__ == "__main__":
    print(f"[ThreatLens] AI Mode: {'ENABLED' if ENABLE_AI else 'DISABLED'}")
    app.run(debug=True)
