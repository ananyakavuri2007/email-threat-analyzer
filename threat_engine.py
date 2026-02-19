import os
import math
from urllib.parse import urlparse

# =====================================================
# MODULE 3 — THREAT INTELLIGENCE ENGINE
# =====================================================

# -----------------------------------------------------
# 1️⃣ Dangerous File Extensions
# -----------------------------------------------------
DANGEROUS_EXTENSIONS = [
    "exe", "bat", "cmd", "js", "vbs",
    "scr", "ps1", "jar", "apk", "msi"
]


def check_dangerous_attachments(attachments):
    risk = 0
    reasons = []

    for file in attachments:
        ext = file.get("extension", "").lower()

        if ext in DANGEROUS_EXTENSIONS:
            risk += 40
            reasons.append(f"Dangerous attachment extension detected: .{ext}")

    return risk, reasons


# -----------------------------------------------------
# 2️⃣ Suspicious Shortened URL Detection
# -----------------------------------------------------
SUSPICIOUS_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "rb.gy",
    "t.co",
    "goo.gl"
]


def check_suspicious_urls(urls):
    risk = 0
    reasons = []

    for url in urls:
        try:
            domain = urlparse(url).netloc.lower()

            for suspicious in SUSPICIOUS_DOMAINS:
                if suspicious in domain:
                    risk += 30
                    reasons.append(f"Suspicious shortened URL detected: {domain}")
                    break

        except Exception:
            continue

    return risk, reasons


# -----------------------------------------------------
# 3️⃣ Domain Mismatch Detection (Spoofing Check)
# -----------------------------------------------------
def check_domain_mismatch(sender, urls):
    risk = 0
    reasons = []

    if not sender:
        return risk, reasons

    try:
        sender_email = sender[0][1]
        sender_domain = sender_email.split("@")[-1].lower()
    except Exception:
        return risk, reasons

    for url in urls:
        try:
            url_domain = urlparse(url).netloc.lower()

            if sender_domain not in url_domain:
                risk += 25
                reasons.append(
                    f"Domain mismatch: sender({sender_domain}) vs url({url_domain})"
                )

        except Exception:
            continue

    return risk, reasons


# -----------------------------------------------------
# 4️⃣ Entropy Calculation (Malware Indicator)
# -----------------------------------------------------
def calculate_entropy(filepath):
    try:
        with open(filepath, "rb") as f:
            data = f.read()

        if not data:
            return 0

        entropy = 0

        for byte_value in range(256):
            p_x = float(data.count(bytes([byte_value]))) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)

        return entropy

    except Exception:
        return 0


def check_attachment_entropy(attachments, attachments_folder):
    risk = 0
    reasons = []

    for file in attachments:
        filename = file.get("filename")
        if not filename:
            continue

        filepath = os.path.join(attachments_folder, filename)

        if os.path.exists(filepath):
            entropy = calculate_entropy(filepath)

            # High entropy threshold (common in packed/encrypted malware)
            if entropy > 7.5:
                risk += 35
                reasons.append(
                    f"High entropy attachment detected ({filename}) → {entropy:.2f}"
                )

    return risk, reasons


# -----------------------------------------------------
# 5️⃣ Final Threat Scoring System
# -----------------------------------------------------
def analyze_threat(email_data, attachments_folder):
    total_risk = 0
    all_reasons = []

    # Run all detection checks
    r1, reason1 = check_dangerous_attachments(email_data.get("attachments", []))
    r2, reason2 = check_suspicious_urls(email_data.get("urls", []))
    r3, reason3 = check_domain_mismatch(
        email_data.get("sender", []),
        email_data.get("urls", [])
    )
    r4, reason4 = check_attachment_entropy(
        email_data.get("attachments", []),
        attachments_folder
    )

    # Sum up risk scores
    total_risk = r1 + r2 + r3 + r4
    all_reasons = reason1 + reason2 + reason3 + reason4

    # Determine threat level
    if total_risk >= 70:
        threat_level = "HIGH"
    elif total_risk >= 40:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    return total_risk, threat_level, all_reasons
