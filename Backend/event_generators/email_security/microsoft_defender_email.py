#!/usr/bin/env python3
"""
Microsoft Defender for Email logs generator (JSON format)
"""
from __future__ import annotations
import json
import random
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List

# Threat types and verdicts
THREAT_TYPES = ["Phish", "Malware", "Spam", "Bulk", "None"]
DETECTION_METHODS = ["ATP Safe Attachments", "ATP Safe Links", "Anti-phishing", "Anti-malware", "Anti-spam", "User reported"]

# Email actions
EMAIL_ACTIONS = ["Allow", "Block", "Quarantine", "Replace", "Redirect", "Delete", "MoveToJmf"]
DELIVERY_ACTIONS = ["Delivered", "Blocked", "Replaced", "Quarantined"]

# Malware families
MALWARE_FAMILIES = ["Emotet", "TrickBot", "Dridex", "IcedID", "Qakbot", "BazarLoader", "Agent Tesla", "FormBook"]

# Phishing techniques
PHISHING_TECHNIQUES = [
    "Brand impersonation", "CEO fraud", "Credential harvesting", "Display name spoofing",
    "Domain impersonation", "Mailbox intelligence", "Mixed analysis", "Spoof intelligence"
]

# File types and names
FILE_TYPES = [".pdf", ".docx", ".xlsx", ".zip", ".exe", ".js", ".html", ".txt", ".jpg"]
MALICIOUS_FILE_TYPES = [".exe", ".scr", ".bat", ".js", ".vbs", ".wsf", ".jar"]

# Email subjects
PHISHING_SUBJECTS = [
    "Urgent: Account verification required",
    "Security alert from IT department", 
    "Your account will be suspended",
    "Invoice payment overdue",
    "DocuSign document ready",
    "CEO: Quick question"
]

MALWARE_SUBJECTS = [
    "Invoice attached",
    "Delivery notification",
    "Scan from printer",
    "Voice message",
    "Payment receipt"
]

# Users and domains
USERS = ["john.doe", "jane.smith", "bob.jones", "alice.williams", "admin", "support"]
INTERNAL_DOMAINS = ["company.com", "corp.com", "enterprise.local"]
EXTERNAL_DOMAINS = ["gmail.com", "outlook.com", "suspicious-domain.com", "phishing-site.net"]

def _generate_ip(internal=False):
    """Generate IP address"""
    if internal:
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def _generate_email_address(internal=True, suspicious=False):
    """Generate email address"""
    user = random.choice(USERS)
    if suspicious:
        domain = random.choice([d for d in EXTERNAL_DOMAINS if "suspicious" in d or "phishing" in d])
    elif internal:
        domain = random.choice(INTERNAL_DOMAINS)
    else:
        domain = random.choice(EXTERNAL_DOMAINS)
    return f"{user}@{domain}"

def microsoft_defender_email_log(overrides: dict | None = None) -> Dict:
    """
    Return a single Microsoft Defender for Email event as JSON string.
    
    Pass `overrides` to force any field to a specific value:
        microsoft_defender_email_log({"ThreatTypes": "Phish"})
    """
    now = datetime.now(timezone.utc)
    timestamp = now - timedelta(seconds=random.randint(0, 300))
    
    # Determine threat type and associated details
    threat_type = random.choice(THREAT_TYPES)
    is_malicious = threat_type != "None"
    
    # Generate email addresses
    sender_email = _generate_email_address(internal=False, suspicious=is_malicious)
    recipient_email = _generate_email_address(internal=True)
    
    # Generate subject based on threat type
    if threat_type == "Phish":
        subject = random.choice(PHISHING_SUBJECTS)
    elif threat_type == "Malware":
        subject = random.choice(MALWARE_SUBJECTS)
    else:
        subject = f"Regular email - {random.choice(['Meeting', 'Report', 'Update', 'Newsletter'])}"
    
    # Base record structure
    record = {
        "time": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "resourceId": f"/subscriptions/{uuid.uuid4()}/resourcegroups/rg-security/providers/microsoft.operationalinsights/workspaces/security-workspace",
        "operationName": "EmailEvents",
        "operationVersion": "1.0",
        "category": "EmailEvents",
        "tenantId": str(uuid.uuid4()),
        "resultType": "Success",
        "resultSignature": "EmailProcessed",
        "callerIpAddress": _generate_ip(internal=False),
        "correlationId": str(uuid.uuid4()),
        "identity": "System",
        "Level": 4,
        "location": "Global",
        "Tenant": "company.onmicrosoft.com",
        "properties": {
            "ReportId": str(uuid.uuid4()),
            "NetworkMessageId": f"<{uuid.uuid4()}@{sender_email.split('@')[1]}>",
            "InternetMessageId": f"<{uuid.uuid4()}@mail.protection.outlook.com>",
            "Timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "EmailClusterId": str(uuid.uuid4()),
            "SenderIPv4": _generate_ip(internal=False),
            "SenderIPv6": None,
            "SenderMailFromAddress": sender_email,
            "SenderFromAddress": sender_email,
            "SenderDisplayName": sender_email.split('@')[0].replace('.', ' ').title(),
            "SenderObjectId": str(uuid.uuid4()) if random.random() > 0.5 else None,
            "SenderMailFromDomain": sender_email.split('@')[1],
            "SenderFromDomain": sender_email.split('@')[1],
            "Subject": subject,
            "EmailDirection": random.choice(["Inbound", "Outbound", "Intra-org"]),
            "DeliveryAction": random.choice(DELIVERY_ACTIONS),
            "DeliveryLocation": random.choice(["Inbox", "JunkEmailFolder", "DeletedItems", "Quarantine", "External", "Failed", "Dropped", "Forwarded"]),
            "RecipientEmailAddress": recipient_email,
            "RecipientObjectId": str(uuid.uuid4()),
            "AuthenticationDetails": json.dumps({
                "SPF": random.choice(["Pass", "Fail", "SoftFail", "Neutral", "None"]),
                "DKIM": random.choice(["Pass", "Fail", "None"]),
                "DMARC": random.choice(["Pass", "Fail", "None"]),
                "CompAuth": random.choice(["Pass", "Fail", "SoftPass", "None"])
            }),
            "ConnectorIndex": random.randint(0, 10),
            "EmailActionPolicy": random.choice(["Standard preset security policy", "Strict preset security policy", "Custom policy"]),
            "EmailActionPolicyGuid": str(uuid.uuid4()),
            "EmailLanguage": random.choice(["en", "es", "fr", "de", "zh", "ja"]),
            "ThreatTypes": threat_type,
            "DetectionMethods": random.choice(DETECTION_METHODS) if is_malicious else None,
            "ActionType": random.choice(EMAIL_ACTIONS) if is_malicious else "Allow",
            "ActionTrigger": random.choice(["User", "Admin", "Automated"]) if is_malicious else None,
            "ActionResult": "Success",
            "PolicyAction": random.choice(["Allow", "Block", "Quarantine"]),
            "UserLevelAction": random.choice(["Allow", "Block", "MoveToJmf"]) if random.random() > 0.7 else None,
            "UserLevelPolicy": random.choice(["Standard", "Strict", "Custom"]) if random.random() > 0.7 else None,
            "BulkComplaintLevel": str(random.randint(0, 9)) if threat_type == "Bulk" else None,
            "ConfidenceLevel": random.choice(["Low", "Normal", "High"]),
            "EmailSize": random.randint(1024, 5000000),  # 1KB to 5MB
            "AttachmentCount": random.randint(0, 5),
            "UrlCount": random.randint(0, 10),
            "SizeInBytes": random.randint(1024, 5000000),
            "Directionality": random.choice(["Inbound", "Outbound", "Intra-org"]),
            "ThreatsAndDetectionTech": threat_type if is_malicious else None,
            "AdditionalFields": json.dumps({
                "CustomDomain": random.choice([True, False]),
                "IsReadReceiptRequested": random.choice([True, False]),
                "HasAttachments": random.choice([True, False]),
                "MessageTraceId": str(uuid.uuid4())
            })
        }
    }
    
    # Add threat-specific details
    if threat_type == "Malware":
        record["properties"]["MalwareFamily"] = random.choice(MALWARE_FAMILIES)
        record["properties"]["MalwareFilterVerdict"] = "Malware"
        record["properties"]["FileName"] = f"document_{random.randint(1000, 9999)}{random.choice(MALICIOUS_FILE_TYPES)}"
        record["properties"]["FileType"] = random.choice(MALICIOUS_FILE_TYPES)[1:]
        record["properties"]["SHA256"] = uuid.uuid4().hex + uuid.uuid4().hex
        record["properties"]["ThreatNames"] = [random.choice(MALWARE_FAMILIES)]
        
    elif threat_type == "Phish":
        record["properties"]["PhishFilterVerdict"] = "Phish"
        record["properties"]["PhishConfidenceLevel"] = random.choice(["Low", "Normal", "High"])
        record["properties"]["PhishDetectionMethod"] = random.choice(PHISHING_TECHNIQUES)
        record["properties"]["UrlsInfo"] = json.dumps([{
            "Url": f"https://phishing-site-{random.randint(1, 100)}.com/login",
            "UrlVerdict": "Malicious",
            "UrlDomain": f"phishing-site-{random.randint(1, 100)}.com"
        }])
        
    elif threat_type == "Spam":
        record["properties"]["SpamFilterVerdict"] = "Spam"
        record["properties"]["SpamConfidenceLevel"] = random.choice(["Low", "Normal", "High"])
        record["properties"]["BulkComplaintLevel"] = str(random.randint(5, 9))
        
    # Add organizational details
    record["properties"]["OrgLevelAction"] = random.choice(["Allow", "Block", "Quarantine"])
    record["properties"]["OrgLevelPolicy"] = random.choice(["Default", "AntiPhishing", "AntiMalware", "AntiSpam"])
    record["properties"]["SystemOverrides"] = json.dumps([]) if random.random() > 0.8 else None
    record["properties"]["UserOverrides"] = json.dumps([]) if random.random() > 0.9 else None
    
    # Add latest delivery details
    record["properties"]["LatestDeliveryAction"] = record["properties"]["DeliveryAction"]
    record["properties"]["LatestDeliveryLocation"] = record["properties"]["DeliveryLocation"]
    
    # Wrap in EventHub format
    event = {
        "records": [record]
    }
    
    # Apply any overrides
    if overrides:
        record["properties"].update(overrides)
    
    return event

# ---------------------------------------------------------------------------
# Defender XDR Advanced Hunting MDO tables (schema-accurate)
# Schemas mirror microsoft_defender_telemetry_and_alerts.md sections 1.1 – 1.3.
# ---------------------------------------------------------------------------


def _iso_z_defender(dt: datetime) -> str:
    """ISO-8601 with 7-digit fractional second + Z suffix (Defender format)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    frac = f"{dt.microsecond:06d}{random.randint(0, 9)}"
    return f"{base}.{frac}Z"


_DEFAULT_DEFENDER_PROFILE = {
    "tenant_id": "b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c",
    "victim_upn": "alex.morgan@contoso.com",
    "victim_object_id": "9a8b7c6d-1234-5678-90ab-cdef01234567",
    "sender_from": "billing-noreply@arcadia-invoices.com",
    "sender_mail_from": "bounce+04827@arcadia-invoices.com",
    "sender_domain": "arcadia-invoices.com",
    "sender_display": "Arcadia Billing",
    "sender_ip": "185.220.101.42",
    "subject": "Invoice #INV-2026-04827 \u2014 Payment Past Due",
    "url": "https://secure-invoice-portal.arcadia-cdn[.]net/inv/04827/view?token=eyJhbGciOiJIUzI1NiJ9",
    "url_clean": "https://secure-invoice-portal.arcadia-cdn.net/inv/04827/view?token=eyJhbGciOiJIUzI1NiJ9",
    "url_domain": "secure-invoice-portal.arcadia-cdn.net",
    "url_chain": [
        "https://secure-invoice-portal.arcadia-cdn.net/inv/04827/view",
        "https://arcadia-cdn-edge.b-cdn.net/dl/invoice-04827.zip",
    ],
    "network_message_id": "5c44b08a-b1c2-4d3e-9f87-2e8a4b6c0d12",
    "email_cluster_id": "ec_2026-05-29_a17f9c",
    "alert_id": "ad9d8c7b-6e5f-4a3b-2c1d-0e9f8a7b6c5d",
    "client_ip": "172.18.84.119",
}


def _merge_profile(overrides):
    prof = dict(_DEFAULT_DEFENDER_PROFILE)
    if overrides and isinstance(overrides.get("_profile"), dict):
        prof.update(overrides["_profile"])
    return prof


def _clean_overrides(overrides):
    if not overrides:
        return {}
    return {k: v for k, v in overrides.items() if not k.startswith("_")}


def email_events_log(overrides: dict | None = None) -> Dict:
    """Generate a Defender for Office 365 ``EmailEvents`` row."""
    prof = _merge_profile(overrides)
    now = datetime.now(timezone.utc)
    event = {
        "Timestamp": _iso_z_defender(now),
        "NetworkMessageId": prof["network_message_id"],
        "InternetMessageId": f"<{uuid.uuid4()}@{prof['sender_domain']}>",
        "SenderFromAddress": prof["sender_from"],
        "SenderDisplayName": prof["sender_display"],
        "SenderObjectId": None,
        "SenderMailFromAddress": prof["sender_mail_from"],
        "SenderIPv4": prof["sender_ip"],
        "SenderIPv6": None,
        "SenderFromDomain": prof["sender_domain"],
        "SenderMailFromDomain": prof["sender_domain"],
        "RecipientEmailAddress": prof["victim_upn"],
        "RecipientObjectId": prof["victim_object_id"],
        "Subject": prof["subject"],
        "EmailClusterId": prof["email_cluster_id"],
        "EmailDirection": "Inbound",
        "DeliveryAction": "Delivered",
        "DeliveryLocation": "Inbox",
        "OriginalDeliveryAction": None,
        "OriginalDeliveryLocation": None,
        "Connectors": "",
        "EmailLanguage": "en",
        "AuthenticationDetails": json.dumps(
            {"SPF": "pass", "DKIM": "pass", "DMARC": "none", "CompAuth": "pass"}
        ),
        "AttachmentCount": 0,
        "UrlCount": 1,
        "EmailAction": "",
        "EmailActionPolicy": "",
        "EmailActionPolicyGuid": None,
        "ThreatTypes": "Phish",
        "ThreatNames": "Phish.URL",
        "DetectionMethods": json.dumps(
            {"Phish": ["URL reputation", "URL detonation reputation"]}
        ),
        "ConfidenceLevel": json.dumps({"Phish": "High"}),
        "Connector": "",
        "BulkComplaintLevel": 4,
        "PhishConfidenceLevel": "High",
        "LatestDeliveryAction": "Delivered",
        "LatestDeliveryLocation": "Inbox",
        "UserLevelAction": "",
        "UserLevelPolicy": "",
        "OrgLevelAction": "",
        "OrgLevelPolicy": "",
        "ThreatOriginatingService": "EOP",
        "AlertId": prof["alert_id"],
        "ReportId": random.randint(8_472_690_000, 8_472_699_999),
        "AdditionalFields": json.dumps(
            {
                "TenantId": prof["tenant_id"],
                "FirstSeenInOrg": True,
                "FirstSeenForRecipient": True,
            }
        ),
        "_table": "EmailEvents",
    }
    event.update(_clean_overrides(overrides))
    return event


def email_url_info_log(overrides: dict | None = None) -> Dict:
    """Generate an ``EmailUrlInfo`` row."""
    prof = _merge_profile(overrides)
    now = datetime.now(timezone.utc)
    event = {
        "Timestamp": _iso_z_defender(now),
        "NetworkMessageId": prof["network_message_id"],
        "Url": prof["url"],
        "UrlDomain": prof["url_domain"],
        "UrlLocation": "Body",
        "ReportId": random.randint(8_472_690_000, 8_472_699_999),
        "_table": "EmailUrlInfo",
    }
    event.update(_clean_overrides(overrides))
    return event


def url_click_events_log(overrides: dict | None = None) -> Dict:
    """Generate a ``UrlClickEvents`` row (Safe Links click-through)."""
    prof = _merge_profile(overrides)
    now = datetime.now(timezone.utc)
    event = {
        "Timestamp": _iso_z_defender(now),
        "Url": prof["url"],
        "ActionType": "ClickAllowed",
        "AccountUpn": prof["victim_upn"],
        "Workload": "Email",
        "NetworkMessageId": prof["network_message_id"],
        "ThreatTypes": "Phish",
        "DetectionMethods": "URL reputation",
        "IPAddress": prof["client_ip"],
        "IsClickedThrough": True,
        "UrlChain": json.dumps(prof["url_chain"]),
        "ReportId": random.randint(8_472_690_000, 8_472_699_999),
        "_table": "UrlClickEvents",
    }
    event.update(_clean_overrides(overrides))
    return event


if __name__ == "__main__":
    # Generate sample logs
    print("Sample Microsoft Defender for Email events:")
    for threat in ["Phish", "Malware", "Spam", "None"]:
        print(f"\n{threat} event:")
        print(microsoft_defender_email_log({"ThreatTypes": threat}))
        print()
    print("\nDefender Advanced Hunting MDO samples:")
    print(json.dumps(email_events_log(), indent=2))
    print(json.dumps(email_url_info_log(), indent=2))
    print(json.dumps(url_click_events_log(), indent=2))