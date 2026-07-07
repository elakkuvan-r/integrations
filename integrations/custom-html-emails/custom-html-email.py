#!/usr/bin/env python3
# Created by Diego Arjona Garcia (Wazuh Security Engineer)
# Property of Wazuh Inc.

import sys
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# --- SMTP CONFIGURATION ---
SMTP_SERVER = "YOUR_SMTP_SERVER_IP_OR_DOMAIN"
SMTP_PORT = 25
SMTP_USER = "sender@yourdomain.com"
SMTP_PASS = "YOUR_PASSWORD" # Optional if your relay doesn't require auth
TO_EMAIL = "recipient@yourdomain.com"
# --------------------------

# Read the alert file path passed by Wazuh
alert_file = sys.argv[1]

with open(alert_file, 'r') as f:
    alert_data = json.load(f)

# Extracting the requested fields with fallbacks
description = alert_data.get('rule', {}).get('description', 'N/A')
rule_level = alert_data.get('rule', {}).get('level', 'N/A')
rule_id = alert_data.get('rule', {}).get('id', 'N/A')
timestamp = alert_data.get('timestamp', 'N/A')
affected_device = alert_data.get('agent', {}).get('name', 'Wazuh Manager')
log_payload = alert_data.get('full_log', json.dumps(alert_data.get('syscheck', {}), indent=2))

# Construct HTML Body
html_content = f"""
<html>
<head>
    <style>
        table {{ font-family: Arial, sans-serif; border-collapse: collapse; width: 100%; }}
        td, th {{ border: 1px solid #dddddd; text-align: left; padding: 12px; }}
        th {{ background-color: #d9534f; color: white; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        pre {{ white-space: pre-wrap; word-wrap: break-word; background: #f4f4f4; padding: 10px; border: 1px solid #ccc; }}
    </style>
</head>
<body>
    <h2>High Severity Wazuh Alert</h2>
    <table>
        <tr><th colspan="2">Alert Summary</th></tr>
        <tr><td><strong>Description</strong></td><td>{description}</td></tr>
        <tr><td><strong>Rule Level</strong></td><td><span style="color: red; font-weight: bold;">{rule_level}</span></td></tr>
        <tr><td><strong>Affected Device</strong></td><td>{affected_device}</td></tr>
        <tr><td><strong>Timestamp</strong></td><td>{timestamp}</td></tr>
        <tr><td><strong>Log Payload</strong></td><td><pre>{log_payload}</pre></td></tr>
    </table>
</body>
</html>
"""

# Create Email Message
msg = MIMEMultipart('alternative')
msg['Subject'] = f"Wazuh Alert Level {rule_level}: {description[:50]}"
msg['From'] = SMTP_USER
msg['To'] = TO_EMAIL
msg.attach(MIMEText(html_content, 'html'))

# Send via SMTP
try:
    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    # server.starttls()                  #UNCOMMENT IF YOUR SERVER REQUIRES TLS
    # server.login(SMTP_USER, SMTP_PASS) #UNCOMMENT IF YOUR SERVER REQUIRES AUTH
    server.sendmail(SMTP_USER, TO_EMAIL, msg.as_string())
    server.quit()
except Exception as e:
    with open('/var/ossec/logs/integrations.log', 'a') as log:
        log.write(f"HTML Email Integration Error: {str(e)}\n")
