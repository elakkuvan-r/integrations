from datetime import datetime
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
import smtplib
import requests

# === CONFIGURATION ===
INDEXER_HOST = "https://YOUR_INDEXER_IP:9200"
INDEXER_USER = "admin"                    # Your default indexer admin user
INDEXER_PASSWORD = "YOUR_INDEXER_PASSWORD"

SMTP_SERVER = "YOUR_SMTP_SERVER_IP/DOMAIN"       # SMTP relay host or external server URL
SMTP_PORT = 25                            # SMTP Port (e.g., 25, 587, 465)
SMTP_USER = "SENDER_ADDRESS"              # Sender address
SMTP_PASSWORD = "your-smtp-password"      # Account/App Password if required
EMAIL_TO = "RECIPIENT_ADDRESS"        # Recipient address
# =====================


def fetch_report_data():
    """Queries the Wazuh Indexer with support for all dashboard UI operators."""
    init_url = f"{INDEXER_HOST}/wazuh-alerts*/_search?scroll=1m"

    script_dir = os.path.dirname(os.path.abspath(__file__))
    filters_path = os.path.join(script_dir, "filters.txt")

    # OpenSearch query buckets
    must_conditions = [{"range": {"timestamp": {"gte": "now-24h"}}}]
    must_not_conditions = []

    if os.path.exists(filters_path):
        try:
            with open(filters_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or ":" not in line:
                        continue

                    # Split prefix from target configuration
                    prefix, expression = line.split(":", 1)
                    prefix = prefix.strip()

                    # Handle operations with values (=)
                    if "=" in expression:
                        field, value = expression.split("=", 1)
                        field, value = field.strip(), value.strip()
                    else:
                        field = expression.strip()
                        value = None

                    # 1. Operator: IS
                    if prefix == "is" and value:
                        must_conditions.append({"term": {field: value}})

                    # 2. Operator: IS NOT
                    elif prefix == "is_not" and value:
                        must_not_conditions.append({"term": {field: value}})

                    # 3. Operator: IS ONE OF
                    elif prefix == "is_one_of" and value:
                        values_list = [v.strip() for v in value.split(",")]
                        must_conditions.append({"terms": {field: values_list}})

                    # 4. Operator: IS NOT ONE OF
                    elif prefix == "is_not_one_of" and value:
                        values_list = [v.strip() for v in value.split(",")]
                        must_not_conditions.append({"terms": {field: values_list}})

                    # 5. Operator: EXISTS
                    elif prefix == "exists" and field:
                        must_conditions.append({"exists": {"field": field}})

                    # 6. Operator: DOES NOT EXIST
                    elif prefix == "does_not_exist" and field:
                        must_not_conditions.append({"exists": {"field": field}})

            print("[+] Parsed filters.txt successfully with full UI operator rules.")
        except Exception as e:
            print(f"[-] Error parsing filters.txt ({e}). Running without filters.")
    else:
        print("[*] filters.txt not found. Fetching raw 24h data log pool.")

    # Assemble query payload
    query_payload = {
        "size": 1000,
        "query": {
            "bool": {
                "must": must_conditions,
                "must_not": must_not_conditions
            }
        }
    }

    all_alerts = []

    try:
        response = requests.post(
            init_url,
            auth=(INDEXER_USER, INDEXER_PASSWORD),
            json=query_payload,
            verify=False,
        )
        response.raise_for_status()

        res_data = response.json()
        scroll_id = res_data.get("_scroll_id")
        hits = res_data.get("hits", {}).get("hits", [])

        while hits:
            for hit in hits:
                if "_source" in hit:
                    all_alerts.append(hit["_source"])

            scroll_url = f"{INDEXER_HOST}/_search/scroll"
            scroll_payload = {"scroll": "1m", "scroll_id": scroll_id}

            response = requests.post(
                scroll_url,
                auth=(INDEXER_USER, INDEXER_PASSWORD),
                json=scroll_payload,
                verify=False,
            )
            response.raise_for_status()

            res_data = response.json()
            scroll_id = res_data.get("_scroll_id")
            hits = res_data.get("hits", {}).get("hits", [])

        # Release the scroll context to free indexer resources
        if scroll_id:
            try:
                requests.delete(
                    f"{INDEXER_HOST}/_search/scroll",
                    auth=(INDEXER_USER, INDEXER_PASSWORD),
                    json={"scroll_id": scroll_id},
                    verify=False,
                )
            except Exception as cleanup_err:
                print(f"[!] Failed to clear scroll context: {cleanup_err}")

        print(f"[+] Successfully retrieved all {len(all_alerts)} alerts matching operators.")
        return all_alerts

    except Exception as e:
        print(f"[-] Failed to fetch data from Wazuh Indexer via Scroll: {e}")
        return []


def flatten_json(y):
    """Flattens nested JSON objects into dot-notation keys."""
    out = {}

    def flatten(x, name=""):
        if isinstance(x, dict):
            for a in x:
                flatten(x[a], name + a + ".")
        elif isinstance(x, list):
            i = 0
            for a in x:
                flatten(a, name + str(i) + ".")
                i += 1
        else:
            out[name[:-1]] = x

    flatten(y)
    return out


def convert_to_dynamic_csv(data):
    """Dynamically gathers keys, sorts chronologically (oldest first)."""
    if not data:
        return "No data found for the selected period."

    data = sorted(data, key=lambda x: x.get("timestamp", ""), reverse=False)
    flattened_rows = [flatten_json(row) for row in data]

    all_keys = set()
    for row in flattened_rows:
        all_keys.update(row.keys())

    headers = sorted(list(all_keys))

    if "@timestamp" in headers:
        headers.insert(0, headers.pop(headers.index("@timestamp")))
    elif "timestamp" in headers:
        headers.insert(0, headers.pop(headers.index("timestamp")))

    csv_lines = [",".join(headers)]

    for row in flattened_rows:
        line_items = []
        for header in headers:
            val = row.get(header, "-")
            val_str = str(val).replace("\n", " ").replace("\r", "")

            if "," in val_str or '"' in val_str:
                escaped_quotes = val_str.replace('"', '""')
                val_str = f'"{escaped_quotes}"'

            line_items.append(val_str)

        csv_lines.append(",".join(line_items))

    return "\n".join(csv_lines)


def send_email(csv_content):
    """Attempts to email the report; saves locally if network fails."""
    date_str = datetime.now().strftime("%Y-%m-%d")
    filename = f"Wazuh_Report_{date_str}.csv"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(csv_content)
    print(f"[+] Saved backup copy locally to: {os.path.abspath(filename)}")

    msg = MIMEMultipart()
    msg["From"] = SMTP_USER
    msg["To"] = EMAIL_TO
    msg["Subject"] = f"Wazuh Security Report - {date_str}"

    body = f"Hello,\n\nPlease find attached your automated security report.\n\nGenerated on: {datetime.now()}"
    msg.attach(MIMEText(body, "plain"))

    attachment = MIMEApplication(csv_content.encode("utf-8"), name=filename)
    attachment["Content-Disposition"] = f'attachment; filename="{filename}"'
    msg.attach(attachment)

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, EMAIL_TO, msg.as_string())
        server.quit()
        print("[+] Report emailed successfully!")
    except Exception as e:
        print(f"[-] Email delivery failed ({e}). printing preview to terminal:")
        print("-" * 50)
        print("\n".join(csv_content.split("\n")[:5]))
        print("... [truncated] ...")


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()

    print("[*] Starting report generation from Indexer...")
    raw_data = fetch_report_data()
    if raw_data:
        csv_data = convert_to_dynamic_csv(raw_data)
        send_email(csv_data)
    else:
        print("[-] No records returned. Verify credentials or time windows.")
