#!/usr/bin/env python3
"""
greenbone_to_wazuh.py

Pulls completed Greenbone/GVM scan reports via GMP, flattens each
result into one JSON object per line, maps CVSS -> Wazuh rule level,
and appends only new results to a log file that a Wazuh agent/manager
tails via a <localfile> block with log_format=json.
"""

import json
import os
from datetime import datetime, timezone

from gvm.connections import TLSConnection, UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

# ---- CONFIG: adjust to your environment ----
# Docker deployments (most Greenbone Community Container stacks) expose GMP
# over a Unix socket shared via a Docker volume, NOT over TCP 9390 by default.
# Set CONNECTION_MODE accordingly.
CONNECTION_MODE = "socket"      # "socket" (Docker default) or "tls" (TCP/9390 exposed)

GVM_SOCKET_PATH = "/tmp/gvm/gvmd/gvmd.sock"  # host-side path after exposing the volume

GVM_HOST = "127.0.0.1"          # only used if CONNECTION_MODE == "tls"
GVM_PORT = 9390                 # only used if CONNECTION_MODE == "tls"

GVM_USER = "wazuh-integration"  # admin user for Greenbone
GVM_PASS = "CHANGE_ME"          # admin password Greenbone

STATE_FILE = "/var/lib/greenbone-wazuh/last_report.state"
OUTPUT_LOG = "/var/log/greenbone/scan_results.json"


def cvss_to_wazuh_level(cvss):
    """
    Map CVSS base score (0-10 scale) onto your Wazuh rule level buckets:
    Low 0-6, Medium 7-11, High 12-14, Critical 15+
    Picks a representative level within each bucket.
    """
    if cvss is None:
        return 0
    if cvss < 4.0:
        return 4        # Low
    elif cvss < 7.0:
        return 9         # Medium
    elif cvss < 9.0:
        return 13        # High
    else:
        return 15        # Critical


def severity_label(level):
    if level >= 15:
        return "critical"
    elif level >= 12:
        return "high"
    elif level >= 7:
        return "medium"
    else:
        return "low"


def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return f.read().strip() or None
    return None


def save_state(report_id):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        f.write(report_id)


def extract_cve(nvt_el):
    """Handle both older <cve> flat field and newer <refs><ref type="cve"> layouts."""
    if nvt_el is None:
        return None
    cve = nvt_el.findtext("cve")
    if cve and cve.upper() != "NOCVE":
        return cve
    refs = nvt_el.find("refs")
    if refs is not None:
        cves = [r.get("id") for r in refs.findall("ref") if r.get("type") == "cve"]
        if cves:
            return ",".join(cves)
    return None


def main():
    if CONNECTION_MODE == "socket":
        connection = UnixSocketConnection(path=GVM_SOCKET_PATH)
    elif CONNECTION_MODE == "tls":
        connection = TLSConnection(hostname=GVM_HOST, port=GVM_PORT)
    else:
        raise ValueError(f"Unknown CONNECTION_MODE: {CONNECTION_MODE}")

    transform = EtreeCheckCommandTransform()

    with Gmp(connection, transform=transform) as gmp:
        gmp.authenticate(GVM_USER, GVM_PASS)

        reports_xml = gmp.get_reports(filter_string="status=Done sort-reverse=date")
        report_elements = reports_xml.findall("report")

        if not report_elements:
            print("No completed reports found.")
            return

        last_seen = load_state()
        newest_id = report_elements[0].get("id")

        os.makedirs(os.path.dirname(OUTPUT_LOG), exist_ok=True)
        written = 0

        with open(OUTPUT_LOG, "a") as out:
            for report_el in report_elements:
                report_id = report_el.get("id")
                if report_id == last_seen:
                    break  # everything older than this has already been processed

                full_report = gmp.get_report(
                    report_id=report_id,
                    details=True,
                    filter_string="apply_overrides=0 min_qod=70 levels=chmlgdf rows=-1",
                )
                results = full_report.findall(".//result")

                for result in results:
                    host = result.findtext("host")
                    name = result.findtext("name")
                    nvt = result.find("nvt")
                    cve = extract_cve(nvt)
                    cvss_text = nvt.findtext("cvss_base") if nvt is not None else None
                    cvss = float(cvss_text) if cvss_text else None
                    port = result.findtext("port")
                    raw_description = result.findtext("description") or ""
                    description = " ".join(raw_description.split())[:1000]
                    threat = result.findtext("threat")

                    level = cvss_to_wazuh_level(cvss)
                    label = severity_label(level)

                    # Skip informational/log-only findings — Greenbone often reports
                    # cvss_score as 0.0 (not None) for these, so check both.
                    if threat in ("Log", "Debug", None) and (cvss is None or cvss == 0.0):
                        continue

                    record = {
                        "greenbone.timestamp": datetime.now(timezone.utc).isoformat(),
                        "greenbone.source": "greenbone",
                        "greenbone.report_id": report_id,
                        "greenbone.host": host,
                        "greenbone.port": port,
                        "greenbone.vulnerability_name": name,
                        "greenbone.cve": cve,
                        "greenbone.cvss_score": cvss,
                        "greenbone.threat": threat,
                        "greenbone.wazuh_level": level,
                        "greenbone.severity_label": label,
                        "greenbone.description": description,
                    }

                    out.write(json.dumps(record, separators=(",", ":")) + "\n")
                    written += 1

        save_state(newest_id)
        print(f"Wrote {written} results, latest report_id={newest_id}")


if __name__ == "__main__":
    main()
