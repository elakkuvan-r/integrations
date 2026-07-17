#!/usr/bin/python3
#
# detect_new_agents.py
# Detects newly enrolled Wazuh agents by comparing agent IDs returned by the
# Wazuh manager API against the highest agent ID seen so far (cache file).
# Each new agent is appended, as one JSON object per line, to a local log
# file that can be ingested back into Wazuh with a <localfile> block.

import json
import logging
import os
import sys

import requests
import urllib3

# === CONFIGURATION ===
MANAGER_IP = "MANAGER_IP"
API_URL = f"https://{MANAGER_IP}:55000"
API_USER = "USERNAME"
API_PASSWORD = "PASSWORD"
VERIFY_SSL = False          # Set to True (or a CA bundle path) in production
PAGE_SIZE = 500             # Agents fetched per API request (max 100000)

CACHE_FILE = "/var/ossec/new_agents_cache.txt"
OUTPUT_LOG = "/var/ossec/logs/new_agents.json"
SCRIPT_LOG = "/var/ossec/logs/new_agents_integration.log"

# On the very first run (no cache file), report all existing agents (True)
# or just create a baseline with the current highest ID (False).
FIRST_RUN_REPORT_ALL = False

# === LOGGING ===
logging.basicConfig(filename=SCRIPT_LOG,
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%Y-%m-%dT%H:%M:%S',
                    level=logging.INFO)

if not VERIFY_SSL:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_token():
    """Authenticate against the Wazuh API and return a JWT token."""
    url = f"{API_URL}/security/user/authenticate"
    try:
        resp = requests.post(url, auth=(API_USER, API_PASSWORD), verify=VERIFY_SSL, timeout=30)
    except requests.exceptions.RequestException as err:
        logging.error("Could not reach the Wazuh API: %s", err)
        sys.exit(1)

    if resp.status_code != 200:
        logging.error("API authentication failed. Status: %s. Response: %s",
                      resp.status_code, resp.text[:200])
        sys.exit(1)

    return resp.json()["data"]["token"]


def fetch_all_agents(token):
    """Return the full list of agents (excluding the manager, ID 000)."""
    headers = {"Authorization": f"Bearer {token}"}
    agents = []
    offset = 0

    while True:
        params = {
            "limit": PAGE_SIZE,
            "offset": offset,
            "sort": "+id",
            "select": "id,name,ip,registerIP,dateAdd,os.name,os.version,os.platform",
        }
        try:
            resp = requests.get(f"{API_URL}/agents", headers=headers,
                                params=params, verify=VERIFY_SSL, timeout=30)
        except requests.exceptions.RequestException as err:
            logging.error("Error querying /agents: %s", err)
            sys.exit(1)

        if resp.status_code != 200:
            logging.error("Error fetching agents. Status: %s. Response: %s",
                          resp.status_code, resp.text[:200])
            sys.exit(1)

        data = resp.json().get("data", {})
        items = data.get("affected_items", [])
        agents.extend(a for a in items if a.get("id") != "000")

        offset += PAGE_SIZE
        if offset >= data.get("total_affected_items", 0):
            break

    return agents


def read_cache():
    """Return the highest known agent ID as int, or None if no cache exists."""
    if not os.path.isfile(CACHE_FILE):
        return None
    try:
        with open(CACHE_FILE, "r") as f:
            content = f.read().strip()
            return int(content) if content else None
    except (OSError, ValueError) as err:
        logging.error("Could not read cache file '%s': %s", CACHE_FILE, err)
        sys.exit(1)


def write_cache(highest_id):
    """Persist the highest agent ID (zero-padded, as Wazuh displays it)."""
    try:
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        with open(CACHE_FILE, "w") as f:
            f.write(str(highest_id).zfill(3))
    except OSError as err:
        logging.error("Could not write cache file '%s': %s", CACHE_FILE, err)
        sys.exit(1)


def build_record(agent):
    """Build the JSON record written to the output log for one new agent."""
    os_info = agent.get("os", {})
    return {
        "integration": "new-agent-detector",
        "registration_time": agent.get("dateAdd", "unknown"),
        "agent_info": {
            "id": agent.get("id"),
            "name": agent.get("name"),
            "ip": agent.get("ip", agent.get("registerIP", "unknown")),
            "os": {
                "name": os_info.get("name", "unknown"),
                "version": os_info.get("version", "unknown"),
                "platform": os_info.get("platform", "unknown"),
            },
        },
    }


def append_records(records):
    """Append one JSON object per line to the output log file."""
    try:
        with open(OUTPUT_LOG, "a") as f:
            for record in records:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError as err:
        logging.error("Could not write output log '%s': %s", OUTPUT_LOG, err)
        sys.exit(1)


def main():
    logging.info("Running the new-agent detection script.")

    token = get_token()
    agents = fetch_all_agents(token)

    if not agents:
        logging.info("No agents registered in the environment. Nothing to do.")
        return

    current_max = max(int(a["id"]) for a in agents)
    cached_max = read_cache()

    # First run: create the cache file
    if cached_max is None:
        if FIRST_RUN_REPORT_ALL:
            cached_max = 0
            logging.info("No cache file found. Reporting all existing agents.")
        else:
            write_cache(current_max)
            logging.info("No cache file found. Baseline created with highest ID %s. "
                         "No agents reported on first run.", str(current_max).zfill(3))
            return

    new_agents = [a for a in agents if int(a["id"]) > cached_max]

    if not new_agents:
        logging.info("No new agents detected (cached highest ID: %s).",
                     str(cached_max).zfill(3))
        return

    records = [build_record(a) for a in new_agents]
    append_records(records)

    new_max = max(int(a["id"]) for a in new_agents)
    write_cache(new_max)

    names = ", ".join(f"{a['id']}:{a['name']}" for a in new_agents)
    logging.info("Detected %d new agent(s): %s. Cache updated to %s.",
                 len(new_agents), names, str(new_max).zfill(3))
    print(f"Detected {len(new_agents)} new agent(s). Logged to {OUTPUT_LOG}.")


if __name__ == "__main__":
    main()
