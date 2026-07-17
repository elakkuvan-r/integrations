# New agent detection

## Table of Contents
* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Integration Steps](#integration-steps)
* [Testing](#testing)
* [Sources](#sources)

## Introduction
This script runs one one of your Wazuh agents to query the list of agents from the manager’s API, and send a log to the manager when new agents are 
discovered.

The agent will execute the script every 5 minutes. If an agent has been enrolled during the last 5 minutes, it will write a log in the monitored log file. 
The log will trigger the custom rule 100110 which is configured to automatically send email notifications.

## Prerequisites
- The endpoint running the script should be enrolled to the Wazuh manager and active.
- The endpoint should have Python3 installed.

## Integration Steps
### Add the integration script
- Copy the `detect_new_agents.py` script to `/opt/scripts/` folder of your agent.
- Edit the script to set the correct credentials (`USERNAME` and `PASSWORD` variables) and Wazuh manager IP address (`MANAGER_IP`). You may need to create a new manager’s API user.
- Set the permissions and ownership:
```
chown root:wazuh /opt/scripts/detect_new_agents.py
chmod 750 /opt/scripts/detect_new_agents.py
```

### Wazuh agent configuration
- Add the following to the configuration of the agent where you copied the integration script:
```
<wodle name="command">
  <disabled>no</disabled>
  <tag>new-agent-detector</tag>
  <command>/opt/scripts/detect_new_agents.py</command>
  <interval>5m</interval>
  <run_on_start>yes</run_on_start>
  <timeout>60</timeout>
  <ignore_output>yes</ignore_output>
</wodle>

<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/logs/new_agents.json</location>
</localfile>
```
The script will run every 5 minutes and write logs to a local file (`/var/ossec/logs/new_agents.json`) when new agents are discovered.
The localfile section ensures the logs will be forwarded to the manager.

### Add custom rule
- In Wazuh Dashboard go to Server Management > Rules > Add new rules file. Name it `detect_new_agent-rules.xml`, add the content of detect_new_agent-rules.xml and save.
- Restart the Wazuh Manager to apply the changes.

## Testing
Once the configuration on the manager is done, the integration will run after 5 minutes and the alerts will appear on the dashboard.
<img width="1358" height="82" alt="image" src="https://github.com/user-attachments/assets/1c783cd1-91bb-4e50-a4f1-edb486883e1a" />

When running for the first time, no agent will be reported.


## Sources
- https://documentation.wazuh.com/current/user-manual/api/reference.html
- https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html
