# Automated SOC Workflow: Threat Detection, Intelligence Enrichment, and Incident Response

# Objective

This project automates SOC workflows using Wazuh for threat detection, TheHive for case management, and Shuffle for automation. It features real-time Mimikatz detection, threat intelligence enrichment via VirusTotal, and automated incident response with email alerts, improving threat visibility and response efficiency.

# Skills Demonstrated

Threat detection and monitoring using Wazuh

Incident response and case management via TheHive

Security automation with Shuffle

Threat intelligence enrichment using VirusTotal

SIEM log analysis and alerting

# Tools Used

Windows 10 Pro VM (Endpoint for testing attacks)

Sysmon (Windows event monitoring)

Wazuh (SIEM for log collection and analysis)

TheHive (Case management platform for incident response)

Shuffle (Security automation and orchestration)

VirusTotal API (Threat intelligence enrichment)

# Project Workflow

1. Environment Setup

Deployed a Windows 10 Pro VM and installed Sysmon for advanced logging.

Created a firewall with specific rules for security.

Deployed two Droplets (Wazuh and TheHive) and added them to the firewall.

Accessed the servers via SSH from PowerShell.

Installed and configured Wazuh and TheHive.

2. Wazuh Configuration

Accessed Wazuh on Chrome using https://wazuh-ip.

Added credentials and configured a Wazuh Agent.

Created a backup of ossec.conf (cp /var/ossec/etc/ossec.conf ~/ossec-backup.conf).

Modified ossec.conf to capture Sysmon logs and changed logall and logall_json to yes.

Restarted Wazuh Manager.

Enabled archives in Filebeat.

Created a new index in Wazuh: wazuh-archives-**.

3. Mimikatz Detection & Wazuh Rule Creation

Installed Mimikatz on Windows.

Created a Wazuh rule to detect Mimikatz execution based on originalfilename.

Modified and executed a renamed Mimikatz binary to trigger detection.

Verified Wazuh alerts in the dashboard.

4. Security Automation with Shuffle

Configured Shuffle automation.

Set up a Webhook in Shuffle and integrated it with Wazuh.

Modified the change_me variable for alert handling.

Configured regex capture for SHA256 hashes.

Integrated VirusTotal API for threat intelligence.

Retrieved threat reputation scores (Malicious: 67 detection in VirusTotal).

Integrated TheHive API to automatically create alerts.

Configured email alerts via SquareX for real-time notifications.

# Results & Insights

Successful detection of Mimikatz execution through Wazuh.

Automated threat enrichment using VirusTotal.

Incident response automation via TheHive.

Security alerting through Shuffle & Email notifications.


Demonstrated SOC automation workflow for real-world threat detection.

# Future Improvements

Implementing additional detection rules for other attack techniques.

Enhancing threat intelligence by integrating more APIs (AbuseIPDB, HybridAnalysis, etc.).

Automating case assignment in TheHive based on severity levels.

Improving email alerts with more detailed forensic data.

# Conclusion

This project showcases a real-world SOC automation workflow, integrating SIEM, threat intelligence, and automated incident response. By leveraging Wazuh, TheHive, and Shuffle, this setup streamlines threat detection, enrichment, and response, significantly reducing manual effort in SOC operations.

# SCcreenshots

# ossec-backup.conf and ossec.conf modification in Program Files (x86) - OSSEC-Agent.

![1](https://github.com/Mihindig/socautomation-/blob/main/1.png)

# ossec.conf changes in Notepad to capture Sysmon logs.

![2](https://github.com/Mihindig/socautomation-/blob/main/2.png)

# Running cp /var/ossec/etc/ossec.conf ~/ossec-backup.conf in root@wazuh.

![3](https://github.com/Mihindig/socautomation-/blob/main/3.png)

# Modifying logall and logall_json settings.

![4](https://github.com/Mihindig/socautomation-/blob/main/4.png)

# Enabling archives in Filebeat.

![5](https://github.com/Mihindig/socautomation-/blob/main/5.png)

# Creating wazuh-archives- index.

![6](https://github.com/Mihindig/socautomation-/blob/main/6.png)

# Event Viewer logs for Mimikatz detection (EventCode 1).

![7](https://github.com/Mihindig/socautomation-/blob/main/7.png)

# Checking archives.json for Mimikatz events.

![8](https://github.com/Mihindig/socautomation-/blob/main/8.png)

# Wazuh rule creation screenshot.

![9](https://github.com/Mihindig/socautomation-/blob/main/9.png)

# Before & After renaming Mimikatz.

![10](https://github.com/Mihindig/socautomation-/blob/main/10.png)

# Wazuh alert for renamed Mimikatz execution.

![11](https://github.com/Mihindig/socautomation-/blob/main/11.png)

# Shuffle Webhook setup & Regex capture for SHA256.

![12](https://github.com/Mihindig/socautomation-/blob/main/12.png)

# VirusTotal detection (Malicious: 67).

![13](https://github.com/Mihindig/socautomation-/blob/main/13.png)

# Configured Shuffle alert (Summary, Title, Severity).

![14](https://github.com/Mihindig/socautomation-/blob/main/14.png)

# Final Shuffle alert screenshot.

![15](https://github.com/Mihindig/socautomation-/blob/main/15.png)

# SquareX email alert screenshot

![16](https://github.com/Mihindig/socautomation-/blob/main/16.png)

# Resources

### https://www.microsoft.com/en-ca/software-download/windows10
### https://www.virtualbox.org/
### https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
### https://github.com/olafhartong/sysmon-modular
### https://www.digitalocean.com
### https://www.virustotal.com

# License:
© Mihindig 2025. All rights reserved.

This repository is for educational purposes only. Unauthorized use, redistribution, or commercial use of this code is prohibited without explicit permission from the author. Please do not copy or redistribute without providing appropriate credit.


# Contact:

<a href="https://www.linkedin.com/in/mihindi-gunawardana-44a0a432b/" target="_blank">
  <img src="https://img.shields.io/badge/-LinkedIn-0072b1?&style=for-the-badge&logo=linkedin&logoColor=white" />
</a>

