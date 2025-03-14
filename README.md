# Automated SOC Workflow: Threat Detection, Intelligence Enrichment, and Incident Response

# Objective

This project automates SOC workflows using Wazuh for threat detection, TheHive for case management, and Shuffle for automation. It features real-time Mimikatz detection, threat intelligence enrichment via VirusTotal, and automated incident response with email alerts, improving threat visibility and response efficiency.

# Skills Demonstrated

Threat detection and monitoring using Wazuh

Incident response and case management via TheHive

Security automation with Shuffle

Threat intelligence enrichment using VirusTotal

SIEM log analysis and alerting

Firewall rule configuration for securing communication

Log analysis and correlation for improved detection

Threat hunting techniques based on Sysmon and Wazuh logs

# Tools Used

Windows 10 Pro VM (Endpoint for testing attacks)

Sysmon (Windows event monitoring and logging)

Wazuh (SIEM for log collection and analysis)

TheHive (Case management platform for incident response)

Shuffle (Security automation and orchestration)

VirusTotal API (Threat intelligence enrichment)

DigitalOcean Droplets (Hosting Wazuh and TheHive servers)

PowerShell & SSH (Remote management and server access)

MITRE ATT&CK Framework (Mapping detections to real-world attack techniques)

# Project Workflow

1. Environment Setup

Deployed a Windows 10 Pro VM and installed Sysmon for advanced event logging.

Configured a firewall with specific rules for network security.

Created and configured two DigitalOcean droplets for Wazuh and TheHive.

Accessed the servers via SSH (ssh root@droplet_ip).

Installed and configured Wazuh and TheHive on respective droplets.

2. Wazuh Configuration

Accessed Wazuh UI via Chrome (https://wazuh-ip).

Added credentials and configured a Wazuh agent.

Created a backup of ossec.conf:

cp /var/ossec/etc/ossec.conf ~/ossec-backup.conf

Modified ossec.conf to capture Sysmon logs:

Enabled logall and logall_json.

Restarted Wazuh Manager to apply changes.

Enabled archives in Filebeat for log storage.

Created a new index in Wazuh:

wazuh-archives-**

3. Mimikatz Detection & Wazuh Rule Creation

Installed Mimikatz on Windows.

Created a custom Wazuh rule to detect Mimikatz execution based on originalfilename.

Renamed Mimikatz executable and re-ran it to trigger detection.

Mapped detection to MITRE ATT&CK Framework (Credential Dumping - T1003).

Verified alerts in the Wazuh dashboard.

Added correlation rules to detect multiple attempts over time.

4. Security Automation with Shuffle

Configured Shuffle automation workflow.

Set up a Webhook in Shuffle and integrated it with Wazuh.

Configured regex capture for SHA256 hashes.

Integrated VirusTotal API for threat intelligence.

Retrieved threat reputation scores (e.g., Malicious: 67 detections).

Integrated TheHive API to automatically create alerts.

Configured email alerts via SquareX for real-time notifications.

Automated case creation in TheHive based on severity.

# Threat Hunting & Advanced Detection

Implemented log correlation in Wazuh to track attack chains.

Used Sysmon Event ID filtering to reduce noise.

Created additional detection rules for LSASS dumping, RDP brute force, and process injection.

Implemented IOC-based detection using threat intelligence feeds.

# Troubleshooting & False Positive Handling

False Positives in Mimikatz Detection:

Fine-tune the rule to avoid generic detections.

Modify originalfilename filter to detect behavior-based anomalies.

Shuffle Workflow Errors:

Ensure correct API keys are used.

Validate regex captures for SHA256 hash extraction.

Wazuh Logs Not Appearing:

Verify ossec.conf changes are saved and Wazuh Manager is restarted.

Check Filebeat logs for issues (sudo systemctl status filebeat).

# Results & Insights

Successfully detected Mimikatz execution via Wazuh.

Automated threat intelligence enrichment using VirusTotal.

Incident response automation via TheHive.

Security alerting through Shuffle & Email notifications.

Implemented log correlation for advanced attack detection.

Mapped detection rules to MITRE ATT&CK for real-world relevance.

# Future Improvements

Expanding detection coverage for additional attack techniques (e.g., PowerShell exploitation, privilege escalation).

Integrating more threat intelligence sources like AbuseIPDB, Hybrid Analysis.

Automating SOC playbooks for better case response in TheHive.

Enhancing email alerts with detailed forensic information.

# Conclusion

This project demonstrates a real-world SOC automation workflow by integrating SIEM, threat intelligence, and automated incident response. By leveraging Wazuh, TheHive, and Shuffle, this setup streamlines threat detection, enrichment, and response, reducing manual effort in SOC operations.

# Screenshots

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

