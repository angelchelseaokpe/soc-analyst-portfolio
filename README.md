# Incident 001: Failed Login Investigation - Windows Event ID 4625

## Project Overview

This project was created as part of my personal SOC home lab to develop practical experience beyond academic study and build evidence of my SOC investigation skills.

The aim was to practise a basic Tier 1 SOC investigation workflow, including Windows Security log analysis, authentication monitoring, alert investigation, SIEM analysis, evidence collection, risk assessment and incident documentation.

I generated controlled failed login activity on a Windows 10 virtual machine and investigated the resulting Windows Event ID 4625 events using both Windows Event Viewer and Splunk Enterprise.

## Lab Environment

- Windows 10 Virtual Machine
- Oracle VirtualBox
- Windows Event Viewer
- Windows Security Event Logs
- Splunk Enterprise
- Splunk Search Processing Language (SPL)

## Investigation Scenario

Five controlled failed login attempts were generated against a local test account named `Bob`.

The purpose was to investigate how failed authentication attempts appear within Windows Security logs and how the same events can be analysed using a SIEM platform.

### Event Details

- **Event ID:** 4625
- **Event Type:** Failed Logon
- **Log Source:** Windows Security Logs
- **Target Account:** Bob
- **Number of Failed Attempts:** 5
- **Logon Type:** 2 — Interactive Logon
- **Source Network Address:** 127.0.0.1
- **Time Range:** Approximately 14:55–14:56
