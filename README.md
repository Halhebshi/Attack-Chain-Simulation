# Attack Chain Simulation

A full red/blue exercise built around a simple idea: don't just run an attack, run it against a real hardened endpoint and document what actually happens, blocks and all.

Most attack chain labs run against a clean throwaway VM with no protection turned on, which makes every step succeed and teaches less than it looks like it does. This lab runs the same eight-stage attack chain against an endpoint that already has Microsoft Defender for Endpoint and a security baseline applied through co-management. The attack did not proceed unopposed. Defender caught Stage 2 in real time and blocked it before it could complete, which is the result documented here rather than something engineered around.

The victim is testuser1, a standard domain account. The responder is Hussein, who investigates the attack afterward using the same Microsoft Defender XDR and Sentinel queries a Tier 2 SOC analyst would run during a live incident.

## Environment

- Windows 11 victim endpoint, MDE onboarded, Intune enrolled, co-managed with SCCM
- Kali Linux attacker VM on the same subnet
- Windows Server 2022 domain controller
- Microsoft Sentinel connected to Defender XDR
- Microsoft 365 E5 tenant

## What Was Built

### The attack chain

Eight stages, each generating real telemetry across EmailEvents, DeviceProcessEvents, DeviceNetworkEvents, SecurityEvent, and ThreatIntelligenceIndicator:

1. Phishing email delivery
2. Office spawning PowerShell
3. PowerShell payload download from the attacker host
4. Reverse shell C2 connection
5. LOLBin abuse for defense evasion (mshta, rundll32, certutil, wmic)
6. Privilege escalation via local Administrators group membership
7. Lateral movement using WMI process creation
8. Threat intelligence correlation by registering the attacker IP as a Sentinel indicator

### The defense that actually fired

Stage 2 was blocked outright by MDE's behavioral detection `Behavior:Win32/OfficeExecPowershell.C`, tied to the Attack Surface Reduction rule that blocks Office applications from spawning child processes. This is exactly the detection that rule exists to provide, and it worked. The rest of the chain was completed by running the equivalent commands directly on the endpoint to continue generating telemetry for the investigation.

### The investigation

This is the more important half of the lab. Starting from a single indicator, the investigation reconstructs the full kill chain:

- A union query across all five relevant tables builds one chronological timeline of everything the victim account touched
- A pivot on the attacker IP across tables finds every device that talked to it, the lateral scope check before containment
- A kill chain reconstruction query anchors on the phishing email timestamp and joins process and network events on the same device within tight time windows, proving the PowerShell execution happened because of the email rather than just near it in time

### Real gaps found along the way

Two findings came out of this that are worth knowing for anyone building a similar environment. Windows Security event forwarding to Sentinel was never configured for the endpoint, so SecurityEvent queries came back empty even though the privilege escalation event fired correctly in the local Windows Event Log, confirmed directly with Get-WinEvent. An environment can have full MDE coverage and still have zero SecurityEvent data if log forwarding was never set up as a separate pipeline.

WinRM was not configured between the lab VMs, which blocked the planned remote WMI call for lateral movement. The same technique and detection signature were demonstrated by running the WMI process creation locally instead, since the behavior MDE looks for does not depend on the call crossing machines.

## MITRE ATT&CK Coverage

Spearphishing Attachment, PowerShell, Ingress Tool Transfer, Application Layer Protocol C2, three Signed Binary Proxy Execution sub-techniques, Windows Management Instrumentation, Valid Accounts privilege escalation, and Remote Services lateral movement. Full mapping with table sources is in the lab document.

## Files in this repo

- Full lab document with stage-by-stage screenshots, KQL queries, and findings
- MITRE ATT&CK coverage table
- Schema notes for EmailEvents and Entra sign-in tables current as of mid-2026

This lab is part of a larger Microsoft 365 security portfolio. See the other repos for IAM lifecycle automation, Purview data governance and Copilot security, and SOC triage automation.
