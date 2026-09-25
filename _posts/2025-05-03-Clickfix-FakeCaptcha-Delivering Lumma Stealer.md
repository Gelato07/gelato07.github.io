---
title: Coming Soon
date: 2025-05-03 00:00:00 +0800
categories: [Investigations]
tags: [Cyber Stuff]
---

# Fake CAPTCHA Campaigns: The Rise of ClickFix Malware

**2 May 2025**
**Prepared by:** Lachlan Gelavis, Level 1 Security Analyst, Security Operations Centre

---

Triskele Labs has observed a significant increase in cybercriminals adopting fake CAPTCHA pages as a social engineering tactic to distribute malware, particularly information stealers such as Lumma Stealer. The term "ClickFix Malware" has recently gained traction to describe this attack style, as referenced by sources such as KrebsOnSecurity.

Throughout 2025, we have seen a sharp rise in malvertising campaigns and the exploitation of legitimate websites and advertisements to expand the reach and impact of these attacks. A malvertising campaign is a cyberattack that uses malicious online advertisements to distribute malware, redirect users to harmful websites, or steal personal data—often without the user's knowledge.

Triskele Labs' Digital Forensics and Incident Response (DFIR) team has responded to multiple ransomware and Business Email Compromise (BEC) incidents linked to this attack vector. Our Security Operations Centre (SOC) has also detected and mitigated this threat on numerous occasions, protecting client environments from further harm.

In this blog post, we break down how attackers carry out fake CAPTCHA campaigns, how our team detects them, and the steps we take in response.

---

## Attack Flow

The flowchart below illustrates the attack chain of a fake CAPTCHA malvertising campaign, where users are tricked into executing a malicious command. This leads to the download and execution of obfuscated scripts that eventually deploy the Lumma Stealer malware.

*[ClickFix - Fake CAPTCHA Attack Flow]*

### Initial Access Vectors

Attackers primarily use malvertising techniques, embedding malicious advertisements or exploiting compromised legitimate websites to redirect unsuspecting users to fraudulent CAPTCHA pages. These deceptive pages are designed to manipulate users into executing harmful actions, such as downloading malicious files or running dangerous commands through the Windows Run dialog, thus initiating malware infection.

Other tactics include exploiting browser vulnerabilities using JavaScript to trigger unauthorised downloads, intrusive push notifications, or phishing emails containing malicious links that direct users to fake CAPTCHA pages.

The image below demonstrates how the fake CAPTCHA campaign deceives users by instructing them to execute a malicious command via the Windows Run dialog, disguised as CAPTCHA verification, which initiates the attack chain.

*[Image: reCAPTCHA — Requesting user to run commands as part of CAPTCHA verification]*

---

## Detection Methods

At Triskele Labs, we detect these attacks using several methods; most originating from SIEM and XDR/EDR alerts, supported by custom detection rules designed to identify suspicious commands and processes (e.g., `mshta`, `rundll32`, `wscript`, `powershell –enc`, and more). Other applicable detection methods include:

- **Behavioural analysis and anomaly detection**
  Monitoring user activity for unusual behaviour, such as executing suspicious commands or downloading unknown files.

- **URL and domain reputation monitoring**
  Identifying and restricting access to newly registered or suspicious domains associated with fake CAPTCHA campaigns.

- **Network traffic analysis**
  Closely observing DNS requests and other network activity to detect suspicious inbound and outbound communications linked to these attacks.

---

## Triage Steps

When an alert of this nature is triggered, the following steps illustrate how Triskele Labs validates the authenticity of the observed behaviour:

1. **Script analysis**
   Investigating scripts for signs of obfuscation, encoding, or unusual execution methods. Where the command's safety is unclear, sandbox tools are used to assess behaviour, including network communication and command-line execution.

2. **Contextual validation**
   Reviewing technical details to determine whether the activity is expected based on the user's role. For instance, users in payroll are far less likely to run advanced commands compared to IT personnel.

---

## Recommended Response Actions

If the investigation confirms a true positive, Triskele Labs will implement the following response measures:

- Immediately isolate the affected assets to prevent further malware propagation or external communication.
- If indicators show that the user account associated with the compromised host has also been affected, disable the account immediately.
- Recommend that the client consider a full wipe and reimage of the affected system as a proactive step.
- Document and share indicators of compromise (IOCs) such as suspicious IPs, file hashes, and domains, for internal CTI enrichment and broader threat-sharing.

---

## Resources

- [Fake CAPTCHA Campaign Alert – The Hacker News](https://thehackernews.com/2025/01/beware-fake-captcha-campaign-spreads.html)
- [MintsLoader Malware Delivery – The Hacker News](https://thehackernews.com/2025/01/mintsloader-delivers-stealc-malware-and.html?m=1)
- [Lumma Stealer Detection Techniques – Netskope](https://www.netskope.com/blog/lumma-stealer-fake-captchas-and-new-techniques-to-evade-detection)
- [ClickFix Analysis – KrebsOnSecurity](https://krebsonsecurity.com/2025/03/clickfix-how-to-infect-your-pc-in-three-easy-steps/)
