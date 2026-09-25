---
title: "Clickfix/FakeCaptcha Campaigns: Delivering Lumma Stealer"
date: 2025-05-02 00:00:00 +0800
categories: [Articles]
tags: [Cyber Stuff]
---

**2 May 2025**
**Prepared by:** Lachlan Gelavis, Level 1 Security Analyst, Security Operations Centre

---

For the official company blog post, check it out here: [Triskele Labs – ClickFix Malware: Fake CAPTCHA Malware Campaign Overview](https://www.triskelelabs.com/clickfix-malware-fake-captcha-malware-campaign-overview)

---

Triskele Labs has observed a significant increase in cybercriminals adopting fake CAPTCHA pages as a social engineering tactic to distribute malware, particularly information stealers such as Lumma Stealer.

Throughout 2025, we have seen a sharp rise in malvertising campaigns and the exploitation of legitimate websites and advertisements to expand the reach and impact of these attacks. Triskele Labs' Digital Forensics and Incident Response (DFIR) team has responded to multiple ransomware and Business Email Compromise (BEC) incidents linked to this attack vector. Our Security Operations Centre detects and investigates these campaigns.

In this blog post, we break down how attackers carry out fake CAPTCHA campaigns, how our team detects them, and the steps we take in response.

---

## Attack Flow

The flowchart below illustrates the attack chain of a fake CAPTCHA malvertising campaign, where users are tricked into executing a malicious command. This leads to the download and execution of obfuscated malware.

*[ClickFix - Fake CAPTCHA Attack Flow]*

![ClickFix - Fake CAPTCHA Attack Flow](https://www.triskelelabs.com/hs-fs/hubfs/ClickFix%20-%20Fake%20CAPTCHA%20Attack%20Flow-01.png?width=5334&height=3000&name=ClickFix%20-%20Fake%20CAPTCHA%20Attack%20Flow-01.png)

### Initial Access Vectors

Attackers primarily use malvertising techniques, embedding malicious advertisements or exploiting compromised legitimate websites to redirect unsuspecting users to fraudulent CAPTCHA pages. These deceptive pages instruct users to complete a fake verification process.

Other tactics include exploiting browser vulnerabilities using JavaScript to trigger unauthorised downloads, intrusive push notifications, or phishing emails containing malicious links that direct users to the fake CAPTCHA pages.

The image below demonstrates how the fake CAPTCHA campaign deceives users by instructing them to execute a malicious command via the Windows Run dialog, disguised as CAPTCHA verification.

*[Image: reCAPTCHA — Requesting user to run commands as part of CAPTCHA verification]*

---

## Detection Methods

At Triskele Labs, we detect these attacks using several methods; most originating from SIEM and XDR/EDR alerts, supported by custom detection rules designed to identify suspicious commands and processes.

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
   Investigating scripts for signs of obfuscation, encoding, or unusual execution methods. Where the command's safety is unclear, sandbox tools are used to assess behaviour, including network communications.

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
