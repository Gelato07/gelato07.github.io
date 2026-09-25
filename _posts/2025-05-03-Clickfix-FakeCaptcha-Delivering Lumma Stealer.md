---
title: "Fake CAPTCHAs: How Attackers Are Using Them to Spread Malware"
date: 2025-05-02 00:00:00 +0800
categories: [Articles]
tags: [Cyber Stuff]
---

Over the past 4 months within 2025, there has been a sharp rise in cybercriminals using fake CAPTCHA pages as a social engineering tactic to distribute malware, particularly information stealers like Lumma Stealer. Malvertising campaigns and the exploitation of legitimate websites and ad networks have become an increasingly common way for attackers to get in front of victims, and I've seen this technique tied to a growing number of ransomware and Business Email Compromise (BEC) incidents.

In this post, I want to break down how these fake CAPTCHA campaigns work, how they can be detected, and what a good response looks like.

## Attack Flow

The flowchart below illustrates the attack chain of a fake CAPTCHA malvertising campaign, where users are tricked into executing a malicious command. This leads to the download and execution of obfuscated malware.

![ClickFix - Fake CAPTCHA Attack Flow](https://www.triskelelabs.com/hs-fs/hubfs/ClickFix%20-%20Fake%20CAPTCHA%20Attack%20Flow-01.png?width=5334&height=3000&name=ClickFix%20-%20Fake%20CAPTCHA%20Attack%20Flow-01.png)

## Initial Access Vectors

Attackers primarily rely on malvertising - embedding malicious ads or exploiting compromised legitimate websites to redirect unsuspecting users to fraudulent CAPTCHA pages. These pages instruct users to complete a fake "verification" process.

Other tactics I've observed include exploiting browser vulnerabilities with JavaScript to trigger unauthorised downloads, intrusive push notifications, and phishing emails with malicious links that funnel users toward the same fake CAPTCHA pages.

The image below shows how one of these campaigns deceives users into executing a malicious command via the Windows Run dialog, disguised as CAPTCHA verification.

![reCAPTCHA — Requesting user to run commands as part of CAPTCHA verification](https://www.triskelelabs.com/hs-fs/hubfs/recaptcha.webp?width=728&height=380&name=recaptcha.webp)

## Detection Methods

There are a few methods that work well for catching this kind of activity, most of which start with SIEM and XDR/EDR alerts, backed by custom detection rules for suspicious commands and processes:

- Behavioural analysis and anomaly detection, watching for unusual user activity, like running suspicious commands or downloading unknown files.
- URL and domain reputation monitoring - flagging and restricting access to newly registered or suspicious domains tied to fake CAPTCHA campaigns.
- Network traffic analysis, keeping an eye on DNS requests and other network activity for suspicious inbound/outbound communication linked to these attacks.

## Triage Steps

When an alert like this fires, here's how I'd go about validating whether it's genuine:

1. Commandline analysis - Investigate the script for signs of obfuscation, encoding, unintelligible arguments or unusual execution methods. Where a command's intent isn't obvious, sandbox tools help assess its behaviour, including any network communications it triggers.
2. Network Pivoting - Review logs from roughly two minutes before and after the malicious command, focusing on the process used to initiate the malware (for example, powershell.exe, cmd.exe, mshta.exe, etc.). Check for inbound and outbound connections and look for suspicious network activity, such as Domain Generation Algorithm (DGA) domains, newly created domains, or known information stealer infrastructure from threat intelligence feeds.
3. Contextual validation - Check whether the activity fits the user's role. Someone in payroll running advanced system commands is a lot more suspicious than an IT admin doing the same thing.

## Recommended Response Actions

If an investigation confirms a true positive, here's what I'd recommend doing:

- Isolate the affected asset immediately to stop malware propagation or further external communication.
- If the associated user account shows signs of compromise, disable it right away.
- Consider a full wipe and reimage of the affected system as a precaution.
- Document and share indicators of compromise (IOCs) like suspicious IPs, file hashes, domains to help the community for broader threat intelligence and detection tuning.
