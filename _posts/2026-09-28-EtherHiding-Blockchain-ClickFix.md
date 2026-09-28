---
title: "From Blockchain to Clipboard: Dissecting an EtherHiding ClickFix Attack"
date: 2026-09-28 00:00:00 +0800
categories: ["Byte-Sized Deep Dives"]
tags: [Cyber Stuff]
description: "A walkthrough of a real EtherHiding campaign, tracing how attackers use Polygon smart contracts as a dead drop to serve a ClickFix fake CAPTCHA and deliver an information stealer."
published: true
---

## How the EtherHiding C2 Functions

EtherHiding is a malware delivery technique in which attackers store malicious code or configuration inside smart contracts on public blockchains such as BNB Smart Chain and Ethereum, rather than on conventional servers. Compromised websites or malware retrieve this data using free, read-only blockchain calls that leave no transaction record. These calls are made through RPC (Remote Procedure Call) endpoints, which are public gateways that let any website or program query the blockchain without running its own node. A typical request uses the `eth_call` method, which simply reads data from the contract without changing anything on-chain. Because the data can't be removed by a host or registrar, and the attacker can update it at will, the infrastructure is highly resistant to takedown. The blockchain effectively acts as a tamper-proof dead drop between attacker and victim.

A normal Command-and-Control (C2) server can be blocked by defenders, reported, and taken down, but EtherHiding removes that weak point by moving the command server onto a public blockchain such as Ethereum, BNB Smart Chain or Polygon. Attackers deploy a smart contract, which is a small program that lives permanently on the blockchain, and store malicious data in it: the address of their current server, the malicious code itself and more. The malware reads from that contract to find out what to do next.

*This matters for three reasons:*

- **Nothing can be taken down.** A blockchain is copied across thousands of computers and no one controls it, so there's no host or registrar to approach.
- **Reading leaves no trace.** The malware uses a lookup that doesn't create a blockchain transaction, so fetching instructions costs nothing and isn't recorded.
- **Updates are cheap and instant.** When attackers want to switch servers or payloads, they post one small transaction. In one North Korean campaign, each update cost an average of \$1.37 USD in gas fees, and every infected machine picks up the change automatically.

[DPRK Adopts EtherHiding: Nation-State Malware Hiding on Blockchains](https://cloud.google.com/blog/topics/threat-intelligence/dprk-adopts-etherhiding)

## What It Does (Delivery/Goal)

EtherHiding is a delivery and control mechanism, not the harmful payload itself. What it delivers is typically:

- **Information stealers** that take saved browser passwords, session cookies and payment cards
- **Crypto wallet theft**, targeting wallets such as MetaMask and Phantom
- **Backdoors** that give attackers ongoing remote access to run commands and copy files

## How the Attack Starts (Threat Vector)

The technique first emerged in September 2023 and has since been adopted by both criminal groups and state actors. It always depends on a separate way in, usually one of these ([GBHackers](https://gbhackers.com/north-korean-hackers-2/)):

- **Compromised websites with fake prompts.** Attackers break into legitimate websites, very often WordPress sites, and add a small script. Visitors then see a fake "update your browser" pop-up or a fake "verify you're human" check that asks them to paste a command into their computer. Google has tracked more than 14,000 web pages that display signs of compromise from one group alone. ([CSO Online](https://www.csoonline.com/article/4074916/north-korean-threat-actors-turn-blockchains-into-malware-delivery-servers.html))
- **Fake job interviews.** A North Korea-linked group poses as recruiters, mainly approaching software developers. Candidates are asked to perform a coding test or review a project, which requires them to download files from repositories like GitHub, and those files contain the malware. Google described this as the first time GTIG has observed a nation-state actor adopting this method. ([Google Cloud](https://cloud.google.com/blog/topics/threat-intelligence/dprk-adopts-etherhiding))
- **Compromised software packages.** Malicious code has also been slipped into widely used open-source developer packages, reaching anyone who installs them.

## How to Analyse It

The blockchain that the attackers use also exposes them, since everything on it is public and permanent. To analyse it, you:

1.  Unpack the malicious script to find the blockchain address and lookup it uses.
2.  Repeat that lookup safely to see what the attackers are currently serving.
3.  Review the contract's full history on public blockchain explorers. Every past update is visible, which reveals the attackers' previous servers.
4.  Follow the attacker's wallet to find related contracts and campaigns. In one recent investigation, this turned 11 domain-rotation transactions tied to a single smart contract creator into a wider picture of 26 transactions across 4 contracts.

### Examples of Public RPC Endpoints

These are the kinds of public gateways that anyone can send requests to, with no account needed. A few examples:

| Blockchain      | Example public RPC endpoint              |
| --------------- | ---------------------------------------- |
| BNB Smart Chain | `hxxps://bsc-dataseed[.]binance[.]org`   |
| BNB Smart Chain | `hxxps://bsc-dataseed1[.]bnbchain[.]org` |
| Ethereum        | `hxxps://eth[.]llamarpc[.]com`           |
| Ethereum        | `hxxps://rpc[.]ankr[.]com/eth`           |
| Polygon         | `hxxps://polygon-rpc[.]com`              |

RPC endpoints change over time, so check that these are still current before relying on them. The original ClearFake/EtherHiding campaign was reported to use Binance's BSC endpoints.

* * *

## Kill Chain: Real EtherHiding Request Flow from a Compromised Website (`theburritocity[.]com`)

### 1\. Victim Visits Compromised Website

The attacker has already compromised the website by inserting malicious code, so when someone opens the page, their browser runs it automatically. The visitor sees a normal Mexican restaurant website and has no idea that malicious scripts are running in the background.

![5fcc2b5b983ba9a8b68b3214a79c9961.png](/assets/img/etherhiding/5fcc2b5b983ba9a8b68b3214a79c9961-1.png)

### 2\. RPC Endpoints Invoked by Two Obfuscated JS Scripts | `Stage 1`

#### Script 1

This first script is the resolver/loader stage. It contains no attack payload itself; its whole job is to look up the current attacker domain from contract `0xb90658783fDa2E726C5756f94A461291C0cef691` and pull in stage two. However, there is a key exposed here that comes in handy for decoding communications.

**Key:** `JtjOz1KWzihFtqt4GY7eOyqsZZ48iI`

> **Note:** This is preparation for Stage 2, after the second script executes.

**Raw Page Response**

![2d1ed95430c6b3eea69cec5c1ba798d9.png](/assets/img/etherhiding/2d1ed95430c6b3eea69cec5c1ba798d9-1.png)

**Obfuscated**

![e95eed4e452edb637e0398782522b1c1.png](/assets/img/etherhiding/e95eed4e452edb637e0398782522b1c1-1.png)

**Deobfuscated**

![853939b9bf4492230a881644ebea396d.png](/assets/img/etherhiding/853939b9bf4492230a881644ebea396d-1.png)

It checks whether you're a real Windows user, then asks the Polygon smart contract for the attacker's current server address, decrypts that address, and injects a second-stage script (`/js/all.min.js?m=1`) from it into the page. The blockchain is used as a *dead drop* so attackers can swap servers without touching the hacked site.

#### Script 2

The second script asks the Polygon smart contract `0x08207B087F61d7e95E441E15fd6d40BEfd6eD308` for the attacker's current server, reports the visit, and downloads a targeting config. If the visitor matches the targeting rules, it covers the entire website with a full-screen iframe showing a fake Cloudflare CAPTCHA. That page can silently copy a malicious command to your clipboard and tell you to paste it into Windows Run or a terminal (the "ClickFix" technique). Once you "pass," it sets cookies so you're never shown it again.

`webanalytics-cdn[.]sbs` appears to be a web analytics server where the attackers track visits.

**Raw Page Response**

![08f4fbdd661575473b3d2ded5c98f2e1.png](/assets/img/etherhiding/08f4fbdd661575473b3d2ded5c98f2e1-1.png)

![028fe7e4786f325cdb08c5e00ef43eb8.png](/assets/img/etherhiding/028fe7e4786f325cdb08c5e00ef43eb8-1.png)

**Obfuscated / Deobfuscated**

![bc5630200016e4a7b17f2539799da48e.png](/assets/img/etherhiding/bc5630200016e4a7b17f2539799da48e-1.png)

From observing the second script, three non-obvious things caught my eye: the `allow="clipboard-write"` attribute and the two cookies `_cf_verified` and `_wp_perf_ok`.

- **`clipboard-write`** is a big tell, since a legitimate CAPTCHA never needs to write to your clipboard. **(ClickFix command/payload written to clipboard)**
- **`_cf_verified`** disguises itself as a legitimate Cloudflare CAPTCHA cookie, but it's malicious. **(Checks whether this person has already been shown the fake CAPTCHA)**
- **`_wp_perf_ok`** disguises itself under a legitimate-sounding name, imitating a WordPress performance plugin to avoid detection. **(Checks whether this person has already been shown the fake CAPTCHA)**

### 3\. `eth_call` Requests Are Built and Sent | `Stage 1`

The `"to"` field is the attacker's contract, `"data"` means "run the function that returns the stored text," and `"latest"` means "use the newest version."

These are the `eth_call` (JSON-RPC) contract configs used to retrieve the malicious data:

**Script 1**

```text
jsonrpc:    2.0
method:     eth_call
params.to:  0xb90658783fDa2E726C5756f94A461291C0cef691   // Dead-drop contract
params.data: 0x3bc5de30                                   // Function to call
block:      latest
id:         1
```

**Script 2**

```text
jsonrpc:    2.0
method:     eth_call
params.to:  0x08207B087F61d7e95E441E15fd6d40BEfd6eD308   // Dead-drop contract
params.data: 0x38bcdc1c                                   // Function to call
block:      latest
id:         1
```

These `eth_call` requests went to the following RPC endpoints, as they were the only ones that replied with stored data:

- `hxxps[://]polygon[.]drpc[.]org/` - 2 calls
- `hxxps[://]polygon-bor-rpc[.]publicnode[.]com/` — 1 call

![adff5d42af531e278cdca4e5d8683867.png](/assets/img/etherhiding/adff5d42af531e278cdca4e5d8683867-1.png)

Looking at the response timings, we can observe the chronological order of the contract requests:

1.  `polygon-bor-rpc[.]publicnode[.]com` (231 bytes | 133 ms)
2.  `polygon[.]drpc[.]org` (230 bytes / 204 ms)
3.  `polygon[.]drpc[.]org` (358 bytes / 214 ms)

### 4\. RPC Endpoint Responses from `eth_call` (Decoded and Delivered) | `Stage 1`

**Response 1**

- **RPC endpoint:** `hxxps[://]polygon-bor-rpc[.]publicnode[.]com/`
- **Contract:** `0x08207B087F61d7e95E441E15fd6d40BEfd6eD308`

```text
jsonrpc: 2.0
id: 1
result: 0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000019646565722e616c6261696b6d656e756f6e6c696e652e636f6d00000000000000
```

**Hex decoded:** `deer[.]albaikmenuonline[.]com`

![349b3b75862b179c5922c2f0d2457a38.png](/assets/img/etherhiding/349b3b75862b179c5922c2f0d2457a38-1.png)

**Response 2**

- **RPC endpoint:** `hxxps[://]polygon[.]drpc[.]org/`
- **Contract:** `0xb90658783fDa2E726C5756f94A461291C0cef691`

```text
jsonrpc: 2.0
id: 1
result: 0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000019646565722e616c6261696b6d656e756f6e6c696e652e636f6d00000000000000
```

**Hex decoded:** `deer[.]albaikmenuonline[.]com`

**Response 3**

- **RPC endpoint:** `hxxps[://]polygon[.]drpc[.]org/`
- **Contract:** `0xb90658783fDa2E726C5756f94A461291C0cef691`

```text
jsonrpc: 2.0
id: 1
result: 0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000005f496f6b496d75336b726a6d7358375a656851536557725542395f4e73327779715273397532465f686433766d6a637546345632784f7252416a775a6c5a34627669715635734447674d5f4d446c6765304533543662395363386879774d366f00
```

**Hex decoded (encrypted Base64URL):**

```text
_IokImu3krjmsX7ZehQSeWrUB9_Ns2wyqRs9u2F_hd3vmjcuF4V2xOrRAjwZlZ4bviqV5sDGgM_MDlge0E3T6b9Sc8hywM6o
```

![57611d87f473d76b2724b1ef09a8e9ed.png](/assets/img/etherhiding/57611d87f473d76b2724b1ef09a8e9ed-1.png)

### RPC Endpoint Response Findings and Analysis

#### `deer[.]albaikmenuonline[.]com`

Observing the requests involving this newly discovered domain, we can see:

- An API **POST** request to the endpoint `beacon`, which looks to be a heartbeat.
- An API **GET** request to the endpoint `api`, an OS check to see whether you match their target (in this case, Windows users).

![0902af25bf2c7686dba939650366d0bf.png](/assets/img/etherhiding/0902af25bf2c7686dba939650366d0bf-1.png)

![ca8d299ad2a712438aeaaa49dd7e0322.png](/assets/img/etherhiding/ca8d299ad2a712438aeaaa49dd7e0322-1.png)

**API GET response rundown (threat actor's targeting config):**

- Only Windows users are being attacked right now. Mac, Linux, Android and iOS are all turned off.
- Windows victims get `/landing/windows.html`, the fake CAPTCHA page. Linux is also set to the Windows page, but Linux is switched off.
- Pages exist for other platforms (Mac, Android, iOS), so the kit supports them and the attacker can enable them at any time.

**Response in plain text (from JSON):**

| Setting                   | Value                                                                                                           |
| ------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Enabled                   | Yes                                                                                                             |
| Set cookies               | Yes                                                                                                             |
| Cookie version            | 1                                                                                                               |
| Skip CAPTCHA              | No                                                                                                              |
| Show to Windows users     | Yes                                                                                                             |
| Show to Mac users         | No                                                                                                              |
| Show to Linux users       | No                                                                                                              |
| Show to Android users     | No                                                                                                              |
| Show to iPhone/iPad users | No                                                                                                              |
| Windows landing page      | `/landing/windows.html?_k=845c7760b59deb18ae395d44419e0f1e2a2f`                                                 |
| Mac landing page          | `/landing/mac.html?_k=845c7760b59deb18ae395d44419e0f1e2a2f`                                                     |
| Linux landing page        | `/landing/windows.html?_k=845c7760b59deb18ae395d44419e0f1e2a2f`                                                 |
| Android landing page      | `/landing/android.html?_k=845c7760b59deb18ae395d44419e0f1e2a2f`                                                 |
| iOS landing page          | `/landing/ios.html?_k=845c7760b59deb18ae395d44419e0f1e2a2f`                                                     |
| Windows rules             | None                                                                                                            |
| Mac rules                 | None                                                                                                            |
| Linux rules               | None                                                                                                            |
| Android rules             | None                                                                                                            |
| iOS rules                 | One rule (switched off) for iOS 19 and below, using `/landing/ios.html?_k=845c7760b59deb18ae395d44419e0f1e2a2f` |

* * *

#### `_IokImu3krjmsX7ZehQSeWrUB9_Ns2wyqRs9u2F_hd3vmjcuF4V2xOrRAjwZlZ4bviqV5sDGgM_MDlge0E3T6b9Sc8hywM6o`

Since this response came from contract `0xb90658783fDa2E726C5756f94A461291C0cef691`, we can use the key found in the first script, `JtjOz1KWzihFtqt4GY7eOyqsZZ48iI`, to decrypt it. I used Claude AI to help create a CyberChef recipe, since the output kept coming out jumbled and I knew I was missing something.

Claude decrypted it by calculating the combined keystream from the key `JtjOz1KWzihFtqt4GY7eOyqsZZ48iI` and pasting it into the recipe as a hex key covering 256 bytes. The recipe:

1.  **Find / Replace** removes the leading `0x`.
2.  **From Hex** turns the hex into raw bytes.
3.  **Drop bytes (64)** removes the blockchain header (32 bytes of offset plus 32 bytes of length).
4.  **Remove null bytes** strips the zero padding at the end.
5.  **From Base64** decodes using the URL-safe alphabet (`-` and `_`).
6.  **XOR** applies the calculated keystream.

![47e173383b660e40a6da38b6287f1143.png](/assets/img/etherhiding/47e173383b660e40a6da38b6287f1143-1.png)

After decoding, we discovered three new domains that appear to be further attacker servers hosting the next stage:

- `netweblabs[.]com`
- `pluginyardware[.]com`
- `thumbinfo[.]net`

* * *

### Corroboration

Looking back at the URLScan results, we can see one of the same domains serving the JS script `all.min.js`.

![9700d759c447ea4ea1a2ddd03e066d44.png](/assets/img/etherhiding/9700d759c447ea4ea1a2ddd03e066d44.png)

Going back to the first script, we can also see that exact same JS file referenced, back when we didn't know what it did.

**Bottom of Script 1**

![0f56260305e1e813b5ec821b19d640ca.png](/assets/img/etherhiding/0f56260305e1e813b5ec821b19d640ca.png)

![9a7a9a66c2a25b51f59f6d0080e2bb16.png](/assets/img/etherhiding/9a7a9a66c2a25b51f59f6d0080e2bb16.png)

The decoded value is one or more semicolon-separated (`;`) domains. The script appends `/js/all.min.js?m=1` to each domain and injects them as deferred `<script>` tags. This tells the browser to **download the JavaScript file in the background** and **execute it only after the page has been fully parsed.**

It then tries every URL with a 3-second timeout, retries with a 6-second timeout, sets `window.currentServer` to the attempted URL, and starts **Stage 2**:

- `hxxps[://]netweblabs[.]com/js/all.min.js?m=1`
- `hxxps[://]pluginyardware[.]com/js/all.min.js?m=1`
- `hxxps[://]thumbinfo[.]net/js/all.min.js?m=1`

* * *

### 5\. Loads ClickFix (Payload) | `Stage 2`

From the corroboration above, we can see the C2 servers being requested with the same response size and containing the same data:

![0f6a91c992960f81adbeee694c8d8bb4.png](/assets/img/etherhiding/0f6a91c992960f81adbeee694c8d8bb4.png)

Lo and behold... another obfuscated JS script, of course -\_-

This makes it the third and final script.

#### Script 3

![cbc1d583ef3b9cc66ac3f223fae0b150.png](/assets/img/etherhiding/cbc1d583ef3b9cc66ac3f223fae0b150.png)

**Deobfuscated**

![5d9cdb8b704d12b0db032a12b7abf5fd.png](/assets/img/etherhiding/5d9cdb8b704d12b0db032a12b7abf5fd.png)

After analysing and deconstructing Script 3, we identified the following steps:

1.  **Fingerprint.** The script sends `GET /first_allow_host` (JSONP) with the user agent, platform, CPU cores, RAM, site origin, language, browser, `method=1`, and the C2 origin. The server decides whether to attack this victim (`allow`), assigns a victim `id`, and returns the command template in `payload`.
    
    > Basically, it asks the server to confirm this is a valid target before loading the fake CAPTCHA/ClickFix.
    
2.  **Fake Cloudflare page.** The script locks scrolling, sets the title to "Just a moment…", and draws a full-screen overlay (`z-index: 2147483647`).
    
    > At this point, it displays the fake CAPTCHA and waits for the user to click to "verify".
    
3.  **Checkbox click, the core of the attack.** Clicking the checkbox:
    - Copies the malicious command to the clipboard (`navigator.clipboard.writeText`, with an `execCommand('copy')` fallback).
    - Enables anti-analysis measures and reports `/click_continue`.
    - After 2 seconds, expands the widget with instructions: **Win+X** -> **I** (Terminal/PowerShell) -> **Ctrl+V** -> **Enter**.
    - Logs `/click_win` to the C2 whenever the Windows key is pressed.
4.  **Waiting for execution.** Every 5 seconds it polls `/check_allow_host?id=`. Once the server reports `allow: false`, most likely because the pasted command has beaconed back with the victim ID, it hides the overlay and reloads the page.

This is how EtherHiding is used to deploy malvertising techniques like ClickFix/FakeCaptcha.

| Type                              | Value                                                                                           |
| --------------------------------- | ----------------------------------------------------------------------------------------------- |
| C2 domain                         | `netweblabs[.]com`                                                                              |
| Stage-2 URL                       | `hxxps[://]netweblabs[.]com/js/all.min.js?m=1`                                                  |
| Endpoint: fingerprint and payload | `/first_allow_host?callback=&ua=&platform=&cpu=&ram=&origin=&language=&browser=&method=&layer=` |
| Endpoint: polling                 | `/check_allow_host?callback=&id=`                                                               |
| Endpoint: telemetry               | `/click_download`, `/click_continue`, `/click_win` (all `?callback=&id=`)                       |

### Screenshots from Dynamic Analysis

![64e63ae7aa54c4fc3f92d4bd6fb8343d.png](/assets/img/etherhiding/64e63ae7aa54c4fc3f92d4bd6fb8343d.png)

**Image 1:** The polling requests come from functions `_0x8f_0x1cb` and `_0x5_0xe4b` in `all.min.js?m=1`, matching the deobfuscated code.

![527f8a57824fd51d421af7459d5be02b.png](/assets/img/etherhiding/527f8a57824fd51d421af7459d5be02b.png)

**Image 2:** The fake Cloudflare CAPTCHA reports the checkbox click to the C2 via `/click_continue` (victim ID `27431`, `45.86.230[.]47`).

![b057c197819c39d5a1c01a6b15c30d06.png](/assets/img/etherhiding/b057c197819c39d5a1c01a6b15c30d06.png)

**Image 3:** The page polls `/check_allow_host` every 5 seconds, waiting for the pasted command to run.

* * *

## Bonus: Quick ClickFix Command Analysis

![aed775ec5b6ef7b902c428972dbfbbf9.png](/assets/img/etherhiding/aed775ec5b6ef7b902c428972dbfbbf9.png)

### ClickFix Command Breakdown

1.  Shows a fake update banner with an ID that matches the CAPTCHA, so it looks legitimate.
2.  Downloads a ZIP from `netweblabs[.]com/get_verify?i=27431&m=1`.
3.  Unzips it into `C:\Windows\Temp\f9804df4384d34e0\`.
4.  Waits 4–12 seconds, then runs `1.bat`, which launches `upnpcont.exe`, the actual malware.
5.  The malware (Most commonly Information Stealers) then carries out the threat actor's operations to achieve their goal.

| Type              | Value                                                     |
| ----------------- | --------------------------------------------------------- |
| Payload URL       | `hxxps[://]netweblabs[.]com/get_verify?i=27431&m=1`       |
| Drop folder       | `C:\Windows\Temp\f9804df4384d34e0\`                       |
| Files             | `1.bat`, `upnpcont.exe` (plus any other files in the ZIP) |
| Instance / Ray ID | `f9804df4384d34e0`                                        |
| Victim ID         | `27431`                                                   |

I'd like to dig into the third stage of the attack, but that will have to be another post involving malware analysis.

  
Thanks for reading :) 

&nbsp;

**References**

1.  **Google Cloud (GTIG)**, "DPRK Adopts EtherHiding: Nation-State Malware Hiding on Blockchains":  
    https://cloud.google.com/blog/topics/threat-intelligence/dprk-adopts-etherhiding  
    <br/>
2.  **GBHackers**:  
    https://gbhackers.com/north-korean-hackers-2/  
    <br/>
3.  **CSO Online**, "North Korean threat actors turn blockchains into malware delivery servers":  
    https://www.csoonline.com/article/4074916/north-korean-threat-actors-turn-blockchains-into-malware-delivery-servers.html

&nbsp;

**Tools Used**

1.  **Obfuscator.io Deobfuscator**  
    https://obf-io.deobfuscate.io  
    <br/>
2.  **Cyberchef  
    **https://gchq.github.io/CyberChef/  
    <br/>Recipie Used:  
    
    ```Chef
    Find_/_Replace({'option':'Regex','string':'^0x'},'',true,false,true,false)
    From_Hex('None')
    Drop_bytes(0,64,false)
    Remove_null_bytes()
    From_Base64('A-Za-z0-9-_',true,false)
    XOR({'option':'Hex','string':'4afd7cea9ede8116c23ac229e066f23bd772d99003b637c232bb1eab65ce580b8af8acec8f24d048d037ee740049e580e79e11c445d040c92cb973dc66199806bafa9d32de56de45fc820e57f38ef5ac1fd253de4ed73ac781ea7427a614c808ab40ec64ec530a901c65019c03ba2de061ec5ce548d58ff88235b422d616b94efa72fa61189e2a730faa11c83bee6ffa6af356e39d069043c230e424c75c0880086f26ac38811db81fd649fc7d08780164f1ab149e51d03ef232d56a168e167d34ba468f2bc62de4570a8b16860f72ffb922ac5fde4c0040e378249c248b42c8549d39d43bf265189924941d800dc730ba6dec5a0e4ef18632aa329950d662ab'},'Standard',false)
    Defang_URL(true,true,true,'Valid domains and full URLs')
    
    ```
    
3.  urlscan.io  
    https://urlscan.io
4.  Claude AI  
    https://claude.ai/new
