#!/usr/bin/env python3
"""
Fetch threat intelligence feeds and write a compact summary for the
Threat Intel page at assets/data/threat-intel.json.

Sources
  - CISA Known Exploited Vulnerabilities (KEV) catalog. No key needed.
  - abuse.ch ThreatFox (optional). Only used when ABUSECH_AUTH_KEY is set.
  - abuse.ch URLhaus list of currently online malware URLs. No key needed.
  - IOC search only, no keys needed: abuse.ch Feodo Tracker, MalwareBazaar
    and SSLBL, Spamhaus DROP, Emerging Threats compromised IPs, Blocklist.de,
    CINS Army and the Tor exit node list.
  - Government feeds for the IOC search: indicators from CISA cybersecurity
    advisories (STIX files) and CIRCL's OSINT MISP feed (TLP:CLEAR only).

It also writes assets/data/ioc-index.json, the indicator list behind the
page's IOC search. Searches run in the reader's browser against that file,
so the auth key is never exposed and nothing a reader types leaves the page.

Standard library only, so it runs on a bare GitHub Actions runner.
If a fetch fails, the existing JSON file is left untouched so the page
keeps showing the last good snapshot instead of breaking the build.

Usage:
  python3 tools/fetch_threat_intel.py
  python3 tools/fetch_threat_intel.py --kev-file kev.json   # offline/testing
"""

import argparse
import csv
import html
import json
import os
import re
import sys
import urllib.request
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

OUT_PATH = Path(__file__).resolve().parent.parent / "assets" / "data" / "threat-intel.json"
IOC_PATH = OUT_PATH.with_name("ioc-index.json")

KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # CISA's official GitHub mirror, used if the main site is unreachable
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_ONLINE_CSV = "https://urlhaus.abuse.ch/downloads/csv_online/"
# Extra IOC search feeds. All are free to use; none needs a key.
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
BAZAAR_URL = "https://bazaar.abuse.ch/export/csv/recent/"
SSLBL_URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop_v4.json"
ET_COMPROMISED_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
BLOCKLIST_DE_URL = "https://lists.blocklist.de/lists/all.txt"
CINS_URL = "https://cinsscore.com/list/ci-badguys.txt"
TOR_EXIT_URL = "https://check.torproject.org/torbulkexitlist"
# Government feeds for the IOC search
CISA_SITEMAP_URL = "https://www.cisa.gov/sitemap.xml"
CISA_RSS_URL = "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml"
CISA_ADVISORY_URL = "https://www.cisa.gov/news-events/cybersecurity-advisories/{}"
CIRCL_FEED_URL = "https://www.circl.lu/doc/misp/feed-osint/"
USER_AGENT = "Cyber-Weblog-ThreatIntel/1.0 (+https://gelato07.github.io)"

RECENT_LIMIT = 75
MONTHS_OF_HISTORY = 24

# ---------------------------------------------------------------------------
# Weakness categorisation
# ---------------------------------------------------------------------------
# Each KEV entry is placed in one category, based on its CWE IDs first.
# Generic CWEs (e.g. CWE-20 "Improper Input Validation") say little about the
# attack, so for those we fall back to keywords in the vulnerability name.

CATEGORIES = {
    "Memory corruption": [
        787, 416, 119, 122, 125, 190, 121, 120, 843, 415, 822, 824, 476, 191,
        680, 763, 823, 124, 126, 127, 131, 789, 189, 1284, 457, 908, 681,
    ],
    "Command & code injection": [78, 94, 77, 74, 88, 95, 917, 1336, 96, 97, 138, 116, 1321],
    "SQL injection": [89, 564],
    "Authentication bypass": [287, 306, 288, 290, 798, 1188, 294, 302, 303, 305, 307, 640, 521, 522, 1390, 1391, 347, 295, 345],
    "Access control & privilege escalation": [284, 264, 863, 269, 862, 276, 285, 732, 250, 266, 668, 639, 281, 267, 1220],
    "Path traversal & file handling": [22, 23, 59, 434, 36, 73, 24, 35, 29, 552, 98, 61, 427, 426],
    "Insecure deserialization": [502],
    "Web client-side (XSS, CSRF, redirects)": [79, 352, 601, 1021, 80],
    "Server-side request forgery": [918],
    "Information disclosure": [200, 209, 532, 538, 215, 497, 201, 203],
    "Security feature bypass": [693, 184, 358, 1390],
    "Backdoors & supply chain": [506, 912, 494, 829],
}

# CWEs too generic to classify on their own
GENERIC_CWES = {"CWE-20", "CWE-399", "CWE-400", "CWE-404", "CWE-754", "CWE-703", "CWE-noinfo", "CWE-Other"}

KEYWORDS = [  # checked in order, first match wins
    ("SQL injection", ["sql injection"]),
    ("Insecure deserialization", ["deserializ"]),
    ("Server-side request forgery", ["server-side request forgery", "ssrf"]),
    ("Web client-side (XSS, CSRF, redirects)", ["cross-site scripting", "xss", "cross-site request forgery", "csrf", "open redirect"]),
    ("Path traversal & file handling", ["path traversal", "directory traversal", "file upload", "arbitrary file"]),
    ("Memory corruption", ["use-after-free", "use after free", "buffer overflow", "out-of-bounds", "memory corruption",
                           "heap", "type confusion", "integer overflow", "double free", "stack overflow", "null pointer"]),
    ("Command & code injection", ["command injection", "code injection", "os command", "injection"]),
    ("Authentication bypass", ["authentication bypass", "hard-coded", "hardcoded", "missing authentication",
                               "improper authentication", "default credential"]),
    ("Access control & privilege escalation", ["privilege escalation", "elevation of privilege", "access control",
                                               "authorization", "permission"]),
    ("Information disclosure", ["information disclosure", "information leak", "exposure of sensitive"]),
    ("Backdoors & supply chain", ["backdoor", "embedded malicious", "supply chain"]),
    ("Security feature bypass", ["security feature bypass", "bypass"]),
]
OTHER = "Other / unspecified"

CWE_TO_CATEGORY = {f"CWE-{n}": cat for cat, nums in CATEGORIES.items() for n in nums}


def categorise(vuln):
    for cwe in vuln.get("cwes") or []:
        cwe = cwe.replace("NVD-", "")
        if cwe in GENERIC_CWES:
            continue
        if cwe in CWE_TO_CATEGORY:
            return CWE_TO_CATEGORY[cwe]
    text = f"{vuln.get('vulnerabilityName', '')} {vuln.get('shortDescription', '')}".lower()
    for category, words in KEYWORDS:
        if any(w in text for w in words):
            return category
    return OTHER


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

def http_json(url, data=None, headers=None, timeout=60):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def http_text(url, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def fetch_kev():
    last_error = None
    for url in KEV_URLS:
        try:
            data = http_json(url)
            if data.get("vulnerabilities"):
                print(f"KEV: {len(data['vulnerabilities'])} entries from {url}")
                return data
        except Exception as exc:  # noqa: BLE001 - we want to try the next mirror on any failure
            last_error = exc
            print(f"KEV: failed to fetch {url}: {exc}", file=sys.stderr)
    raise RuntimeError(f"Could not fetch KEV catalog: {last_error}")


def fetch_threatfox(auth_key, days=7):
    body = json.dumps({"query": "get_iocs", "days": days}).encode()
    data = http_json(THREATFOX_URL, data=body, headers={"Auth-Key": auth_key, "Content-Type": "application/json"})
    if data.get("query_status") != "ok":
        raise RuntimeError(f"ThreatFox query_status={data.get('query_status')}")
    return data.get("data") or []


def fetch_urlhaus_online():
    text = http_text(URLHAUS_ONLINE_CSV)
    rows = list(csv.reader(line for line in text.splitlines() if line and not line.startswith("#")))
    if not rows:
        raise RuntimeError("URLhaus returned no rows")
    return rows


# ---------------------------------------------------------------------------
# Summarising
# ---------------------------------------------------------------------------

def parse_day(s):
    return datetime.strptime(s[:10], "%Y-%m-%d").date()


def month_key(d):
    return f"{d.year:04d}-{d.month:02d}"


def last_n_months(today, n):
    keys, y, m = [], today.year, today.month
    for _ in range(n):
        keys.append(f"{y:04d}-{m:02d}")
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    return list(reversed(keys))


def ranked(counter, limit=None):
    return [{"label": k, "count": v} for k, v in counter.most_common(limit)]


def summarise_kev(kev, today):
    vulns = kev["vulnerabilities"]
    year_ago = today - timedelta(days=365)
    month_ago = today - timedelta(days=30)

    for v in vulns:
        v["_date"] = parse_day(v["dateAdded"])
        v["_category"] = categorise(v)
        v["_ransomware"] = v.get("knownRansomwareCampaignUse", "").strip().lower() == "known"

    last_year = [v for v in vulns if v["_date"] > year_ago]

    months = last_n_months(today, MONTHS_OF_HISTORY)
    monthly_total = Counter(month_key(v["_date"]) for v in vulns)
    monthly_ransom = Counter(month_key(v["_date"]) for v in vulns if v["_ransomware"])

    vendor_counts = Counter(v["vendorProject"].strip() for v in last_year)
    top_vendor = vendor_counts.most_common(1)[0] if vendor_counts else None

    recent = sorted(vulns, key=lambda v: (v["_date"], v["cveID"]), reverse=True)[:RECENT_LIMIT]

    return {
        "catalog_version": kev.get("catalogVersion"),
        "catalog_released": kev.get("dateReleased"),
        "totals": {
            "all": len(vulns),
            "last_30_days": sum(1 for v in vulns if v["_date"] > month_ago),
            "last_365_days": len(last_year),
            "ransomware_all": sum(1 for v in vulns if v["_ransomware"]),
            "ransomware_365_days": sum(1 for v in last_year if v["_ransomware"]),
        },
        "top_vendor_365_days": {"label": top_vendor[0], "count": top_vendor[1]} if top_vendor else None,
        "categories": {
            "all": ranked(Counter(v["_category"] for v in vulns)),
            "last_365_days": ranked(Counter(v["_category"] for v in last_year)),
        },
        "monthly": [
            {"month": m, "total": monthly_total.get(m, 0), "ransomware": monthly_ransom.get(m, 0)} for m in months
        ],
        "vendors_365_days": ranked(vendor_counts, 10),
        "recent": [
            {
                "cve": v["cveID"],
                "vendor": v["vendorProject"],
                "product": v["product"],
                "name": v["vulnerabilityName"],
                "date_added": v["dateAdded"],
                "due_date": v.get("dueDate"),
                "ransomware": v["_ransomware"],
                "category": v["_category"],
                "description": (v.get("shortDescription") or "")[:400],
            }
            for v in recent
        ],
    }


THREAT_TYPE_LABELS = {
    "botnet_cc": "botnet C2 servers",
    "payload_delivery": "payload delivery sites",
    "payload": "malware payloads",
    "cc_skimming": "card skimming sites",
}


def summarise_threatfox(iocs, days):
    families = Counter(
        (i.get("malware_printable") or "Unknown").strip()
        for i in iocs
        if (i.get("malware_printable") or "").lower() not in ("", "unknown malware", "unknown")
    )
    types = Counter(
        THREAT_TYPE_LABELS.get(i.get("threat_type"), (i.get("threat_type") or "other").replace("_", " "))
        for i in iocs
    )
    return {
        "window_days": days,
        "total_iocs": len(iocs),
        "families": ranked(families, 10),
        "threat_types": ranked(types),
    }


# ---------------------------------------------------------------------------
# IOC search index
# ---------------------------------------------------------------------------
# Rows are short arrays to keep the file small:
#   [value, type, family, threat type, compromised (0/1), first seen, source, source id, tags]
# Values are lowercased so the page can match them exactly.

SRC_THREATFOX, SRC_URLHAUS = "tf", "uh"
SRC_FEODO, SRC_BAZAAR, SRC_SSLBL = "feodo", "mb", "sslbl"
SRC_CISA, SRC_CIRCL = "cisa", "circl"
IOC_TYPES = {"ip:port": "ip", "domain": "domain", "url": "url",
             "md5_hash": "md5", "sha1_hash": "sha1", "sha256_hash": "sha256"}


def threatfox_rows(iocs, families):
    rows = []
    for i in iocs:
        kind = IOC_TYPES.get(i.get("ioc_type"))
        value = (i.get("ioc") or "").strip().lower()
        if not kind or not value:
            continue
        name = (i.get("malware_printable") or "").strip()
        if name.lower() in ("", "unknown malware", "unknown"):
            name = ""
        malpedia = i.get("malware_malpedia") or ""
        if malpedia.rstrip("/").endswith("/unknown"):
            malpedia = ""
        fam = families.setdefault(name, [name, malpedia])[0] if name else ""
        rows.append([
            value, kind, fam, i.get("threat_type") or "", 1 if i.get("is_compromised") else 0,
            (i.get("first_seen") or "")[:10], SRC_THREATFOX, str(i.get("id") or ""),
            ",".join((i.get("tags") or [])[:6]),
        ])
    return rows


def urlhaus_rows(csv_rows):
    rows = []
    for r in csv_rows:
        if len(r) < 7:
            continue
        uid, added, url, threat, tags = r[0], r[1], r[2].strip().lower(), r[5], r[6]
        if not url:
            continue
        tags = "" if tags == "None" else tags
        rows.append([url, "url", "", threat, 0, added[:10], SRC_URLHAUS, uid, tags])
    return rows


# Extra row feeds: indicators with context (malware family, file name, listing reason)

def feodo_rows():
    rows = []
    for e in http_json(FEODO_URL):
        ip, port = (e.get("ip_address") or "").strip(), e.get("port")
        if not ip:
            continue
        tags = [e.get("status") or "", e.get("as_name") or "", e.get("country") or ""]
        rows.append([f"{ip}:{port}" if port else ip, "ip", e.get("malware") or "", "botnet_cc", 0,
                     (e.get("first_seen") or "")[:10], SRC_FEODO, ip, ",".join(t for t in tags if t)])
    return rows


def bazaar_rows():
    reader = csv.reader((line for line in http_text(BAZAAR_URL).splitlines() if line and not line.startswith("#")),
                        skipinitialspace=True)
    rows = []
    for r in reader:
        if len(r) < 9:
            continue
        seen, sha256, md5, sha1, name, ftype, sig = r[0], r[1], r[2], r[3], r[5], r[6], r[8]
        sig = "" if sig in ("n/a", "") else sig
        tags = ",".join(t.replace(",", " ") for t in (name, ftype) if t and t != "n/a")
        for value, kind in ((sha256, "sha256"), (md5, "md5"), (sha1, "sha1")):
            if value:
                rows.append([value.lower(), kind, sig, "payload", 0, seen[:10], SRC_BAZAAR, sha256.lower(), tags])
    return rows


def sslbl_rows():
    rows = []
    for r in csv.reader(line for line in http_text(SSLBL_URL).splitlines() if line and not line.startswith("#")):
        if len(r) < 3:
            continue
        listed, sha1, reason = r[0], r[1].strip().lower(), r[2].strip()
        family = reason[:-4].strip() if reason.endswith(" C&C") else ""
        if family.lower() == "malware":  # SSLBL's generic label, not a family
            family = ""
        rows.append([sha1, "sslcert", family, "ssl_c2", 0, listed[:10], SRC_SSLBL, sha1, reason])
    return rows


# Value-only lists: plain IP (or CIDR) blocklists without per-entry context.
# "level" sets the verdict a match gives: malicious, suspicious or info.

IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def plain_ips(url):
    return sorted({line.strip() for line in http_text(url).splitlines()
                   if line.strip() and not line.startswith("#") and IPV4.match(line.strip())})


def spamhaus_drop():
    values = []
    for line in http_text(SPAMHAUS_DROP_URL).splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if entry.get("cidr"):
            values.append(f"{entry['cidr']}|{entry.get('sblid', '')}")
    return values


LISTS = [
    {"id": "drop", "name": "Spamhaus DROP", "kind": "cidr", "level": "malicious",
     "link": "https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
     "desc": "Inside an IP range Spamhaus lists as hijacked or run by criminals. Traffic to or from it should be dropped.",
     "fetch": spamhaus_drop},
    {"id": "et", "name": "Emerging Threats compromised IPs", "kind": "ip", "level": "suspicious",
     "link": "https://rules.emergingthreats.net/",
     "desc": "Known compromised or hostile host, listed by Proofpoint Emerging Threats.",
     "fetch": lambda: plain_ips(ET_COMPROMISED_URL)},
    {"id": "blde", "name": "Blocklist.de", "kind": "ip", "level": "suspicious",
     "link": "https://www.blocklist.de/en/index.html",
     "desc": "Reported for attacks such as SSH, mail or web login brute forcing in the last 48 hours.",
     "fetch": lambda: plain_ips(BLOCKLIST_DE_URL)},
    {"id": "cins", "name": "CINS Army", "kind": "ip", "level": "suspicious",
     "link": "https://cinsscore.com/",
     "desc": "Poor-reputation IP seen attacking networks protected by Sentinel IPS.",
     "fetch": lambda: plain_ips(CINS_URL)},
    {"id": "tor", "name": "Tor exit nodes", "kind": "ip", "level": "info",
     "link": "https://metrics.torproject.org/rs.html",
     "desc": "A Tor exit node: the traffic came through the Tor network. Not malicious by itself, but the real source is hidden.",
     "fetch": lambda: plain_ips(TOR_EXIT_URL)},
]

ROW_FEEDS = [  # (source id, display name, fetch) for feeds fetched inside the index build
    (SRC_FEODO, "Feodo Tracker", feodo_rows),
    (SRC_BAZAAR, "MalwareBazaar", bazaar_rows),
    (SRC_SSLBL, "SSLBL", sslbl_rows),
]


# Government feeds. Each report is fetched once and its rows are carried over
# from the previous index, so a normal run only downloads new reports.

CISA_YEARS = 2          # advisories from this year and the previous two
CIRCL_DAYS = 365        # CIRCL events from the last year
CIRCL_MAX_NEW = 400     # cap on new CIRCL events fetched in one run
SHAREABLE_TLP = {"tlp:clear", "tlp:white"}

STIX_KINDS = [  # (substring of the STIX object path, IOC type)
    ("ipv4-addr", "ip"), ("domain-name", "domain"), ("url:", "url"),
    ("sha-256", "sha256"), ("sha256", "sha256"), ("sha-1", "sha1"), ("sha1", "sha1"), ("md5", "md5"),
]
STIX_TERM = re.compile(r"([a-z0-9-]+:[a-z0-9_.'-]+)\s*=\s*'([^']+)'", re.I)


def stix_indicators(bundle):
    found = set()
    for obj in bundle.get("objects", []):
        if obj.get("type") != "indicator":
            continue
        for path, value in STIX_TERM.findall(obj.get("pattern") or ""):
            path = path.lower()
            kind = next((k for key, k in STIX_KINDS if key in path), None)
            if kind:
                found.add((value.strip().lower(), kind))
    families = sorted({o.get("name", "") for o in bundle.get("objects", []) if o.get("type") == "malware" and o.get("name")})
    return found, families


def cisa_advisory_ids(today):
    """Advisory IDs like aa26-222a from CISA's sitemap and RSS feed."""
    text = ""
    try:
        index_xml = http_text(CISA_SITEMAP_URL)
        for child in re.findall(r"<loc>([^<]+sitemap[^<]*)</loc>", index_xml):
            text += http_text(child)
    except Exception as exc:  # noqa: BLE001 - the RSS feed alone still finds new advisories
        print(f"CISA: sitemap skipped ({exc})", file=sys.stderr)
    text += http_text(CISA_RSS_URL)
    oldest = (today.year - CISA_YEARS) % 100
    found = re.findall(r"cybersecurity-advisories/(aa(\d{2})-\d{3}[a-z])", text)
    return sorted({adv_id for adv_id, year in found if int(year) >= oldest}, reverse=True)


def cisa_advisory(adv_id):
    page_url = CISA_ADVISORY_URL.format(adv_id)
    page = http_text(page_url)
    title = re.search(r'<meta property="og:title" content="([^"]+)"', page) or re.search(r"<title>([^<|]+)", page)
    date = re.search(r'datetime="(\d{4}-\d{2}-\d{2})', page)
    report = {"title": re.sub(r"\s*\|\s*CISA$", "", html.unescape(title.group(1).strip())) if title else adv_id.upper(),
              "date": date.group(1) if date else "", "url": page_url, "source": "CISA"}
    stix = re.search(r'href="([^"]+stix[^"]*\.json)"', page, re.I)
    rows = []
    if stix:
        bundle = http_json(urljoin(page_url, html.unescape(stix.group(1))))
        indicators, families = stix_indicators(bundle)
        family = families[0] if len(families) == 1 else ""
        rows = [[v, k, family, "advisory", 0, report["date"], SRC_CISA, adv_id, ""] for v, k in sorted(indicators)]
    return report, rows


def misp_attributes(event):
    attrs = list(event.get("Attribute", []))
    for obj in event.get("Object", []):
        attrs += obj.get("Attribute", [])
    return attrs


MISP_KINDS = {"ip-dst": "ip", "ip-src": "ip", "domain": "domain", "hostname": "domain", "url": "url",
              "md5": "md5", "sha1": "sha1", "sha256": "sha256"}


def misp_values(attr):
    """(value, IOC type) pairs for one MISP attribute, splitting composite types like filename|sha256."""
    kind, value = attr.get("type", ""), (attr.get("value") or "").strip().lower()
    if not value:
        return []
    if kind in ("ip-dst|port", "ip-src|port"):
        ip, _, port = value.partition("|")
        return [(f"{ip}:{port}" if port else ip, "ip")]
    if "|" in kind:
        return [(v, MISP_KINDS[k]) for k, v in zip(kind.split("|"), value.split("|")) if k in MISP_KINDS]
    return [(value, MISP_KINDS[kind])] if kind in MISP_KINDS else []


def circl_event(uuid, entry):
    event = http_json(f"{CIRCL_FEED_URL}{uuid}.json")["Event"]
    attrs = misp_attributes(event)
    link = next((a.get("value") for a in attrs if a.get("type") == "link" and (a.get("value") or "").startswith("http")), None)
    report = {"title": entry.get("info", "")[:160], "date": entry.get("date", ""),
              "url": link or f"{CIRCL_FEED_URL}{uuid}.json", "source": "CIRCL"}
    found = {pair for a in attrs if a.get("to_ids") for pair in misp_values(a)}
    rows = [[v, k, "", "osint_report", 0, report["date"], SRC_CIRCL, uuid, ""] for v, k in sorted(found)]
    return report, rows


def incremental_feed(name, src, wanted, fetch_one, previous, max_new=None):
    """Keep previous rows for reports still wanted, fetch the reports not seen before.
    wanted: {report id: extra info passed to fetch_one}."""
    prev_reports = {k: v for k, v in previous.get("reports", {}).items() if v.get("src") == src}
    reports = {k: v for k, v in prev_reports.items() if k in wanted}
    rows = [r for r in previous.get("rows", []) if r[6] == src and r[7] in reports]
    new_ids = [k for k in wanted if k not in prev_reports][:max_new]
    failed = 0
    for rid in new_ids:
        try:
            report, new_rows = fetch_one(rid, wanted[rid])
        except Exception as exc:  # noqa: BLE001 - skip this report and retry it on the next run
            failed += 1
            print(f"{name}: {rid} skipped ({exc})", file=sys.stderr)
            continue
        reports[rid] = {**report, "src": src, "count": len(new_rows)}
        rows += new_rows
    print(f"{name}: {len(reports)} reports ({len(new_ids) - failed} new), {len(rows)} indicators")
    return reports, rows


def cisa_feed(today, previous):
    ids = cisa_advisory_ids(today)
    return incremental_feed("CISA advisories", SRC_CISA, {i: None for i in ids},
                            lambda rid, _: cisa_advisory(rid), previous)


def circl_feed(today, previous):
    manifest = http_json(f"{CIRCL_FEED_URL}manifest.json")
    cutoff = (today - timedelta(days=CIRCL_DAYS)).isoformat()
    wanted = {}
    for uuid, entry in manifest.items():
        tlp = {t.get("name", "") for t in entry.get("Tag", []) if t.get("name", "").startswith("tlp:")}
        # Only events marked for public sharing, and nothing with a stricter TLP tag alongside.
        # Maltrail's daily dumps are skipped: hundreds of thousands of honeypot IPs, not reports.
        if (entry.get("date", "") >= cutoff and tlp & SHAREABLE_TLP and not tlp - SHAREABLE_TLP
                and not entry.get("info", "").startswith("Maltrail IOC")):
            wanted[uuid] = entry
    wanted = dict(sorted(wanted.items(), key=lambda kv: kv[1].get("date", ""), reverse=True))
    return incremental_feed("CIRCL OSINT", SRC_CIRCL, wanted, circl_event, previous, CIRCL_MAX_NEW)


def build_ioc_index(now, tf_iocs, uh_csv):
    """Combine every feed. A feed that fails this run keeps its data from the last good index."""
    previous = {}
    try:
        previous = json.loads(IOC_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    prev_sources = previous.get("sources", {})
    stamp = now.isoformat(timespec="seconds")

    def prev_updated(src):
        info = prev_sources.get(src)
        return info if isinstance(info, str) else (info or {}).get("updated")

    families, sources, rows, lists = {}, {}, [], []

    def row_feed(src, name, get_rows):
        nonlocal rows
        fresh = None
        try:
            fresh = get_rows()
        except Exception as exc:  # noqa: BLE001
            print(f"{name}: skipped ({exc})", file=sys.stderr)
        if fresh:
            rows += fresh
            sources[src] = {"name": name, "updated": stamp, "count": len(fresh)}
            print(f"{name}: {len(fresh)} indicators")
        elif prev_updated(src):
            kept = [r for r in previous.get("rows", []) if r[6] == src]
            rows += kept
            sources[src] = {"name": name, "updated": prev_updated(src), "count": len(kept)}
            if src == SRC_THREATFOX:
                families.update({f[0]: f for f in previous.get("families", [])})

    row_feed(SRC_THREATFOX, "ThreatFox", lambda: None if tf_iocs is None else threatfox_rows(tf_iocs, families))
    row_feed(SRC_URLHAUS, "URLhaus", lambda: None if uh_csv is None else urlhaus_rows(uh_csv))
    for src, name, get_rows in ROW_FEEDS:
        row_feed(src, name, get_rows)

    reports = {}
    for src, name, feed in ((SRC_CISA, "CISA advisories", cisa_feed), (SRC_CIRCL, "CIRCL OSINT", circl_feed)):
        try:
            feed_reports, feed_rows = feed(now.date(), previous)
        except Exception as exc:  # noqa: BLE001 - keep everything from the last good index
            print(f"{name}: skipped ({exc})", file=sys.stderr)
            feed_reports = {k: v for k, v in previous.get("reports", {}).items() if v.get("src") == src}
            feed_rows = [r for r in previous.get("rows", []) if r[6] == src]
            if not feed_reports:
                continue
            sources[src] = {"name": name, "updated": prev_updated(src), "count": len(feed_rows)}
        else:
            sources[src] = {"name": name, "updated": stamp, "count": len(feed_rows)}
        reports.update(feed_reports)
        rows += feed_rows

    prev_lists = {l["id"]: l for l in previous.get("lists", [])}
    for spec in LISTS:
        meta = {k: v for k, v in spec.items() if k != "fetch"}
        values = None
        try:
            values = spec["fetch"]()
        except Exception as exc:  # noqa: BLE001
            print(f"{spec['name']}: skipped ({exc})", file=sys.stderr)
        if values:
            lists.append({**meta, "values": values})
            sources[spec["id"]] = {"name": spec["name"], "updated": stamp, "count": len(values)}
            print(f"{spec['name']}: {len(values)} entries")
        elif spec["id"] in prev_lists:
            lists.append({**meta, "values": prev_lists[spec["id"]]["values"]})
            sources[spec["id"]] = {"name": spec["name"], "updated": prev_updated(spec["id"]),
                                   "count": len(prev_lists[spec["id"]]["values"])}

    if not rows and not lists:
        return None
    total = len(rows) + sum(len(l["values"]) for l in lists)
    print(f"IOC index: {total} indicators from {len(sources)} feeds")
    return {
        "generated_at": stamp,
        "sources": sources,
        "families": sorted(families.values()),
        "rows": rows,
        "lists": lists,
        "reports": reports,
    }


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kev-file", help="read KEV JSON from a local file instead of downloading")
    parser.add_argument("--out", default=str(OUT_PATH), help="output path (default: %(default)s)")
    args = parser.parse_args()

    out_path = Path(args.out)
    now = datetime.now(timezone.utc)
    today = now.date()

    try:
        if args.kev_file:
            kev = json.loads(Path(args.kev_file).read_text(encoding="utf-8"))
        else:
            kev = fetch_kev()
        summary = {"generated_at": now.isoformat(timespec="seconds"), "kev": summarise_kev(kev, today)}
    except Exception as exc:  # noqa: BLE001
        # Keep the last good snapshot so a feed outage never breaks the site build
        print(f"ERROR: {exc}. Keeping existing {out_path} unchanged.", file=sys.stderr)
        return 0

    tf_iocs = None
    auth_key = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
    if auth_key:
        try:
            days = 7
            tf_iocs = fetch_threatfox(auth_key, days)
            summary["threatfox"] = summarise_threatfox(tf_iocs, days)
            print(f"ThreatFox: {summary['threatfox']['total_iocs']} IOCs in last {days} days")
        except Exception as exc:  # noqa: BLE001
            print(f"ThreatFox: skipped ({exc})", file=sys.stderr)
    else:
        print("ThreatFox: ABUSECH_AUTH_KEY not set, skipping")

    uh_csv = None
    try:
        uh_csv = fetch_urlhaus_online()
        print(f"URLhaus: {len(uh_csv)} online malware URLs")
    except Exception as exc:  # noqa: BLE001
        print(f"URLhaus: skipped ({exc})", file=sys.stderr)

    index = build_ioc_index(now, tf_iocs, uh_csv)
    if index:
        IOC_PATH.parent.mkdir(parents=True, exist_ok=True)
        IOC_PATH.write_text(json.dumps(index, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
        print(f"Wrote {IOC_PATH} ({IOC_PATH.stat().st_size / 1024:.1f} KB)")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {out_path} ({out_path.stat().st_size / 1024:.1f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
