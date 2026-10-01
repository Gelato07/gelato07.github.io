#!/usr/bin/env python3
"""
Fetch threat intelligence feeds and write a compact summary for the
Threat Intel page at assets/data/threat-intel.json.

Sources
  - CISA Known Exploited Vulnerabilities (KEV) catalog. No key needed.
  - abuse.ch ThreatFox (optional). Only used when ABUSECH_AUTH_KEY is set.
  - abuse.ch URLhaus list of currently online malware URLs. No key needed.

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
import json
import os
import sys
import urllib.request
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

OUT_PATH = Path(__file__).resolve().parent.parent / "assets" / "data" / "threat-intel.json"
IOC_PATH = OUT_PATH.with_name("ioc-index.json")

KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # CISA's official GitHub mirror, used if the main site is unreachable
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_ONLINE_CSV = "https://urlhaus.abuse.ch/downloads/csv_online/"
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
#   [value, type, family index, threat type, compromised (0/1), first seen, source, source id, tags]
# Values are lowercased so the page can match them exactly.

SRC_THREATFOX, SRC_URLHAUS = "tf", "uh"
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


def build_ioc_index(now, tf_iocs, uh_csv):
    """Combine both feeds. A feed that failed this run keeps its rows from the last good index."""
    previous = None
    try:
        previous = json.loads(IOC_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass

    families, sources, rows = {}, {}, []
    for src, fresh, convert in ((SRC_THREATFOX, tf_iocs, lambda d: threatfox_rows(d, families)),
                                (SRC_URLHAUS, uh_csv, urlhaus_rows)):
        if fresh is not None:
            rows += convert(fresh)
            sources[src] = now.isoformat(timespec="seconds")
        elif previous and src in previous.get("sources", {}):
            rows += [r for r in previous["rows"] if r[6] == src]
            sources[src] = previous["sources"][src]
            if src == SRC_THREATFOX:
                families.update({f[0]: f for f in previous.get("families", [])})

    if not rows:
        return None
    hosts = sum(1 for r in rows if r[1] == "url")
    print(f"IOC index: {len(rows)} indicators ({hosts} URLs) from {', '.join(sorted(sources))}")
    return {
        "generated_at": now.isoformat(timespec="seconds"),
        "sources": sources,
        "families": sorted(families.values()),
        "rows": rows,
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
