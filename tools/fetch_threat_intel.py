#!/usr/bin/env python3
"""Build the data snapshot behind the Threat Intel tab.

Downloads CISA's Known Exploited Vulnerabilities (KEV) catalog, summarises it,
and writes assets/data/threat-intel.json. The page reads that static file, so
readers' browsers never call a third-party API.

If CISA's site is down, CISA's GitHub mirror is tried instead. If both fail,
the existing snapshot is left untouched and the script exits 0, so a feed
outage never breaks a deploy.

Optional: set ABUSECH_AUTH_KEY to add ThreatFox malware-family counts for the
last 7 days. Only per-family counts are stored, never the indicators.

Standard library only, so it runs on a stock GitHub Actions runner.
"""

import json
import os
import sys
import urllib.request
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

KEV_SOURCES = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
]
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"

OUTPUT = Path(__file__).resolve().parent.parent / "assets" / "data" / "threat-intel.json"

LATEST_LIMIT = 200
TREND_MONTHS = 24
TOP_VENDORS = 10
TOP_FAMILIES = 12
USER_AGENT = "gelato07.github.io threat-intel builder"

GENERIC_TYPE = "Input validation (generic)"
OTHER_TYPE = "Other"
NO_CWE_TYPE = "No CWE assigned"
CATCH_ALLS = (GENERIC_TYPE, OTHER_TYPE, NO_CWE_TYPE)

# Attack types, checked in order. A vulnerability with several CWEs lands in the
# first type that matches, so the specific types come before the catch-alls.
ATTACK_TYPES = [
    ("Memory corruption", {
        "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125", "CWE-126",
        "CWE-129", "CWE-131", "CWE-190", "CWE-191", "CWE-193", "CWE-401", "CWE-415",
        "CWE-416", "CWE-476", "CWE-680", "CWE-704", "CWE-763", "CWE-787", "CWE-788",
        "CWE-822", "CWE-823", "CWE-824", "CWE-843", "CWE-908", "CWE-1284", "CWE-134",
        "CWE-189",
    }),
    ("Command / code injection", {
        "CWE-74", "CWE-77", "CWE-78", "CWE-88", "CWE-94", "CWE-95", "CWE-96", "CWE-97",
        "CWE-913", "CWE-917", "CWE-1321", "CWE-1336",
    }),
    ("Deserialization", {"CWE-502"}),
    ("Auth bypass / access control", {
        "CWE-250", "CWE-255", "CWE-259", "CWE-264", "CWE-266", "CWE-269", "CWE-276",
        "CWE-280", "CWE-281", "CWE-282", "CWE-284", "CWE-285", "CWE-287", "CWE-288",
        "CWE-289", "CWE-290", "CWE-294", "CWE-302", "CWE-303", "CWE-305", "CWE-306",
        "CWE-345", "CWE-346", "CWE-347", "CWE-425", "CWE-522", "CWE-639", "CWE-640",
        "CWE-648", "CWE-732", "CWE-798", "CWE-862", "CWE-863", "CWE-912", "CWE-1188",
        "CWE-1220", "CWE-1390",
    }),
    ("Path traversal / file handling", {
        "CWE-22", "CWE-23", "CWE-24", "CWE-29", "CWE-35", "CWE-36", "CWE-41", "CWE-59",
        "CWE-61", "CWE-73", "CWE-98", "CWE-426", "CWE-427", "CWE-434", "CWE-552", "CWE-610",
        "CWE-706", "CWE-1386",
    }),
    ("Web injection (SQLi, XSS, SSRF, XXE)", {
        "CWE-79", "CWE-80", "CWE-89", "CWE-91", "CWE-352", "CWE-601", "CWE-611",
        "CWE-776", "CWE-918", "CWE-943",
    }),
    ("Security feature bypass", {
        "CWE-184", "CWE-254", "CWE-295", "CWE-311", "CWE-326", "CWE-451", "CWE-494",
        "CWE-693", "CWE-807", "CWE-829",
    }),
    ("Information disclosure", {
        "CWE-200", "CWE-201", "CWE-209", "CWE-312", "CWE-319", "CWE-359", "CWE-532",
        "CWE-538",
    }),
    (GENERIC_TYPE, {"CWE-20", "CWE-1287"}),
]


def fetch_json(url, data=None, headers=None, timeout=60):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def fetch_kev():
    for url in KEV_SOURCES:
        try:
            data = fetch_json(url)
            if data.get("vulnerabilities"):
                print(f"KEV: {len(data['vulnerabilities'])} entries from {url}")
                return data, url
            print(f"KEV: no entries in response from {url}", file=sys.stderr)
        except Exception as exc:  # network, HTTP or JSON errors
            print(f"KEV: failed to fetch {url}: {exc}", file=sys.stderr)
    return None, None


def attack_type(cwes):
    found = set(cwes or [])
    if not found:
        return NO_CWE_TYPE
    for name, ids in ATTACK_TYPES:
        if found & ids:
            return name
    return OTHER_TYPE


def parse_date(value):
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def count_types(vulns):
    counts = Counter(v["_type"] for v in vulns)
    specific = [name for name, _ in ATTACK_TYPES if name not in CATCH_ALLS]
    # Largest first, but keep the catch-all buckets at the bottom.
    specific.sort(key=lambda n: -counts.get(n, 0))
    return [{"name": n, "count": counts.get(n, 0)} for n in specific + list(CATCH_ALLS)]


def month_key(d):
    return f"{d.year:04d}-{d.month:02d}"


def months_back(today, n):
    y, m = today.year, today.month
    keys = []
    for _ in range(n):
        keys.append(f"{y:04d}-{m:02d}")
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    return list(reversed(keys))


def summarise_kev(kev, source, today):
    vulns = []
    for v in kev["vulnerabilities"]:
        added = parse_date(v.get("dateAdded"))
        if not added:
            continue
        v["_added"] = added
        v["_type"] = attack_type(v.get("cwes"))
        v["_ransomware"] = v.get("knownRansomwareCampaignUse", "").strip().lower() == "known"
        vulns.append(v)
    vulns.sort(key=lambda v: (v["_added"], v.get("cveID", "")), reverse=True)

    last30 = [v for v in vulns if v["_added"] > today - timedelta(days=30)]
    last12m = [v for v in vulns if v["_added"] > today - timedelta(days=365)]
    this_year = [v for v in vulns if v["_added"].year == today.year]

    month_keys = months_back(today, TREND_MONTHS)
    totals = Counter(month_key(v["_added"]) for v in vulns)
    ransom = Counter(month_key(v["_added"]) for v in vulns if v["_ransomware"])
    monthly = [{"month": k, "total": totals.get(k, 0), "ransomware": ransom.get(k, 0)} for k in month_keys]

    vendors = Counter(v.get("vendorProject", "Unknown").strip() for v in this_year)

    latest = [{
        "cve": v.get("cveID", ""),
        "vendor": v.get("vendorProject", ""),
        "product": v.get("product", ""),
        "name": v.get("vulnerabilityName", ""),
        "added": v["_added"].isoformat(),
        "due": v.get("dueDate", ""),
        "ransomware": v["_ransomware"],
        "type": v["_type"],
        "cwes": v.get("cwes", []),
        "description": v.get("shortDescription", ""),
    } for v in vulns[:LATEST_LIMIT]]

    return {
        "catalogVersion": kev.get("catalogVersion", ""),
        "dateReleased": kev.get("dateReleased", ""),
        "source": source,
        "totals": {
            "all": len(vulns),
            "last30": len(last30),
            "ransomware": sum(v["_ransomware"] for v in vulns),
        },
        "attackTypes": {"last12": count_types(last12m), "all": count_types(vulns)},
        "monthly": monthly,
        "topVendors": {
            "year": today.year,
            "rows": [{"name": n, "count": c} for n, c in vendors.most_common(TOP_VENDORS)],
        },
        "latest": latest,
    }


def fetch_threatfox(auth_key):
    try:
        body = json.dumps({"query": "get_iocs", "days": 7}).encode()
        data = fetch_json(THREATFOX_API, data=body,
                          headers={"Auth-Key": auth_key, "Content-Type": "application/json"})
    except Exception as exc:
        print(f"ThreatFox: request failed: {exc}", file=sys.stderr)
        return None
    if data.get("query_status") != "ok" or not isinstance(data.get("data"), list):
        print(f"ThreatFox: unexpected status {data.get('query_status')!r}", file=sys.stderr)
        return None
    families = Counter(
        (ioc.get("malware_printable") or "Unknown").strip()
        for ioc in data["data"]
        if (ioc.get("malware_printable") or "").strip().lower() not in ("", "unknown malware")
    )
    print(f"ThreatFox: {len(data['data'])} IOCs across {len(families)} families")
    return {
        "days": 7,
        "families": [{"name": n, "count": c} for n, c in families.most_common(TOP_FAMILIES)],
    }


def load_existing():
    try:
        return json.loads(OUTPUT.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def main():
    now = datetime.now(timezone.utc)
    existing = load_existing()

    kev, source = fetch_kev()
    if kev is None:
        msg = "keeping the last good snapshot" if existing else "no snapshot exists yet; the page will show an error"
        print(f"KEV: every source failed, {msg}.", file=sys.stderr)
        return 0

    out = {"generated": now.isoformat(timespec="seconds"), "kev": summarise_kev(kev, source, now.date())}

    auth_key = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
    if auth_key:
        out["threatfox"] = fetch_threatfox(auth_key)
        if out["threatfox"] is None and existing and existing.get("threatfox"):
            out["threatfox"] = existing["threatfox"]  # keep last good ThreatFox counts
    else:
        out["threatfox"] = None

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(out, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {OUTPUT} ({OUTPUT.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
