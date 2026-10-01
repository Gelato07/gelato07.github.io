---
title: Threat Intel
icon: fas fa-shield-halved
order: 6
---

<link rel="stylesheet" href="{{ '/assets/css/threat-intel.css' | relative_url }}">

<div class="ti" id="ti" data-ioc-url="{{ '/ioc-search/' | relative_url }}" data-src="{{ '/assets/data/threat-intel.json' | relative_url }}?v={{ site.time | date: '%s' }}">
  <p class="ti-lede" id="ti-lede">Loading the latest exploited-vulnerability data…</p>
  <p class="ti-meta" id="ti-meta"></p>

  <section class="ti-section" id="ti-body" hidden>
    <div class="ti-head">
      <h2 id="ti-types-title">What attackers are exploiting</h2>
      <div class="ti-toggle" role="group" aria-label="Time range">
        <button type="button" data-range="last_365_days" aria-pressed="true">Last 12 months</button>
        <button type="button" data-range="all" aria-pressed="false">All time</button>
      </div>
    </div>
    <p class="ti-note">Each vulnerability in CISA's catalog is grouped by its underlying weakness (CWE), so you can see which bug classes attackers lean on most.</p>
    <div class="ti-chart" id="ti-types-wrap"><canvas id="ti-types" role="img" aria-labelledby="ti-types-title"></canvas></div>

    <h2 id="ti-monthly-title">How fast the list is growing</h2>
    <p class="ti-note">New additions per month over the last two years, split by whether CISA has linked them to ransomware campaigns.</p>
    <div class="ti-chart ti-chart--wide"><canvas id="ti-monthly" role="img" aria-labelledby="ti-monthly-title"></canvas></div>

    <h2 id="ti-vendors-title">Most targeted vendors this year</h2>
    <div class="ti-chart" id="ti-vendors-wrap"><canvas id="ti-vendors" role="img" aria-labelledby="ti-vendors-title"></canvas></div>

    <div id="ti-tf" hidden>
      <h2 id="ti-tf-title">Malware families seen this week</h2>
      <p class="ti-note" id="ti-tf-note"></p>
      <div class="ti-chart" id="ti-tf-wrap"><canvas id="ti-tf-chart" role="img" aria-labelledby="ti-tf-title"></canvas></div>
    </div>

    <h2>Latest additions</h2>
    <div class="ti-filters">
      <label class="ti-field">
        <span>Search</span>
        <input type="search" id="ti-q" placeholder="CVE, vendor or product" autocomplete="off">
      </label>
      <label class="ti-field">
        <span>Weakness type</span>
        <select id="ti-cat"><option value="">All types</option></select>
      </label>
      <label class="ti-check">
        <input type="checkbox" id="ti-ransom"> Ransomware-linked only
      </label>
    </div>
    <p class="ti-count" id="ti-count" aria-live="polite"></p>
    <div class="ti-table-wrap">
      <table class="ti-table">
        <thead>
          <tr>
            <th scope="col">Added</th>
            <th scope="col">CVE</th>
            <th scope="col">Vendor and product</th>
            <th scope="col">Vulnerability</th>
            <th scope="col">Weakness type</th>
          </tr>
        </thead>
        <tbody id="ti-rows"></tbody>
      </table>
    </div>
    <button type="button" class="ti-more" id="ti-more" hidden>Show more</button>

    <p class="ti-source">
      Data from the <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA Known Exploited Vulnerabilities catalog</a><span id="ti-tf-credit" hidden> and <a href="https://threatfox.abuse.ch/">abuse.ch ThreatFox</a></span>, refreshed daily. Weakness groupings are my own mapping of CWE IDs and may differ from vendor classifications.
    </p>
  </section>
</div>

<script defer src="https://cdn.jsdelivr.net/npm/chart.js@4.5.1/dist/chart.umd.min.js"></script>
<script defer src="{{ '/assets/js/threat-intel.js' | relative_url }}"></script>
