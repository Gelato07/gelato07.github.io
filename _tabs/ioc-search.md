---
title: IOC Search
icon: fas fa-magnifying-glass
order: 7
---

<link rel="stylesheet" href="{{ '/assets/css/threat-intel.css' | relative_url }}">

<div class="ti">
  <section class="ti-ioc" aria-label="IOC lookup" data-src="{{ '/assets/data/ioc-index.json' | relative_url }}?v={{ site.time | date: '%s' }}">
    <p class="ti-note">Check an IP, domain, URL or file hash against recent abuse.ch ThreatFox and URLhaus data. Paste several at once, and defanged values like <code>hxxp://evil[.]com</code> are fine. Searches run in your browser, so nothing you enter is sent anywhere.</p>
    <form class="ti-ioc-form" id="ti-ioc-form" role="search">
      <label for="ti-ioc-q" class="ti-sr">Indicators to look up</label>
      <input type="search" id="ti-ioc-q" placeholder="IP, domain, URL or MD5 / SHA1 / SHA256 hash" autocomplete="off" spellcheck="false">
      <button type="submit">Search</button>
    </form>
    <p class="ti-count" id="ti-ioc-status" aria-live="polite"></p>
    <div id="ti-ioc-results" aria-live="polite"></div>
  </section>

  <p class="ti-source">
    Data from <a href="https://threatfox.abuse.ch/">abuse.ch ThreatFox</a> and <a href="https://urlhaus.abuse.ch/">abuse.ch URLhaus</a>, refreshed daily. For exploited-vulnerability trends, see the <a href="{{ '/threat-intel/' | relative_url }}">Threat Intel</a> tab.
  </p>
</div>

<script defer src="{{ '/assets/js/ioc-search.js' | relative_url }}"></script>
