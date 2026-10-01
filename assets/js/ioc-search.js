/* IOC lookup for the Threat Intel page.
   Searches assets/data/ioc-index.json (built by tools/fetch_threat_intel.py)
   entirely in the browser. The index is only downloaded on first use.
   Indicator values are attacker-controlled, so they are always shown defanged
   and inserted with textContent, never as links or HTML. */
(function () {
  'use strict';

  var section = document.querySelector('.ti-ioc');
  if (!section) return;

  var $ = function (id) { return document.getElementById(id); };
  var form = $('ti-ioc-form');
  var input = $('ti-ioc-q');
  var status = $('ti-ioc-status');
  var results = $('ti-ioc-results');
  var fmt = new Intl.NumberFormat();

  var MAX_QUERIES = 25;
  var MAX_MATCHES = 15;
  var MAX_RELATED = 3;

  // Row layout written by the build script
  var VALUE = 0, TYPE = 1, FAMILY = 2, THREAT = 3, COMPROMISED = 4, FIRST_SEEN = 5, SOURCE = 6, SOURCE_ID = 7, TAGS = 8;

  var index = null;   // { exact: Map, byHost: Map, families: {}, meta }
  var loading = null;

  function el(tag, attrs, text) {
    var node = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) { node.setAttribute(k, attrs[k]); });
    if (text != null) node.textContent = text;
    return node;
  }

  function link(href, text) {
    return el('a', { href: href, target: '_blank', rel: 'noopener noreferrer' }, text);
  }

  // ---- Context: what a match could mean -------------------------------------
  var POSTS = {
    clickfix: { title: 'Fake CAPTCHAs: How Attackers Use Them to Spread Malware', url: '/posts/Clickfix-FakeCaptcha-Delivering-Lumma-Stealer/' },
    etherhiding: { title: 'Dissecting an EtherHiding ClickFix Attack', url: '/posts/EtherHiding-Blockchain-ClickFix/' }
  };

  // Matched against family names and tags, lowercased
  var FAMILY_NOTES = [
    { match: /clearfake|etherhid/, text: 'ClearFake injects JavaScript into compromised websites to show fake browser-update or fake CAPTCHA (ClickFix) prompts. It often loads its code from blockchain smart contracts (EtherHiding).', post: 'etherhiding' },
    { match: /clickfix|fakecaptcha|fake captcha/, text: 'ClickFix / fake CAPTCHA: the visitor is told to paste a command into the Run box or a terminal to "verify" themselves, which installs malware, usually an infostealer.', post: 'clickfix' },
    { match: /socgholish|fakeupdates/, text: 'SocGholish (FakeUpdates) shows a fake browser-update prompt on compromised sites and drops a JavaScript loader. It is a common first step before ransomware.' },
    { match: /lumma/, text: 'Lumma Stealer is an infostealer that takes browser passwords, session cookies and crypto wallets. It is often delivered through ClickFix lures.', post: 'clickfix' },
    { match: /smartloader|luajit/, text: 'SmartLoader is a LuaJIT-based loader spread through fake GitHub projects, game cheats and cracked software. It usually delivers infostealers.' },
    { match: /webshell/, text: 'A web shell is a script planted on a compromised web server that gives the attacker remote control of the site.' },
    { match: /mirai|mozi|hajime|gafgyt/, text: 'An IoT botnet that infects routers, cameras and other devices, mostly to launch DDoS attacks.' },
    { match: /coinminer|xmrig/, text: 'A cryptominer that uses the victim\'s CPU to mine cryptocurrency for the attacker.' },
    { match: /cobalt strike|adaptixc2|sliver|vshell|havoc|brute ratel|mythic/, text: 'A post-exploitation / C2 framework. A match usually means hands-on-keyboard attacker activity, not just commodity malware.' },
    { match: /asyncrat|remcos|njrat|xworm|dcrat|quasar/, text: 'A remote access trojan (RAT) that gives the attacker full control of an infected machine.' },
    { match: /stealer|vidar|stealc|redline|raccoon|amos/, text: 'An infostealer that takes saved passwords, browser cookies and crypto wallets, often leading to account takeover.' }
  ];

  var THREAT_LABELS = {
    botnet_cc: { label: 'C2 server', text: 'Command-and-control (C2) server: infected machines contact it for instructions and to send stolen data.' },
    payload_delivery: { label: 'Payload delivery', text: 'Payload delivery: hosts or redirects to a malware download.' },
    payload: { label: 'Malware sample', text: 'A malware sample: this file hash is a known malicious payload.' },
    cc_skimming: { label: 'Card skimmer', text: 'Card skimming: steals payment card details typed into checkout pages.' },
    malware_download: { label: 'Malware download', text: 'Serves a malware download that was online when the data was refreshed.' }
  };

  var COMPROMISED_NOTE = 'Flagged as compromised: this is a real, legitimate website or server that attackers have broken into and are abusing. Its owner is most likely a victim, so treat it as unsafe, not as attacker-owned.';

  // ---- Parsing --------------------------------------------------------------
  function refang(s) {
    return s.trim()
      .replace(/^[<("'`[]+|[>)"'`\],;]+$/g, '')
      .replace(/^hxxp/i, 'http').replace(/^fxp/i, 'ftp')
      .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\[\s*\.\s*\]/gi, '.')
      .replace(/\[:\]/g, ':').replace(/\[:\/\/\]/g, '://')
      .toLowerCase();
  }

  function isIp(s) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::(\d{1,5}))?$/.exec(s);
    return !!m && [1, 2, 3, 4].every(function (i) { return +m[i] <= 255; });
  }

  function hostOf(url) {
    try { return new URL(url).hostname.replace(/^\[|\]$/g, ''); } catch (e) { return ''; }
  }

  function classify(raw) {
    var v = refang(raw);
    if (!v) return null;
    if (/^[a-f0-9]{32}$/.test(v)) return { value: v, type: 'md5' };
    if (/^[a-f0-9]{40}$/.test(v)) return { value: v, type: 'sha1' };
    if (/^[a-f0-9]{64}$/.test(v)) return { value: v, type: 'sha256' };
    if (isIp(v)) return { value: v, type: 'ip' };
    if (/^[a-z][a-z0-9+.-]*:\/\//.test(v)) return { value: v, type: 'url', host: hostOf(v) };
    // A host with a path but no scheme, e.g. evil.com/payload.exe
    if (/^[a-z0-9.-]+\.[a-z0-9-]+(:\d+)?\//.test(v)) return { value: 'http://' + v, type: 'url', host: hostOf('http://' + v) };
    if (/^(?=.{4,253}$)([a-z0-9_-]{1,63}\.)+[a-z][a-z0-9-]{1,62}$/.test(v)) return { value: v, type: 'domain' };
    return { value: v, type: 'unknown' };
  }

  var TYPE_NAMES = { md5: 'MD5 hash', sha1: 'SHA1 hash', sha256: 'SHA256 hash', ip: 'IP address', url: 'URL', domain: 'Domain', unknown: 'Unrecognised' };

  function defang(v) {
    return v.replace(/^http/, 'hxxp').replace(/\./g, '[.]');
  }

  // ---- Index ----------------------------------------------------------------
  function push(map, key, row) {
    if (!key) return;
    var list = map.get(key);
    if (list) list.push(row); else map.set(key, [row]);
  }

  function buildIndex(json) {
    var exact = new Map(), byHost = new Map(), families = {};
    (json.families || []).forEach(function (f) { families[f[0]] = f[1]; });
    json.rows.forEach(function (r) {
      push(exact, r[VALUE], r);
      if (r[TYPE] === 'domain') push(byHost, r[VALUE], r);
      else if (r[TYPE] === 'ip') push(byHost, r[VALUE].split(':')[0], r);
      else if (r[TYPE] === 'url') push(byHost, hostOf(r[VALUE]), r);
    });
    return { exact: exact, byHost: byHost, families: families, meta: json };
  }

  function load() {
    if (!loading) {
      status.textContent = 'Loading indicator data…';
      loading = fetch(section.getAttribute('data-src'), { cache: 'no-cache' })
        .then(function (res) {
          if (!res.ok) throw new Error('HTTP ' + res.status);
          return res.json();
        })
        .then(function (json) {
          index = buildIndex(json);
          describeIndex();
          return index;
        })
        .catch(function (err) {
          loading = null;
          status.textContent = 'The indicator data could not be loaded (' + err.message + '). Please try again later.';
          throw err;
        });
    }
    return loading;
  }

  function describeIndex() {
    var s = index.meta.sources || {};
    var parts = [];
    if (s.tf) parts.push('ThreatFox (last 7 days)');
    if (s.uh) parts.push('URLhaus (online malware URLs)');
    var when = index.meta.generated_at ? new Date(index.meta.generated_at) : null;
    status.textContent = 'Searching ' + fmt.format(index.meta.rows.length) + ' indicators from ' + parts.join(' and ') +
      (when && !isNaN(when) ? ', refreshed ' + when.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : '') + '.';
  }

  // ---- Matching -------------------------------------------------------------
  function parentDomains(d) {
    var labels = d.split('.'), out = [];
    for (var i = 1; i < labels.length - 1; i++) out.push(labels.slice(i).join('.'));
    return out;
  }

  function lookup(q) {
    var found = [], seen = new Set();
    // direct: the searched indicator itself; otherwise a related record (same host, parent or subdomain)
    function add(rows, relation, direct) {
      (rows || []).forEach(function (r) {
        if (seen.has(r)) return;
        seen.add(r);
        found.push({ row: r, relation: relation, direct: direct });
      });
    }

    if (q.type === 'md5' || q.type === 'sha1' || q.type === 'sha256') {
      add(index.exact.get(q.value), 'Exact match', true);
    } else if (q.type === 'ip') {
      var ip = q.value.split(':')[0];
      var hasPort = ip !== q.value;
      add(index.exact.get(q.value), 'Exact match', true);
      add(index.byHost.get(ip), hasPort ? 'Same IP, other port or URL' : 'Same IP', !hasPort);
    } else if (q.type === 'domain') {
      add(index.byHost.get(q.value), 'Exact match', true);
      parentDomains(q.value).forEach(function (p) { add(index.byHost.get(p), 'Parent domain ' + defang(p), false); });
      var suffix = '.' + q.value;
      index.byHost.forEach(function (rows, host) {
        if (host.length > suffix.length && host.slice(-suffix.length) === suffix) add(rows, 'Subdomain ' + defang(host), false);
      });
    } else if (q.type === 'url') {
      add(index.exact.get(q.value), 'Exact match', true);
      add(index.exact.get(q.value.replace(/\/$/, '')), 'Exact match', true);
      add(index.exact.get(q.value + '/'), 'Exact match', true);
      if (q.host) {
        // The host itself being a listed domain or IP is a direct hit; other URLs on it are only related
        var onHost = index.byHost.get(q.host) || [];
        add(onHost.filter(function (r) { return r[TYPE] !== 'url'; }), 'Host ' + defang(q.host) + ' is listed', true);
        add(onHost.filter(function (r) { return r[TYPE] === 'url'; }), 'Other URL on the same host', false);
      }
    }
    // Direct hits first
    found.sort(function (a, b) { return b.direct - a.direct; });
    return found;
  }

  // ---- Rendering ------------------------------------------------------------
  function pivots(q) {
    var v = encodeURIComponent(q.value);
    var links = [];
    if (q.type === 'ip') {
      var ip = encodeURIComponent(q.value.split(':')[0]);
      links.push(['VirusTotal', 'https://www.virustotal.com/gui/ip-address/' + ip],
        ['AbuseIPDB', 'https://www.abuseipdb.com/check/' + ip],
        ['Shodan', 'https://www.shodan.io/host/' + ip],
        ['ThreatFox', 'https://threatfox.abuse.ch/browse.php?search=ioc%3A' + ip]);
    } else if (q.type === 'domain') {
      links.push(['VirusTotal', 'https://www.virustotal.com/gui/domain/' + v],
        ['urlscan.io', 'https://urlscan.io/search/#domain%3A' + v],
        ['URLhaus', 'https://urlhaus.abuse.ch/browse.php?search=' + v],
        ['ThreatFox', 'https://threatfox.abuse.ch/browse.php?search=ioc%3A' + v]);
    } else if (q.type === 'url') {
      var host = encodeURIComponent(q.host || '');
      links.push(['VirusTotal', 'https://www.virustotal.com/gui/search/' + encodeURIComponent(v)],
        ['URLhaus', 'https://urlhaus.abuse.ch/browse.php?search=' + v]);
      if (host) links.push(['urlscan.io (host)', 'https://urlscan.io/search/#domain%3A' + host]);
    } else if (q.type === 'md5' || q.type === 'sha1' || q.type === 'sha256') {
      links.push(['VirusTotal', 'https://www.virustotal.com/gui/file/' + v],
        ['MalwareBazaar', 'https://bazaar.abuse.ch/browse.php?search=' + q.type + '%3A' + v],
        ['ThreatFox', 'https://threatfox.abuse.ch/browse.php?search=ioc%3A' + v]);
    }
    if (!links.length) return null;
    var p = el('p', { 'class': 'ti-ioc-pivots' }, 'Look it up on: ');
    links.forEach(function (l, i) {
      if (i) p.appendChild(document.createTextNode(' · '));
      p.appendChild(link(l[1], l[0]));
    });
    return p;
  }

  function sourceLink(r) {
    var id = encodeURIComponent(r[SOURCE_ID]);
    return r[SOURCE] === 'tf'
      ? link('https://threatfox.abuse.ch/ioc/' + id + '/', 'ThreatFox #' + r[SOURCE_ID])
      : link('https://urlhaus.abuse.ch/url/' + id + '/', 'URLhaus #' + r[SOURCE_ID]);
  }

  function matchRow(m) {
    var r = m.row;
    var li = el('li', { 'class': 'ti-ioc-match' });
    li.appendChild(el('code', { 'class': 'ti-ioc-value' }, r[TYPE] === 'md5' || r[TYPE] === 'sha1' || r[TYPE] === 'sha256' ? r[VALUE] : defang(r[VALUE])));

    var facts = el('div', { 'class': 'ti-ioc-facts' });
    facts.appendChild(el('span', { 'class': 'ti-ioc-rel' }, m.relation));
    if (r[FAMILY]) {
      var malpedia = index.families[r[FAMILY]];
      facts.appendChild(malpedia ? link(malpedia, r[FAMILY]) : el('span', null, r[FAMILY]));
    }
    var threat = THREAT_LABELS[r[THREAT]];
    facts.appendChild(el('span', null, threat ? threat.label : r[THREAT].replace(/_/g, ' ')));
    if (r[COMPROMISED]) facts.appendChild(el('span', { 'class': 'ti-badge' }, 'Compromised site'));
    if (r[FIRST_SEEN]) facts.appendChild(el('span', null, 'First seen ' + r[FIRST_SEEN]));
    facts.appendChild(sourceLink(r));
    li.appendChild(facts);

    if (r[TAGS]) li.appendChild(el('div', { 'class': 'ti-ioc-tags' }, 'Tags: ' + r[TAGS].split(',').join(', ')));
    return li;
  }

  // Plain-language notes on what the matches point to, without repeats
  function context(matches) {
    var notes = [], seen = {};
    function note(key, text, post) {
      if (seen[key]) return;
      seen[key] = true;
      notes.push({ text: text, post: post });
    }
    matches.forEach(function (m) {
      var r = m.row;
      if (r[COMPROMISED]) note('compromised', COMPROMISED_NOTE);
      var haystack = (r[FAMILY] + ' ' + r[TAGS]).toLowerCase();
      FAMILY_NOTES.forEach(function (f, i) {
        if (f.match.test(haystack)) note('family' + i, f.text, f.post);
      });
      var threat = THREAT_LABELS[r[THREAT]];
      if (threat) note('threat' + r[THREAT], threat.text);
    });
    if (!notes.length) return null;

    var box = el('div', { 'class': 'ti-ioc-context' });
    box.appendChild(el('h3', null, 'What this could be'));
    var ul = el('ul');
    notes.forEach(function (n) {
      var li = el('li', null, n.text);
      if (n.post && POSTS[n.post]) {
        li.appendChild(document.createTextNode(' Related write-up: '));
        li.appendChild(el('a', { href: POSTS[n.post].url }, POSTS[n.post].title));
        li.appendChild(document.createTextNode('.'));
      }
      ul.appendChild(li);
    });
    box.appendChild(ul);
    return box;
  }

  function resultCard(q) {
    var card = el('article', { 'class': 'ti-ioc-card' });
    var head = el('header', { 'class': 'ti-ioc-head' });
    var shown = q.type === 'md5' || q.type === 'sha1' || q.type === 'sha256' ? q.value : defang(q.value);
    head.appendChild(el('code', { 'class': 'ti-ioc-value' }, shown));
    head.appendChild(el('span', { 'class': 'ti-ioc-type' }, TYPE_NAMES[q.type]));
    card.appendChild(head);

    if (q.type === 'unknown') {
      card.appendChild(el('p', { 'class': 'ti-note' }, 'This doesn\'t look like an IP, domain, URL or MD5 / SHA1 / SHA256 hash.'));
      return card;
    }

    var matches = lookup(q);
    var direct = matches.filter(function (m) { return m.direct; });
    var related = matches.length - direct.length;
    var verdict = el('p', { 'class': 'ti-ioc-verdict' + (direct.length ? ' is-hit' : '') });
    if (direct.length) {
      verdict.textContent = 'Malicious: found in ' + fmt.format(direct.length) + (direct.length === 1 ? ' record' : ' records') +
        (related ? ', plus ' + fmt.format(related) + ' related.' : '.');
    } else if (related) {
      verdict.textContent = 'No exact match, but ' + fmt.format(related) + ' related ' + (related === 1 ? 'record shares' : 'records share') +
        ' its host or domain. Check whether they are really connected before acting on them.';
    } else {
      verdict.textContent = 'No match in this data. That is not proof it\'s safe: the data only covers recent ThreatFox reports and URLs that are online right now.';
    }
    card.appendChild(verdict);

    if (matches.length) {
      // Explain the direct hits; fall back to the related records when there are none
      var ctx = context(direct.length ? direct : matches);
      if (ctx) card.appendChild(ctx);
      // With direct hits, only a few related records are shown: shared hosts like
      // raw.githubusercontent.com can have thousands of unrelated URLs.
      var list = direct.slice(0, MAX_MATCHES).concat(matches.slice(direct.length, direct.length + (direct.length ? MAX_RELATED : MAX_MATCHES)));
      var ul = el('ul', { 'class': 'ti-ioc-matches' });
      list.forEach(function (m) { ul.appendChild(matchRow(m)); });
      card.appendChild(ul);
      if (matches.length > list.length) {
        card.appendChild(el('p', { 'class': 'ti-count' }, 'Showing ' + list.length + ' of ' + fmt.format(matches.length) + ' records.'));
      }
    }

    var p = pivots(q);
    if (p) card.appendChild(p);
    return card;
  }

  function search(text) {
    var seen = {};
    var queries = text.split(/[\s,;|]+/).map(classify).filter(function (q) {
      if (!q || seen[q.value]) return false;
      seen[q.value] = true;
      return true;
    });
    results.textContent = '';
    if (!queries.length) return;
    if (queries.length > MAX_QUERIES) {
      results.appendChild(el('p', { 'class': 'ti-count' }, 'Only the first ' + MAX_QUERIES + ' of ' + queries.length + ' indicators were searched.'));
      queries = queries.slice(0, MAX_QUERIES);
    }
    queries.forEach(function (q) { results.appendChild(resultCard(q)); });
  }

  input.addEventListener('focus', function () { load().catch(function () {}); }, { once: true });
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var text = input.value;
    load().then(function () { search(text); }).catch(function () {});
  });
})();
