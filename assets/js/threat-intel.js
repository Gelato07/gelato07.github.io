/* Threat Intel dashboard for Cyber Weblog.
   Reads assets/data/threat-intel.json (built by tools/fetch_threat_intel.py).
   All feed text is inserted with textContent, never innerHTML, because
   threat feeds are attacker-influenced data. */
(function () {
  'use strict';

  var root = document.getElementById('ti');
  if (!root) return;

  var $ = function (id) { return document.getElementById(id); };
  var fmt = new Intl.NumberFormat();
  var dayFmt = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
  var monthFmt = new Intl.DateTimeFormat(undefined, { month: 'short', year: '2-digit', timeZone: 'UTC' });
  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var charts = [];
  var data;
  var range = 'last_365_days';
  var PAGE = 15;
  var shown = PAGE;

  function el(tag, attrs, text) {
    var node = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) { node.setAttribute(k, attrs[k]); });
    if (text != null) node.textContent = text;
    return node;
  }

  function isNarrow() { return root.clientWidth < 560; }

  // Split long axis labels onto two lines on small screens
  function wrap(label) {
    if (!isNarrow() || label.length <= 18) return label;
    var words = label.split(' '), lines = [''];
    words.forEach(function (w) {
      var cur = lines[lines.length - 1];
      if (cur && (cur + ' ' + w).length > 18) lines.push(w);
      else lines[lines.length - 1] = cur ? cur + ' ' + w : w;
    });
    return lines;
  }

  function day(iso) { return dayFmt.format(new Date(iso.slice(0, 10) + 'T00:00:00Z')); }

  // ---- Theme ------------------------------------------------------------
  // Chirpy exposes its palette as CSS variables; read them at draw time
  // and redraw whenever the reader flips Light / Dark / System.
  function theme() {
    var cs = getComputedStyle(root);
    var v = function (name, fallback) { return (cs.getPropertyValue(name) || '').trim() || fallback; };
    return {
      text: v('--text-color', cs.color),
      muted: v('--ti-muted', '#757575'),
      grid: v('--ti-line', 'rgba(128,128,128,0.25)'),
      accent: v('--ti-accent', '#0056b2'),
      ransom: v('--ti-ransom', '#d93f53')
    };
  }

  // Turn any CSS colour into one with the given opacity, via the canvas parser
  var probe = document.createElement('canvas').getContext('2d');
  function alpha(color, a) {
    probe.fillStyle = '#000';
    probe.fillStyle = color;
    var c = probe.fillStyle;
    if (c.charAt(0) === '#') {
      var n = parseInt(c.slice(1), 16);
      return 'rgba(' + (n >> 16 & 255) + ',' + (n >> 8 & 255) + ',' + (n & 255) + ',' + a + ')';
    }
    return c.replace(/rgba?\(([^)]+)\)/, function (_, inner) {
      var p = inner.split(',').slice(0, 3);
      return 'rgba(' + p.join(',') + ',' + a + ')';
    });
  }

  function baseOptions(t, horizontal) {
    var valueAxis = { beginAtZero: true, ticks: { color: t.muted, precision: 0 }, grid: { color: t.grid }, border: { display: false } };
    var labelAxis = { ticks: { color: t.text, autoSkip: !horizontal }, grid: { display: false }, border: { color: t.grid } };
    return {
      responsive: true,
      maintainAspectRatio: false,
      animation: reduceMotion ? false : { duration: 500 },
      indexAxis: horizontal ? 'y' : 'x',
      scales: horizontal ? { x: valueAxis, y: labelAxis } : { x: labelAxis, y: valueAxis },
      plugins: {
        legend: { display: false, labels: { color: t.text, boxWidth: 12 } },
        tooltip: { displayColors: false }
      }
    };
  }

  // ---- Charts -----------------------------------------------------------
  function drawTypes(t) {
    // "Other" always goes last so it never reads as a real category
    var rows = data.kev.categories[range].slice().sort(function (a, b) {
      return (a.label.indexOf('Other') === 0) - (b.label.indexOf('Other') === 0) || b.count - a.count;
    });
    $('ti-types-wrap').style.height = Math.max(220, rows.length * (isNarrow() ? 44 : 30) + 40) + 'px';
    return new Chart($('ti-types'), {
      type: 'bar',
      data: {
        labels: rows.map(function (r) { return wrap(r.label); }),
        datasets: [{
          label: 'Vulnerabilities',
          data: rows.map(function (r) { return r.count; }),
          backgroundColor: rows.map(function (r) { return r.label.indexOf('Other') === 0 ? alpha(t.muted, 0.45) : t.accent; }),
          borderRadius: 3,
          maxBarThickness: 22
        }]
      },
      options: baseOptions(t, true)
    });
  }

  function drawMonthly(t) {
    var rows = data.kev.monthly;
    var opts = baseOptions(t, false);
    opts.scales.x.stacked = true;
    opts.scales.y.stacked = true;
    opts.scales.x.ticks.maxRotation = 0;
    opts.scales.x.ticks.autoSkipPadding = 10;
    opts.plugins.legend.display = true;
    opts.plugins.legend.position = 'bottom';
    opts.plugins.tooltip.displayColors = true;
    opts.plugins.tooltip.callbacks = {
      title: function (items) {
        var i = items[0].dataIndex;
        var title = items[0].label;
        return i === rows.length - 1 ? title + ' (month to date)' : title;
      },
      footer: function (items) {
        return 'Total: ' + fmt.format(rows[items[0].dataIndex].total);
      }
    };
    return new Chart($('ti-monthly'), {
      type: 'bar',
      data: {
        labels: rows.map(function (r) { return monthFmt.format(new Date(r.month + '-01T00:00:00Z')); }),
        datasets: [
          { label: 'Linked to ransomware', data: rows.map(function (r) { return r.ransomware; }), backgroundColor: t.ransom, borderRadius: 2 },
          { label: 'Other exploited vulnerabilities', data: rows.map(function (r) { return r.total - r.ransomware; }), backgroundColor: alpha(t.accent, 0.55), borderRadius: 2 }
        ]
      },
      options: opts
    });
  }

  function drawRanked(canvasId, wrapId, rows, color) {
    $(wrapId).style.height = Math.max(200, rows.length * 30 + 40) + 'px';
    return new Chart($(canvasId), {
      type: 'bar',
      data: {
        labels: rows.map(function (r) { return wrap(r.label); }),
        datasets: [{ data: rows.map(function (r) { return r.count; }), backgroundColor: color, borderRadius: 3, maxBarThickness: 22 }]
      },
      options: baseOptions(theme(), true)
    });
  }

  function drawAll() {
    charts.forEach(function (c) { c.destroy(); });
    var t = theme();
    charts = [drawTypes(t), drawMonthly(t), drawRanked('ti-vendors', 'ti-vendors-wrap', data.kev.vendors_365_days, t.accent)];
    if (data.threatfox && data.threatfox.families.length) {
      charts.push(drawRanked('ti-tf-chart', 'ti-tf-wrap', data.threatfox.families, t.ransom));
    }
  }

  // ---- Summary text -----------------------------------------------------
  function strong(n, cls) {
    var s = el('strong', cls ? { 'class': cls } : null, fmt.format(n));
    return s;
  }

  function renderLede() {
    var k = data.kev, lede = $('ti-lede');
    lede.textContent = '';
    lede.append(
      strong(k.totals.all), ' vulnerabilities have been confirmed as exploited in the wild. CISA added ',
      strong(k.totals.last_30_days), ' in the last 30 days, and ',
      strong(k.totals.ransomware_all, 'is-ransom'), ' have been used in ransomware campaigns.'
    );
    var meta = 'Refreshed ' + day(data.generated_at) + ' from catalog version ' + k.catalog_version + '.';
    if (k.top_vendor_365_days) {
      meta += ' ' + k.top_vendor_365_days.label + ' has had the most additions this year (' + fmt.format(k.top_vendor_365_days.count) + ').';
    }
    $('ti-meta').textContent = meta;

    if (data.threatfox) {
      var tf = data.threatfox;
      var types = tf.threat_types.slice(0, 3).map(function (r) { return r.label + ' (' + fmt.format(r.count) + ')'; });
      $('ti-tf-note').textContent = fmt.format(tf.total_iocs) + ' indicators were shared on ThreatFox in the last ' + tf.window_days +
        ' days, mostly ' + types.join(', ') + '. Look any of them up on the ';
      $('ti-tf-note').append(el('a', { href: root.getAttribute('data-ioc-url') }, 'IOC Search'), ' tab.');
      $('ti-tf').hidden = false;
      $('ti-tf-credit').hidden = false;
    }
  }

  // ---- Table ------------------------------------------------------------
  function renderTable() {
    var q = $('ti-q').value.trim().toLowerCase();
    var cat = $('ti-cat').value;
    var ransomOnly = $('ti-ransom').checked;
    var all = data.kev.recent;
    var rows = all.filter(function (r) {
      if (ransomOnly && !r.ransomware) return false;
      if (cat && r.category !== cat) return false;
      if (q && (r.cve + ' ' + r.vendor + ' ' + r.product + ' ' + r.name).toLowerCase().indexOf(q) === -1) return false;
      return true;
    });

    var body = $('ti-rows');
    body.textContent = '';
    rows.slice(0, shown).forEach(function (r) {
      var tr = el('tr');
      tr.appendChild(el('td', { 'data-label': 'Added' }, day(r.date_added)));

      var cveCell = el('td', { 'data-label': 'CVE' });
      if (/^CVE-\d{4}-\d{4,}$/.test(r.cve)) {
        cveCell.appendChild(el('a', { href: 'https://nvd.nist.gov/vuln/detail/' + r.cve, rel: 'noopener noreferrer', target: '_blank' }, r.cve));
      } else {
        cveCell.textContent = r.cve;
      }
      tr.appendChild(cveCell);

      var vp = el('td', { 'data-label': 'Vendor and product' }, r.vendor);
      vp.appendChild(el('span', { 'class': 'ti-sub' }, r.product));
      tr.appendChild(vp);

      var nameCell = el('td');
      var details = el('details');
      var summary = el('summary', null, r.name);
      if (r.ransomware) summary.appendChild(el('span', { 'class': 'ti-badge' }, 'Ransomware'));
      details.appendChild(summary);
      details.appendChild(el('p', null, r.description));
      nameCell.appendChild(details);
      tr.appendChild(nameCell);

      tr.appendChild(el('td', { 'data-label': 'Weakness type' }, r.category));
      body.appendChild(tr);
    });

    if (!rows.length) {
      var empty = el('tr', { 'class': 'ti-empty' });
      empty.appendChild(el('td', { colspan: '5' }, 'No recent additions match these filters. Clear the search or pick another weakness type.'));
      body.appendChild(empty);
    }
    var visible = Math.min(shown, rows.length);
    $('ti-count').textContent = rows.length === all.length
      ? 'Showing ' + visible + ' of the ' + all.length + ' most recent additions.'
      : 'Showing ' + visible + ' of ' + rows.length + ' matches in the ' + all.length + ' most recent additions.';
    var more = $('ti-more');
    more.hidden = rows.length <= shown;
    more.textContent = 'Show ' + Math.min(PAGE, rows.length - shown) + ' more';
  }

  function setupTable() {
    var select = $('ti-cat');
    var seen = {};
    data.kev.recent.forEach(function (r) { seen[r.category] = true; });
    Object.keys(seen).sort().forEach(function (c) { select.appendChild(el('option', { value: c }, c)); });
    var refilter = function () { shown = PAGE; renderTable(); };
    ['ti-q', 'ti-cat', 'ti-ransom'].forEach(function (id) {
      $(id).addEventListener(id === 'ti-q' ? 'input' : 'change', refilter);
    });
    $('ti-more').addEventListener('click', function () { shown += PAGE; renderTable(); });
    renderTable();
  }

  // ---- Wiring -----------------------------------------------------------
  function setupToggle() {
    var buttons = root.querySelectorAll('.ti-toggle button');
    buttons.forEach(function (b) {
      b.addEventListener('click', function () {
        range = b.getAttribute('data-range');
        buttons.forEach(function (o) { o.setAttribute('aria-pressed', String(o === b)); });
        drawAll();
      });
    });
  }

  function watchTheme() {
    var redraw = function () { window.requestAnimationFrame(drawAll); };
    new MutationObserver(redraw).observe(document.documentElement, { attributes: true, attributeFilter: ['data-bs-theme', 'data-mode', 'class'] });
    var wasNarrow = isNarrow(), timer;
    window.addEventListener('resize', function () {
      clearTimeout(timer);
      timer = setTimeout(function () {
        if (isNarrow() !== wasNarrow) { wasNarrow = isNarrow(); drawAll(); }
      }, 150);
    });
    var mq = window.matchMedia('(prefers-color-scheme: dark)');
    if (mq.addEventListener) mq.addEventListener('change', redraw);
  }

  function fail(message) {
    var lede = $('ti-lede');
    lede.classList.add('ti-error');
    lede.textContent = message;
  }

  fetch(root.getAttribute('data-src'), { cache: 'no-cache' })
    .then(function (res) {
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return res.json();
    })
    .then(function (json) {
      if (!json || !json.kev) throw new Error('missing KEV section');
      data = json;
      if (typeof Chart === 'undefined') {
        renderLede();
        $('ti-body').hidden = false;
        setupTable();
        $('ti-meta').textContent = 'Charts could not load because the Chart.js script was blocked. The table below still works.';
        return;
      }
      Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
      renderLede();
      $('ti-body').hidden = false;
      setupToggle();
      setupTable();
      drawAll();
      watchTheme();
    })
    .catch(function (err) {
      fail('The threat data file could not be loaded (' + err.message + '). Run tools/fetch_threat_intel.py to regenerate assets/data/threat-intel.json, then rebuild the site.');
    });
})();
