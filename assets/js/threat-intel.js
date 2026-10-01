/* Threat Intel tab: renders the snapshot written by tools/fetch_threat_intel.py.
   No third-party requests are made from the reader's browser. */
(function () {
  'use strict';

  var root = document.getElementById('ti-root');
  if (!root) return;

  var PAGE_SIZE = 25;
  var NUM = new Intl.NumberFormat('en-AU');
  var MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  var tip = document.getElementById('ti-tip');

  function $(id) { return document.getElementById(id); }
  function fmt(n) { return NUM.format(n); }

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === 'text') node.textContent = attrs[k];
      else if (k === 'class') node.className = attrs[k];
      else node.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) { if (c) node.appendChild(c); });
    return node;
  }

  function svg(tag, attrs) {
    var node = document.createElementNS('http://www.w3.org/2000/svg', tag);
    Object.keys(attrs || {}).forEach(function (k) { node.setAttribute(k, attrs[k]); });
    return node;
  }

  function monthLabel(key, withYear) {
    var parts = key.split('-');
    var name = MONTHS[parseInt(parts[1], 10) - 1];
    return withYear ? name + ' ' + parts[0] : name;
  }

  function formatDate(iso) {
    var d = new Date(iso + 'T00:00:00');
    if (isNaN(d)) return iso;
    return d.getDate() + ' ' + MONTHS[d.getMonth()] + ' ' + d.getFullYear();
  }

  /* ---------- Tooltip ---------- */

  function showTip(target, title, rows) {
    tip.textContent = '';
    tip.appendChild(el('strong', { text: title }));
    rows.forEach(function (r) {
      var row = el('div', { class: 'ti-tip-row' });
      if (r.key) row.appendChild(el('span', { class: 'ti-key ' + r.key }));
      row.appendChild(el('span', { text: r.label }));
      row.appendChild(el('b', { text: r.value }));
      tip.appendChild(row);
    });
    tip.hidden = false;

    var box = target.getBoundingClientRect();
    var host = root.getBoundingClientRect();
    var left = box.left - host.left + box.width / 2 - tip.offsetWidth / 2;
    left = Math.max(0, Math.min(left, host.width - tip.offsetWidth));
    var top = box.top - host.top - tip.offsetHeight - 8;
    if (top < 0) top = box.bottom - host.top + 8;
    tip.style.left = left + 'px';
    tip.style.top = top + 'px';
  }

  function hideTip() { tip.hidden = true; }

  function bindTip(node, title, rows) {
    node.addEventListener('mouseenter', function () { showTip(node, title, rows); });
    node.addEventListener('focus', function () { showTip(node, title, rows); });
    node.addEventListener('mouseleave', hideTip);
    node.addEventListener('blur', hideTip);
  }

  /* ---------- Data tables (the accessible view of each chart) ---------- */

  function dataTable(host, headers, rows) {
    var thead = el('tr', {}, headers.map(function (h, i) {
      return el('th', { class: i ? 'num' : '', scope: 'col', text: h });
    }));
    var body = rows.map(function (r) {
      return el('tr', {}, r.map(function (v, i) {
        return el('td', { class: i ? 'num' : '', text: typeof v === 'number' ? fmt(v) : v });
      }));
    });
    host.textContent = '';
    host.appendChild(el('table', {}, [el('thead', {}, [thead]), el('tbody', {}, body)]));
  }

  /* ---------- Horizontal bars ---------- */

  function hbars(host, rows, opts) {
    opts = opts || {};
    var max = Math.max.apply(null, rows.map(function (r) { return r.count; }).concat([1]));
    var total = rows.reduce(function (s, r) { return s + r.count; }, 0);
    host.textContent = '';
    rows.forEach(function (r) {
      var share = total ? Math.round((r.count / total) * 100) : 0;
      var fill = el('span', { class: 'ti-hbar-fill' });
      fill.style.width = (r.count / max) * 85 + '%';
      var bar = el('div', {
        class: 'ti-hbar' + (opts.muted && opts.muted.indexOf(r.name) !== -1 ? ' is-muted' : ''),
        tabindex: '0',
        'aria-label': r.name + ': ' + fmt(r.count) + (opts.unit ? ' ' + opts.unit : '')
      }, [
        el('span', { class: 'ti-hbar-label', text: r.name }),
        el('span', { class: 'ti-hbar-track' }, [fill, el('span', { class: 'ti-hbar-value', text: fmt(r.count) })])
      ]);
      var tipRows = [{ label: opts.unitLabel || 'Count', value: fmt(r.count) }];
      if (opts.share) tipRows.push({ label: 'Share', value: share + '%' });
      bindTip(bar, r.name, tipRows);
      host.appendChild(bar);
    });
  }

  /* ---------- Monthly stacked columns ---------- */

  // A clean tick step (1, 2 or 5 x 10^n) giving at most four intervals.
  function niceStep(max) {
    var raw = Math.max(max, 4) / 4;
    var pow = Math.pow(10, Math.floor(Math.log10(raw)));
    var steps = [1, 2, 5, 10];
    for (var i = 0; i < steps.length; i++) {
      if (steps[i] * pow >= raw) return steps[i] * pow;
    }
    return 10 * pow;
  }

  function columns(host, months, partialKey) {
    var width = Math.max(host.clientWidth, 280);
    var height = width < 500 ? 200 : 240;
    var pad = { top: 12, right: 4, bottom: 26, left: 32 };
    var plotW = width - pad.left - pad.right;
    var plotH = height - pad.top - pad.bottom;
    var step = niceStep(Math.max.apply(null, months.map(function (m) { return m.total; })));
    var yMax = step * Math.ceil(Math.max.apply(null, months.map(function (m) { return m.total; }).concat([1])) / step);
    var band = plotW / months.length;
    var barW = Math.min(24, Math.max(4, band - 4));
    var y = function (v) { return pad.top + plotH - (v / yMax) * plotH; };

    var s = svg('svg', { viewBox: '0 0 ' + width + ' ' + height, role: 'group',
      'aria-label': 'Monthly additions to the KEV catalog, split by ransomware use' });

    for (var v = 0; v <= yMax; v += step) {
      s.appendChild(svg('line', { class: 'ti-gridline', x1: pad.left, x2: width - pad.right, y1: y(v), y2: y(v) }));
      var lbl = svg('text', { class: 'ti-axis', x: pad.left - 6, y: y(v) + 4, 'text-anchor': 'end' });
      lbl.textContent = fmt(v);
      s.appendChild(lbl);
    }

    var labelEvery = width < 500 ? 6 : 3;
    months.forEach(function (m, i) {
      var cx = pad.left + band * i + band / 2;
      var x = cx - barW / 2;
      var other = m.total - m.ransomware;
      var g = svg('g', m.month === partialKey ? { class: 'ti-partial' } : {});
      var gap = m.ransomware && other ? 2 : 0;
      // Ransomware-linked at the baseline, other additions stacked above with a 2px surface gap.
      if (m.ransomware) g.appendChild(segment(x, y(m.ransomware), barW, y(0) - y(m.ransomware), 'ti-s2', !other));
      if (other) g.appendChild(segment(x, y(m.total), barW, y(m.ransomware) - y(m.total) - gap, 'ti-s1', true));
      s.appendChild(g);

      if (i % labelEvery === 0 || i === months.length - 1) {
        var tx = svg('text', { class: 'ti-axis', x: cx, y: height - 8, 'text-anchor': 'middle' });
        tx.textContent = monthLabel(m.month, false) + (m.month.slice(5) === '01' || i === 0 ? " '" + m.month.slice(2, 4) : '');
        s.appendChild(tx);
      }

      var hit = svg('rect', { class: 'ti-hit', x: pad.left + band * i, y: pad.top, width: band, height: plotH,
        tabindex: '0', 'aria-label': monthLabel(m.month, true) + ': ' + m.total + ' added, ' + m.ransomware + ' ransomware-linked' });
      var title = monthLabel(m.month, true) + (m.month === partialKey ? ' (month to date)' : '');
      bindTip(hit, title, [
        { key: 'ti-key-1', label: 'Other additions', value: fmt(other) },
        { key: 'ti-key-2', label: 'Ransomware-linked', value: fmt(m.ransomware) },
        { label: 'Total', value: fmt(m.total) }
      ]);
      s.appendChild(hit);
    });

    host.textContent = '';
    host.appendChild(s);
  }

  // A column segment with a 4px rounded data end and a square base.
  function segment(x, top, w, h, cls, roundTop) {
    if (h <= 0) h = 1;
    var r = roundTop ? Math.min(4, h, w / 2) : 0;
    var bottom = top + h;
    var d = 'M' + x + ',' + bottom +
      'V' + (top + r) +
      (r ? 'Q' + x + ',' + top + ' ' + (x + r) + ',' + top : '') +
      'H' + (x + w - r) +
      (r ? 'Q' + (x + w) + ',' + top + ' ' + (x + w) + ',' + (top + r) : '') +
      'V' + bottom + 'Z';
    return svg('path', { d: d, class: cls });
  }

  /* ---------- Latest additions ---------- */

  function latestTable(rows) {
    var host = $('ti-latest');
    var q = $('ti-q');
    var typeSel = $('ti-type');
    var ransom = $('ti-ransom');
    var more = $('ti-more');
    var shown = PAGE_SIZE;

    var types = rows.map(function (r) { return r.type; })
      .filter(function (t, i, a) { return a.indexOf(t) === i; }).sort();
    types.forEach(function (t) { typeSel.appendChild(el('option', { value: t, text: t })); });

    function matches(r) {
      var term = q.value.trim().toLowerCase();
      if (typeSel.value && r.type !== typeSel.value) return false;
      if (ransom.checked && !r.ransomware) return false;
      if (!term) return true;
      return [r.cve, r.vendor, r.product, r.name].join(' ').toLowerCase().indexOf(term) !== -1;
    }

    function rowNode(r, i) {
      var id = 'ti-row-' + i;
      var cve = el('span', { class: 'ti-cve' }, [document.createTextNode(r.cve)]);
      if (r.ransomware) cve.appendChild(el('span', { class: 'ti-badge', text: 'Ransomware' }));
      var btn = el('button', { type: 'button', class: 'ti-row-btn', 'aria-expanded': 'false', 'aria-controls': id }, [
        cve,
        el('span', { class: 'ti-prod' }, [
          document.createTextNode(r.vendor + ' ' + r.product),
          el('small', { text: r.name })
        ]),
        el('span', { class: 'ti-type', text: r.type }),
        el('span', { class: 'ti-date', text: formatDate(r.added) }),
        el('i', { class: 'fas fa-chevron-down', 'aria-hidden': 'true' })
      ]);

      var meta = el('dl', {}, [
        el('div', {}, [el('dt', { text: 'Added' }), el('dd', { text: formatDate(r.added) })]),
        r.due ? el('div', {}, [el('dt', { text: 'CISA due date' }), el('dd', { text: formatDate(r.due) })]) : null,
        el('div', {}, [el('dt', { text: 'CWE' }), el('dd', { text: r.cwes.length ? r.cwes.join(', ') : 'None assigned' })]),
        el('div', {}, [el('dt', { text: 'Ransomware use' }), el('dd', { text: r.ransomware ? 'Known' : 'Unknown' })])
      ]);
      var link = el('a', { href: 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(r.cve),
        target: '_blank', rel: 'noopener', text: 'View ' + r.cve + ' on NVD' });
      var detail = el('div', { class: 'ti-detail', id: id, hidden: '' }, [
        el('p', { text: r.description }), meta, el('p', {}, [link])
      ]);

      btn.addEventListener('click', function () {
        var open = btn.getAttribute('aria-expanded') === 'true';
        btn.setAttribute('aria-expanded', String(!open));
        detail.hidden = open;
      });
      return el('div', { class: 'ti-row' }, [btn, detail]);
    }

    function render() {
      var hits = rows.filter(matches);
      host.textContent = '';
      host.appendChild(el('div', { class: 'ti-row-head', 'aria-hidden': 'true' }, [
        el('span', { text: 'CVE' }),
        el('span', { text: 'Product' }),
        el('span', { text: 'Attack type' }),
        el('span', { text: 'Added' }),
        el('span', {})
      ]));
      hits.slice(0, shown).forEach(function (r, i) { host.appendChild(rowNode(r, i)); });
      if (!hits.length) host.appendChild(el('p', { class: 'ti-empty', text: 'No entries match these filters.' }));
      $('ti-count').textContent = 'Showing ' + fmt(Math.min(shown, hits.length)) + ' of ' + fmt(hits.length) +
        ' recent additions';
      more.hidden = hits.length <= shown;
    }

    function reset() { shown = PAGE_SIZE; render(); }
    q.addEventListener('input', reset);
    typeSel.addEventListener('change', reset);
    ransom.addEventListener('change', reset);
    more.addEventListener('click', function () { shown += PAGE_SIZE; render(); });
    render();
  }

  /* ---------- Page ---------- */

  function tiles(kev) {
    var host = $('ti-tiles');
    var pct = kev.totals.all ? Math.round((kev.totals.ransomware / kev.totals.all) * 100) : 0;
    [
      { label: 'Known exploited vulnerabilities', value: kev.totals.all, note: 'In the CISA catalog' },
      { label: 'Added in the last 30 days', value: kev.totals.last30, note: 'Newly confirmed in the wild' },
      { label: 'Linked to ransomware', value: kev.totals.ransomware, note: pct + '% of the catalog' }
    ].forEach(function (t) {
      host.appendChild(el('div', { class: 'ti-tile' }, [
        el('div', { class: 'ti-tile-label', text: t.label }),
        el('div', { class: 'ti-tile-value', text: fmt(t.value) }),
        el('div', { class: 'ti-tile-note', text: t.note })
      ]));
    });
  }

  function render(data) {
    var kev = data.kev;
    var generated = new Date(data.generated);
    $('ti-meta').textContent = 'Catalog version ' + kev.catalogVersion + ' · snapshot taken ' +
      (isNaN(generated) ? data.generated : generated.toLocaleString('en-AU', { dateStyle: 'medium', timeStyle: 'short' }));

    tiles(kev);

    var muted = ['Input validation (generic)', 'Other', 'No CWE assigned'];
    var range = 'last12';
    function drawTypes() {
      var rows = kev.attackTypes[range];
      hbars($('ti-types'), rows, { muted: muted, share: true, unitLabel: 'Vulnerabilities', unit: 'vulnerabilities' });
      dataTable($('ti-types-table'), ['Attack type', 'Vulnerabilities'], rows.map(function (r) { return [r.name, r.count]; }));
    }
    root.querySelectorAll('.ti-seg button').forEach(function (b) {
      b.addEventListener('click', function () {
        range = b.getAttribute('data-range');
        root.querySelectorAll('.ti-seg button').forEach(function (o) { o.setAttribute('aria-pressed', String(o === b)); });
        drawTypes();
      });
    });
    drawTypes();

    var partial = data.generated ? data.generated.slice(0, 7) : null;
    var drawTrend = function () { columns($('ti-trend'), kev.monthly, partial); };
    drawTrend();
    var resizeTimer;
    window.addEventListener('resize', function () {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(drawTrend, 150);
    });
    dataTable($('ti-trend-table'), ['Month', 'Total', 'Ransomware-linked'], kev.monthly.map(function (m) {
      return [monthLabel(m.month, true), m.total, m.ransomware];
    }));

    $('ti-vendors-sub').textContent = 'Vendors with the most exploited vulnerabilities added in ' + kev.topVendors.year + '.';
    hbars($('ti-vendors'), kev.topVendors.rows, { unitLabel: 'Added this year', unit: 'added this year' });
    dataTable($('ti-vendors-table'), ['Vendor', 'Added this year'], kev.topVendors.rows.map(function (r) { return [r.name, r.count]; }));

    if (data.threatfox && data.threatfox.families && data.threatfox.families.length) {
      $('ti-tf-card').hidden = false;
      $('ti-tf-credit').hidden = false;
      hbars($('ti-tf'), data.threatfox.families, { unitLabel: 'Indicators', unit: 'indicators' });
      dataTable($('ti-tf-table'), ['Malware family', 'Indicators'], data.threatfox.families.map(function (r) { return [r.name, r.count]; }));
    }

    latestTable(kev.latest);
  }

  fetch(root.getAttribute('data-src'), { cache: 'no-cache' })
    .then(function (res) {
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return res.json();
    })
    .then(render)
    .catch(function (err) {
      $('ti-meta').textContent = 'The threat intel snapshot could not be loaded (' + err.message + '). Please try again later.';
    });
})();
