/* NetSentinel Console
 *
 * Talks to the sensor over its REST API (/api/...) and WebSocket (/ws).
 * No build step and no dependencies: serve it from the sensor at /console/,
 * or open index.html directly and point Settings at the sensor URL.
 */
(function () {
  'use strict';

  // ---------------------------------------------------------------- helpers
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const store = {
    get(k, d) { try { const v = localStorage.getItem('ns.' + k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
    set(k, v) { try { localStorage.setItem('ns.' + k, JSON.stringify(v)); } catch (e) { /* storage unavailable */ } },
  };
  const fmtInt = (n) => (n == null || Number.isNaN(+n)) ? '—' : Math.round(+n).toLocaleString('en-US');
  const fmtNum = (n, d) => (n == null || Number.isNaN(+n)) ? '—' : (+n).toFixed(d == null ? 2 : d);
  const pad = (n, w) => String(n).padStart(w || 2, '0');
  const short = (h, a, b) => { if (!h) return '—'; const s = String(h).replace(/^sha256:/, ''); return s.length > a + b + 1 ? s.slice(0, a) + '…' + s.slice(-b) : s; };
  const plural = (n, one, many) => fmtInt(n) + ' ' + (n === 1 ? one : (many || one + 's'));

  const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
  const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
  const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

  const MODEL_SHORT = {
    ddos_binary_xgboost: 'XGBoost',
    ddos_rate_entropy: 'Rate/entropy',
    dga_cnn_bilstm_v2: 'CNN-BiLSTM',
    dga_cnn_bilstm: 'CNN-BiLSTM',
    c2_beacon_bilstm: 'BiLSTM+FFT',
    c2_combined_score_v2: 'C2 score v2',
    dns_behaviour_rules: 'DNS rules',
    tls_session_profile: 'TLS profile',
    exfil_vae: 'VAE',
    exfil_byte_ratio: 'Byte ratio',
    ett_transformer: 'FT-Transformer',
    portscan_spsd: 'SPSD tree',
    portscan_upsd: 'UPSD',
    portscan_fanout: 'Fan-out',
  };

  // PS 26145 threat families. The sensor's /api/ps26145 is authoritative;
  // this copy lets a saved session file be read without the sensor.
  const PS = [
    { id: 'a', title: 'DDoS', classes: ['DDoS'], ps: 'SYN floods, UDP reflection/amplification, spoofed traffic', det: 'XGBoost · rate / source-IP entropy window' },
    { id: 'b', title: 'C2 beaconing', classes: ['C2 Beacon'], ps: 'periodic check-ins', det: 'Combined periodicity score · BiLSTM+FFT as evidence' },
    { id: 'c', title: 'DGA and DNS tunnelling', classes: ['DGA', 'DNS Tunnel'], ps: 'entropy, n-grams, query length, record types', det: 'CNN-BiLSTM names · NXDOMAIN / record-type / fan-out rules' },
    { id: 'd', title: 'Malware in encrypted sessions', classes: ['Encrypted Malware'], ps: 'JA3/JA3S/JA4, packet-size and timing sequences', det: 'JA3/JA4 rarity · session size/timing · hello anomalies' },
    { id: 'e', title: 'Recon and port scans', classes: ['Port Scan'], ps: 'fan-out across ports or hosts', det: 'SPSD decision tree · port fan-out · host sweep' },
    { id: 'f', title: 'Data exfiltration', classes: ['Data Exfiltration'], ps: 'asymmetric volume, out/in byte ratio', det: 'Out/in byte ratio · VAE on DNS names' },
  ];
  const PS_OF_CLASS = {};
  for (const f of PS) for (const c of f.classes) PS_OF_CLASS[c] = f.id;

  // detector -> (kind, PS family, metric latency names)
  const DETECTORS = [
    { key: 'ddos', kind: 'model', name: 'DDoS classifier', model: 'XGBoost, 59 flow features (CIC-DDoS2019)', ps: 'a', det: ['ddos_binary_xgboost'], lat: ['ddos_xgboost'] },
    { key: 'ddos_rate_entropy', kind: 'rule', name: 'DDoS rate / entropy window', model: 'per-destination 10 s window', ps: 'a', det: ['ddos_rate_entropy'], lat: ['ddos_window', 'ddos_rule'] },
    { key: 'c2_combined', kind: 'rule', name: 'C2 combined score', model: 'timing, FFT, size, rarity, persistence', ps: 'b', det: ['c2_combined_score_v2'], lat: ['c2_combined'] },
    { key: 'c2', kind: 'model', name: 'C2 sequence model', model: 'BiLSTM + FFT (evidence only)', ps: 'b', det: ['c2_beacon_bilstm'], lat: ['c2_bilstm'] },
    { key: 'dga', kind: 'model', name: 'DGA / tunnel names', model: 'character CNN-BiLSTM', ps: 'c', det: ['dga_cnn_bilstm_v2', 'dga_cnn_bilstm'], lat: ['dga_cnn_bilstm'] },
    { key: 'dns_behaviour', kind: 'rule', name: 'DNS behaviour', model: 'NXDOMAIN rate, record types, fan-out', ps: 'c', det: ['dns_behaviour_rules'], lat: ['dns_behaviour'] },
    { key: 'tls_sessions', kind: 'rule', name: 'Encrypted sessions', model: 'JA3/JA3S/JA4 + session profile', ps: 'd', det: ['tls_session_profile'], lat: ['tls_sessions'] },
    { key: 'port_scan', kind: 'rule', name: 'Port scan / host sweep', model: 'SPSD tree + fan-out backstops', ps: 'e', det: ['portscan_spsd', 'portscan_upsd', 'portscan_fanout'], lat: ['portscan_window'] },
    { key: 'exfil_ratio', kind: 'rule', name: 'Exfiltration by volume', model: 'out/in byte ratio', ps: 'f', det: ['exfil_byte_ratio'], lat: ['exfil_ratio'] },
    { key: 'exfiltration', kind: 'model', name: 'DNS exfiltration', model: 'VAE, 24 name features', ps: 'f', det: ['exfil_vae'], lat: ['exfil_vae'] },
    { key: 'ett', kind: 'model', name: 'Encrypted-traffic apps', model: 'FT-Transformer (telemetry)', ps: '', det: ['ett_transformer'], lat: ['ett_transformer'] },
  ];
  const MODEL_LOADED_KEY = { ddos: 'ddos', c2: 'c2_beacon', dga: 'dga', ett: 'encrypted_traffic', exfiltration: 'exfiltration' };

  // ---------------------------------------------------------------- settings
  function defaultBackend() {
    if (/^https?:$/.test(location.protocol) && location.pathname.indexOf('/console') === 0) return location.origin;
    return 'http://localhost:8000';
  }
  const cfg = {
    backend: store.get('backend', '') || defaultBackend(),
    theme: store.get('theme', 'system'),
    tz: store.get('tz', 'utc'),
    max: store.get('max', 5000),
    maskIp: store.get('maskIp', false),
    maskDomain: store.get('maskDomain', false),
  };
  function applyTheme() {
    if (cfg.theme === 'light' || cfg.theme === 'dark') document.documentElement.setAttribute('data-theme', cfg.theme);
    else document.documentElement.removeAttribute('data-theme');
  }
  applyTheme();

  // ---------------------------------------------------------------- state
  const state = {
    alerts: [],            // normalized, oldest first
    ids: new Set(),
    arrived: new Map(),    // id -> arrival time (for the fresh-row highlight)
    queue: [],             // raw alerts waiting for the next render tick
    held: [],              // raw alerts received while paused
    paused: false,
    group: false,
    sevOn: { critical: true, high: true, medium: true, low: true, info: true },
    cls: '',
    filterText: '',
    range: null,           // [t0, t1) from the histogram
    sort: { key: 'time', dir: -1 },
    rows: [],              // current grid rows (alerts or groups)
    selected: null,        // id of selected alert (or group key when grouped)
    detailFor: null,
    health: null, stats: null, extractor: null,
    ledger: null, checkpoints: null,
    sensorId: null,
    simMode: null, simSeenAt: 0,
    replay: null,
    liveIface: null,
    offline: false, offlineName: '',
    conn: 'connecting',
    lastEventAt: null,
    view: 'overview',
    metrics: null, ps: null, detectors: null, bench: null, tier2: null, t2demo: null, t2lines: [], figs: null,
    dirty: { grid: true, histo: true, hosts: true, models: true, integrity: true, ingest: true, chrome: true, overview: true, tier2: true, figs: true },
    hostSort: { key: 'last', dir: -1 },
  };

  // ---------------------------------------------------------------- formatting
  function fmtTime(ms, withDate) {
    const d = new Date(ms);
    if (Number.isNaN(d.getTime())) return '—';
    if (cfg.tz === 'utc') {
      const iso = d.toISOString();
      return withDate ? iso.slice(0, 10) + ' ' + iso.slice(11, 23) + ' UTC' : iso.slice(11, 23);
    }
    const t = pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()) + '.' + pad(d.getMilliseconds(), 3);
    return withDate ? d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + t : t;
  }
  function fmtClock(ms, secs) {
    const d = new Date(ms);
    if (cfg.tz === 'utc') {
      const iso = d.toISOString();
      return secs ? iso.slice(11, 19) : iso.slice(11, 16);
    }
    return pad(d.getHours()) + ':' + pad(d.getMinutes()) + (secs ? ':' + pad(d.getSeconds()) : '');
  }
  function fmtAgo(ms) {
    const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
    if (s < 60) return s + ' s ago';
    if (s < 3600) return Math.floor(s / 60) + ' min ago';
    return Math.floor(s / 3600) + ' h ago';
  }
  function fmtRate(n, unit) {
    if (n == null || Number.isNaN(+n)) return '—';
    const v = +n;
    if (v >= 1e9) return (v / 1e9).toFixed(1) + ' G' + unit;
    if (v >= 1e6) return (v / 1e6).toFixed(1) + ' M' + unit;
    if (v >= 1e3) return (v / 1e3).toFixed(1) + ' k' + unit;
    return v.toFixed(0) + ' ' + unit;
  }

  // Masking for screen recordings
  const V4 = /\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b/g;
  const V6 = /\b([0-9a-f]{1,4}):([0-9a-f]{0,4})(?::[0-9a-f]{0,4}){2,6}\b/gi;
  function mIp(ip) {
    if (!ip || !cfg.maskIp) return ip || '';
    if (ip.indexOf(':') >= 0) { const p = ip.split(':'); return p[0] + ':' + p[1] + ':…'; }
    const p = ip.split('.');
    return p.length === 4 ? p[0] + '.' + p[1] + '.x.x' : ip;
  }
  function mDomain(d) {
    if (!d || !cfg.maskDomain) return d || '';
    const p = d.split('.');
    if (p.length < 2) return '•••';
    return p.slice(0, -1).map((x) => '•'.repeat(Math.max(3, Math.min(x.length, 8)))).join('.') + '.' + p[p.length - 1];
  }
  function mText(s, domain) {
    let t = String(s);
    if (cfg.maskIp) t = t.replace(V4, '$1.$2.x.x').replace(V6, '$1:$2:…');
    if (cfg.maskDomain && domain) t = t.split(domain).join(mDomain(domain));
    return t;
  }

  function isInternal(ip) {
    if (!ip) return false;
    if (ip.indexOf(':') >= 0) { const l = ip.toLowerCase(); return l === '::1' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80'); }
    const p = ip.split('.').map(Number);
    if (p.length !== 4) return false;
    return p[0] === 10 || p[0] === 127 || (p[0] === 192 && p[1] === 168) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 169 && p[1] === 254);
  }

  // ---------------------------------------------------------------- alerts
  function normalize(raw) {
    const f = raw.flow || {};
    const e = raw.evidence || {};
    const sev = String(raw.severity || 'INFO').toLowerCase();
    const fid = raw.flow_id || {};
    const lat = raw.latency_ms || {};
    const a = {
      id: raw.id,
      ts: Date.parse(raw.timestamp) || Date.now(),
      evTs: raw.event_time ? Date.parse(raw.event_time) : null,
      cls: raw.threat_class || 'Unknown',
      sub: raw.threat_subtype || '',
      sev: SEV_RANK[sev] == null ? 'info' : sev,
      score: raw.confidence == null ? null : +raw.confidence,
      confKind: raw.confidence_kind || '',
      src: raw.source_ip || f.src_ip || fid.src_ip || '',
      dst: raw.dest_ip || f.dst_ip || fid.dst_ip || '',
      sport: +(fid.src_port || f.src_port) || 0,
      dport: +(fid.dst_port || f.dst_port) || 0,
      proto: fid.protocol || f.protocol || '',
      model: raw.detector || raw.model_name || '',
      ps: raw.ps_category || PS_OF_CLASS[raw.threat_class] || '',
      scope: fid.scope || '',
      cid: fid.community_id || '',
      lat: lat.ingest_to_alert != null ? +lat.ingest_to_alert : (lat.pipeline != null ? +lat.pipeline : null),
      mitre: raw.mitre || null,
      ev: e,
      receipt: raw.receipt_ref || null,
      domain: e.domain || e.base_domain || fid.domain || e.query || e.qname || '',
      raw: raw,
    };
    a.hay = [a.cls, a.sub, a.src, a.dst, a.domain, a.model, a.cid, a.ps ? 'ps:' + a.ps : '', e.ja4, e.ja3, e.sni, a.mitre && a.mitre.technique, a.mitre && a.mitre.name, a.id].join(' ').toLowerCase();
    return a;
  }
  function showSub(a) {
    const s = (a.sub || '').trim();
    if (!s) return '';
    const l = s.toLowerCase();
    if (l === 'benign' || l === a.cls.toLowerCase()) return '';
    return s;
  }
  const SCOPE_LABEL = { flow: 'flow', host_pair: 'host pair', source: 'source host', destination: 'destination', dns_query: 'DNS query' };
  function fmtMs(v) {
    if (v == null || Number.isNaN(+v)) return '—';
    v = +v;
    if (v >= 10000) return (v / 1000).toFixed(1) + ' s';
    if (v >= 100) return Math.round(v) + ' ms';
    return v.toFixed(v >= 10 ? 1 : 2) + ' ms';
  }
  function modelLabel(a) {
    if (MODEL_SHORT[a.model]) return MODEL_SHORT[a.model];
    if ((!a.model || a.model === 'unknown') && a.cls === 'Port Scan') return 'Scan router';
    return a.model || '—';
  }
  function portLabel(a) {
    if (a.dport) return a.dport + (a.proto ? '/' + a.proto : '');
    return a.proto || '—';
  }

  function ingest(raws, fresh) {
    const now = Date.now();
    let added = 0;
    for (const r of raws) {
      if (!r || !r.id || state.ids.has(r.id)) continue;
      const a = normalize(r);
      state.alerts.push(a);
      state.ids.add(a.id);
      if (fresh) { state.arrived.set(a.id, now); state.lastEventAt = now; }
      added++;
    }
    if (!added) return;
    // keep chronological order (backfill may arrive newest-first)
    const n = state.alerts.length;
    if (n > 1 && state.alerts[n - 1].ts < state.alerts[n - 2].ts) state.alerts.sort((x, y) => x.ts - y.ts);
    const over = state.alerts.length - cfg.max;
    if (over > 0) {
      for (const a of state.alerts.splice(0, over)) { state.ids.delete(a.id); state.arrived.delete(a.id); }
    }
    markAll();
  }
  function markAll() { for (const k in state.dirty) state.dirty[k] = true; }

  // ---------------------------------------------------------------- filtering
  function parseFilter(text) {
    const q = { terms: [], cls: null, sev: null, sevMin: null, src: null, dst: null, ip: null, port: null, mitre: null, model: null, ps: null };
    for (const tok of text.trim().split(/\s+/).filter(Boolean)) {
      const m = tok.match(/^([a-z]+)(:|>=|=)(.+)$/i);
      if (!m) { q.terms.push(tok.toLowerCase()); continue; }
      const k = m[1].toLowerCase(), op = m[2], v = m[3];
      if (k === 'class' || k === 'cls') q.cls = v.toLowerCase();
      else if (k === 'sev' || k === 'severity') { if (op === '>=') q.sevMin = v.toLowerCase(); else q.sev = v.toLowerCase(); }
      else if (k === 'src') q.src = v;
      else if (k === 'dst') q.dst = v;
      else if (k === 'ip' || k === 'host') q.ip = v;
      else if (k === 'port') q.port = +v;
      else if (k === 'mitre' || k === 'attack') q.mitre = v.toUpperCase();
      else if (k === 'model' || k === 'det' || k === 'detector') q.model = v.toLowerCase();
      else if (k === 'ps') q.ps = v.toLowerCase().replace(/[^a-f]/g, '');
      else q.terms.push(tok.toLowerCase());
    }
    return q;
  }
  function sevMatch(a, v) { return a.sev.indexOf(v) === 0; }
  function matches(a, q, useRange) {
    if (!state.sevOn[a.sev]) return false;
    if (state.cls && a.cls !== state.cls) return false;
    if (useRange && state.range && (a.ts < state.range[0] || a.ts >= state.range[1])) return false;
    if (q.cls && a.cls.toLowerCase().indexOf(q.cls) < 0) return false;
    if (q.sev && !sevMatch(a, q.sev)) return false;
    if (q.sevMin && SEV_RANK[a.sev] < (SEV_RANK[q.sevMin] == null ? 0 : SEV_RANK[q.sevMin])) return false;
    if (q.src && a.src.indexOf(q.src) !== 0) return false;
    if (q.dst && a.dst.indexOf(q.dst) !== 0 && a.domain.indexOf(q.dst) < 0) return false;
    if (q.ip && a.src.indexOf(q.ip) !== 0 && a.dst.indexOf(q.ip) !== 0) return false;
    if (q.port && a.dport !== q.port && a.sport !== q.port) return false;
    if (q.mitre && !((a.mitre && a.mitre.technique) || '').toUpperCase().startsWith(q.mitre)) return false;
    if (q.model && a.model.toLowerCase().indexOf(q.model) < 0 && modelLabel(a).toLowerCase().indexOf(q.model) < 0) return false;
    if (q.ps && q.ps.indexOf(a.ps || '-') < 0) return false;
    for (const t of q.terms) if (a.hay.indexOf(t) < 0) return false;
    return true;
  }

  const SORTERS = {
    time: (a) => a.ts,
    count: (a) => a.count || 1,
    sev: (a) => SEV_RANK[a.sev] * 1e13 + a.ts,
    cls: (a) => a.cls,
    src: (a) => a.src,
    dst: (a) => a.domain || a.dst,
    port: (a) => a.dport,
    model: (a) => modelLabel(a),
    score: (a) => a.score == null ? -1 : a.score,
    mitre: (a) => (a.mitre && a.mitre.technique) || '',
    receipt: (a) => a.receipt ? 1 : 0,
    lat: (a) => a.lat == null ? -1 : a.lat,
    fid: (a) => a.cid || a.scope,
  };

  function buildRows() {
    const q = parseFilter(state.filterText);
    let list = state.alerts.filter((a) => matches(a, q, true));
    if (state.group) {
      const groups = new Map();
      for (const a of list) {
        const key = a.cls + '|' + a.src + '|' + (a.domain || a.dst);
        let g = groups.get(key);
        if (!g) { g = { key: key, latest: a, first: a.ts, count: 0, maxSev: a.sev }; groups.set(key, g); }
        g.count++;
        if (a.ts >= g.latest.ts) g.latest = a;
        if (a.ts < g.first) g.first = a.ts;
        if (SEV_RANK[a.sev] > SEV_RANK[g.maxSev]) g.maxSev = a.sev;
      }
      list = Array.from(groups.values()).map((g) => Object.assign(Object.create(g.latest), { groupKey: g.key, count: g.count, first: g.first, sev: g.maxSev }));
    }
    const fn = SORTERS[state.sort.key] || SORTERS.time;
    const dir = state.sort.dir;
    list.sort((x, y) => { const a = fn(x), b = fn(y); return a < b ? -dir : a > b ? dir : (y.ts - x.ts); });
    state.rows = list;
  }
  function rowKey(r) { return r.groupKey || r.id; }

  // ---------------------------------------------------------------- alert grid
  const COLS_BASE = [
    { key: 'time', label: 'Time', w: '104px' },
    { key: 'sev', label: 'Severity', w: '90px' },
    { key: 'cls', label: 'Class', w: 'minmax(124px, 0.9fr)' },
    { key: 'src', label: 'Source', w: 'minmax(150px, 1fr)' },
    { key: 'dst', label: 'Destination', w: 'minmax(160px, 1.3fr)' },
    { key: 'port', label: 'Port', w: '92px' },
    { key: 'model', label: 'Model', w: '104px' },
    { key: 'score', label: 'Score', w: '62px', num: true },
    { key: 'lat', label: 'Latency', w: '76px', num: true },
    { key: 'mitre', label: 'ATT&CK', w: '70px' },
    { key: 'fid', label: 'Flow ID', w: '112px' },
    { key: 'receipt', label: 'Receipt', w: '68px' },
  ];
  // Columns that give way first when the table is narrow (e.g. a laptop screen with the detail pane open).
  const OPTIONAL = ['receipt', 'fid', 'model', 'mitre', 'lat', 'port'];
  const minW = (w) => { const m = /(\d+)px/.exec(w); return m ? +m[1] : 80; };
  function cols() {
    let c = COLS_BASE.slice();
    if (state.group) c.splice(1, 0, { key: 'count', label: 'Count', w: '62px', num: true });
    const avail = ($('#alertGrid').clientWidth || 1400) - 12;
    for (const k of OPTIONAL) {
      if (c.reduce((s, x) => s + minW(x.w), 0) <= avail) break;
      c = c.filter((x) => x.key !== k);
    }
    return c;
  }
  let colSig = '';
  const ROW_H = 26;
  const gridBody = $('#alertBody'), gridRows = $('#alertRows'), gridSpacer = $('#alertSpacer'), gridHead = $('#alertHead');

  function renderHead() {
    const c = cols();
    const tmpl = c.map((x) => x.w).join(' ');
    $('#alertGrid').style.setProperty('--cols', tmpl);
    gridHead.innerHTML = c.map((x) => {
      const arrow = state.sort.key === x.key ? '<span class="arrow">' + (state.sort.dir < 0 ? '▼' : '▲') + '</span>' : '';
      return '<div data-key="' + x.key + '"' + (x.num ? ' class="num"' : '') + '>' + esc(x.label) + arrow + '</div>';
    }).join('');
  }
  function cellHtml(r, key) {
    switch (key) {
      case 'time': return '<div class="mono">' + fmtTime(r.ts) + '</div>';
      case 'count': return '<div class="num times-n">' + fmtInt(r.count) + '</div>';
      case 'sev': return '<div class="sev-cell"><span class="sq ' + r.sev + '"></span>' + SEV_LABEL[r.sev] + '</div>';
      case 'cls': { const s = showSub(r); return '<div>' + esc(r.cls) + (s ? '<span class="cls-sub">' + esc(s) + '</span>' : '') + '</div>'; }
      case 'src': return '<div class="mono">' + esc(mIp(r.src)) + (r.sport ? '<span class="dim">:' + r.sport + '</span>' : '') + '</div>';
      case 'dst': return r.domain ? '<div class="mono" title="' + esc(mDomain(r.domain)) + '">' + esc(mDomain(r.domain)) + '</div>' : '<div class="mono">' + esc(mIp(r.dst) || '—') + '</div>';
      case 'port': return '<div class="mono">' + esc(portLabel(r)) + '</div>';
      case 'model': return '<div>' + esc(modelLabel(r)) + '</div>';
      case 'score': return '<div class="num mono">' + (r.score == null ? '—' : r.score.toFixed(3)) + '</div>';
      case 'mitre': return '<div class="mono">' + esc((r.mitre && r.mitre.technique) || '—') + '</div>';
      case 'receipt': return '<div class="' + (r.receipt ? '' : 'dim') + '">' + (r.receipt ? 'Signed' : '—') + '</div>';
      case 'lat': return '<div class="num mono" title="Extractor emitted the event to alert created">' + (r.lat == null ? '—' : fmtMs(r.lat)) + '</div>';
      case 'fid': return r.cid ? '<div class="mono" title="Community ID ' + esc(r.cid) + '">' + esc(r.cid.slice(2, 12)) + '…</div>' : '<div class="dim">' + esc(SCOPE_LABEL[r.scope] || '—') + '</div>';
      default: return '<div></div>';
    }
  }
  function renderGrid() {
    const sig = cols().map((x) => x.key).join(',');
    if (sig !== colSig) { colSig = sig; renderHead(); }
    const rows = state.rows;
    gridSpacer.style.height = (rows.length * ROW_H) + 'px';
    const top = gridBody.scrollTop, h = gridBody.clientHeight || 600;
    const start = Math.max(0, Math.floor(top / ROW_H) - 8);
    const end = Math.min(rows.length, Math.ceil((top + h) / ROW_H) + 8);
    gridRows.style.transform = 'translateY(' + (start * ROW_H) + 'px)';
    const c = cols();
    const now = Date.now();
    let html = '';
    for (let i = start; i < end; i++) {
      const r = rows[i];
      const k = rowKey(r);
      let cls = 'grid-row';
      if (k === state.selected) cls += ' sel';
      let style = '';
      const at = state.arrived.get(r.id);
      if (at && now - at < 1200 && k !== state.selected) { cls += ' fresh'; style = ' style="animation-delay:-' + (now - at) + 'ms"'; }
      html += '<div class="' + cls + '" data-i="' + i + '"' + style + '>';
      for (const col of c) html += cellHtml(r, col.key);
      html += '</div>';
    }
    gridRows.innerHTML = html;
    renderEmpty();
  }
  function renderEmpty() {
    const el = $('#alertEmpty');
    if (state.rows.length) { el.innerHTML = ''; return; }
    let h;
    if (state.alerts.length) {
      h = '<div class="box"><h3>No alerts match</h3><p>Change the filter, severity or time range.</p><button class="btn" type="button" data-act="clear-filters">Clear filters</button></div>';
    } else if (state.offline) {
      h = '<div class="box"><h3>This session file has no alerts</h3></div>';
    } else if (state.conn === 'open') {
      h = '<div class="box"><h3>Connected. No alerts yet.</h3><p>Replay a capture or start live capture from the <b>Ingest</b> tab. Alerts appear here as the models raise them.</p></div>';
    } else {
      h = '<div class="box"><h3>Waiting for the sensor</h3><p>Nothing is answering at <code>' + esc(cfg.backend) + '</code>. Start it from the project folder with <code>python run.py</code>, or open a saved session.</p>' +
        '<div class="btn-row" style="justify-content:center"><button class="btn" type="button" data-act="retry">Retry now</button><button class="btn" type="button" data-act="open">Open session…</button><button class="btn btn-quiet" type="button" data-act="settings">Change sensor URL</button></div></div>';
    }
    el.innerHTML = h;
  }

  gridBody.addEventListener('scroll', () => requestAnimationFrame(renderGrid));
  gridHead.addEventListener('click', (ev) => {
    const d = ev.target.closest('[data-key]');
    if (!d) return;
    const k = d.getAttribute('data-key');
    if (state.sort.key === k) state.sort.dir = -state.sort.dir;
    else state.sort = { key: k, dir: (k === 'time' || k === 'sev' || k === 'score' || k === 'count') ? -1 : 1 };
    renderHead(); state.dirty.grid = true;
  });
  // mousedown, not click: rows are redrawn several times a second while alerts stream in,
  // and a click needs press and release on the same element.
  gridRows.addEventListener('mousedown', (ev) => {
    if (ev.button !== 0) return;
    const row = ev.target.closest('.grid-row');
    if (!row) return;
    const r = state.rows[+row.getAttribute('data-i')];
    if (r) select(rowKey(r));
  });
  $('#alertEmpty').addEventListener('click', (ev) => {
    const b = ev.target.closest('[data-act]');
    if (!b) return;
    const act = b.getAttribute('data-act');
    if (act === 'retry') { backoff = 1000; connect(); }
    else if (act === 'open') $('#openFile').click();
    else if (act === 'settings') openSettings();
    else if (act === 'clear-filters') clearFilters();
  });

  function select(key) {
    state.selected = key;
    state.dirty.grid = true;
    renderDetail(true);
    renderGrid();
  }
  function moveSelection(delta) {
    if (!state.rows.length) return;
    let i = state.rows.findIndex((r) => rowKey(r) === state.selected);
    i = i < 0 ? 0 : Math.max(0, Math.min(state.rows.length - 1, i + delta));
    select(rowKey(state.rows[i]));
    const y = i * ROW_H;
    if (y < gridBody.scrollTop) gridBody.scrollTop = y;
    else if (y + ROW_H > gridBody.scrollTop + gridBody.clientHeight) gridBody.scrollTop = y + ROW_H - gridBody.clientHeight;
  }
  function clearFilters() {
    state.filterText = ''; $('#filterInput').value = '';
    for (const s of SEVS) state.sevOn[s] = true;
    state.cls = ''; $('#classSelect').value = '';
    state.range = null;
    markAll();
  }

  // ---------------------------------------------------------------- toolbar
  function renderSevToggles() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const a of state.alerts) counts[a.sev]++;
    $('#sevToggles').innerHTML = SEVS.map((s) =>
      '<button type="button" class="sev-toggle' + (state.sevOn[s] ? '' : ' off') + '" data-sev="' + s + '"><span class="sq ' + s + '"></span>' + SEV_LABEL[s] + ' <span class="n">' + fmtInt(counts[s]) + '</span></button>').join('');
  }
  $('#sevToggles').addEventListener('click', (ev) => {
    const b = ev.target.closest('[data-sev]');
    if (!b) return;
    const s = b.getAttribute('data-sev');
    if (ev.altKey || ev.ctrlKey || ev.metaKey) { for (const x of SEVS) state.sevOn[x] = x === s; }
    else state.sevOn[s] = !state.sevOn[s];
    markAll();
  });
  function renderClassSelect() {
    const sel = $('#classSelect');
    const counts = new Map();
    for (const a of state.alerts) counts.set(a.cls, (counts.get(a.cls) || 0) + 1);
    const want = Array.from(counts.entries()).sort((x, y) => y[1] - x[1]);
    const sig = want.map((x) => x[0] + x[1]).join('|');
    if (sel.dataset.sig === sig) return;
    sel.dataset.sig = sig;
    const cur = state.cls;
    sel.innerHTML = '<option value="">All classes</option>' + want.map((x) => '<option value="' + esc(x[0]) + '">' + esc(x[0]) + ' (' + fmtInt(x[1]) + ')</option>').join('');
    sel.value = cur;
  }
  $('#classSelect').addEventListener('change', (ev) => { state.cls = ev.target.value; markAll(); });
  let filterTimer = null;
  $('#filterInput').addEventListener('input', (ev) => {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(() => { state.filterText = ev.target.value; markAll(); }, 120);
  });
  $('#groupToggle').addEventListener('change', (ev) => { state.group = ev.target.checked; state.selected = null; $('#detail').hidden = true; renderHead(); markAll(); });
  $('#pauseBtn').addEventListener('click', togglePause);
  function togglePause() {
    state.paused = !state.paused;
    if (!state.paused && state.held.length) { state.queue.push.apply(state.queue, state.held); state.held = []; }
    renderPause();
  }
  function renderPause() {
    const b = $('#pauseBtn');
    b.classList.toggle('on', state.paused);
    b.textContent = state.paused ? (state.held.length ? 'Resume (' + fmtInt(state.held.length) + ' new)' : 'Resume') : 'Pause';
  }
  $('#timeChipClear').addEventListener('click', () => { state.range = null; markAll(); });

  // ---------------------------------------------------------------- histogram
  const BUCKETS = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 21600].map((s) => s * 1000);
  let histo = null;
  function renderHisto() {
    const svg = $('#histoSvg');
    const W = Math.max(200, svg.clientWidth || 800), H = 44;
    const q = parseFilter(state.filterText);
    const list = state.alerts.filter((a) => matches(a, q, false));
    if (!list.length) {
      svg.innerHTML = '<text x="' + (W / 2) + '" y="' + (H / 2 + 4) + '" text-anchor="middle" fill="var(--text-3)" font-size="12">No alerts to chart</text>';
      svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
      $('#histoAxis').innerHTML = ''; $('#histoTitle').textContent = 'Alerts over time'; histo = null; return;
    }
    let t0 = list[0].ts, t1 = list[list.length - 1].ts;
    for (const a of list) { if (a.ts < t0) t0 = a.ts; if (a.ts > t1) t1 = a.ts; }
    const span = Math.max(1000, t1 - t0);
    let size = BUCKETS[BUCKETS.length - 1];
    for (const b of BUCKETS) { if (span / b <= 90) { size = b; break; } }
    // Right-align the buckets so the newest data sits at the right edge, like a live chart.
    const endIdx = Math.floor(t1 / size);
    const nb = endIdx - Math.floor(t0 / size) + 1;
    const nbShow = Math.max(nb, 30);
    const start = (endIdx - nbShow + 1) * size;
    const bins = Array.from({ length: nbShow }, () => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 }));
    for (const a of list) { const i = Math.floor((a.ts - start) / size); if (i >= 0 && i < nbShow) { bins[i][a.sev]++; bins[i].total++; } }
    let max = 1;
    for (const b of bins) if (b.total > max) max = b.total;
    const bw = W / nbShow;
    const gap = bw > 4 ? 1 : 0;
    let out = '';
    const order = ['info', 'low', 'medium', 'high', 'critical'];
    bins.forEach((b, i) => {
      let y = H;
      const x = i * bw;
      if (state.range && start + i * size >= state.range[0] && start + i * size < state.range[1]) out += '<rect class="sel" x="' + x.toFixed(1) + '" y="0" width="' + bw.toFixed(1) + '" height="' + H + '"/>';
      for (const s of order) {
        if (!b[s]) continue;
        const h = Math.max(1, b[s] / max * (H - 2));
        y -= h;
        out += '<rect class="b" x="' + (x + gap).toFixed(1) + '" y="' + y.toFixed(1) + '" width="' + Math.max(1, bw - gap * 2).toFixed(1) + '" height="' + h.toFixed(1) + '" fill="var(--sev-' + s + ')"/>';
      }
      out += '<rect class="hit" data-b="' + i + '" x="' + x.toFixed(1) + '" y="0" width="' + bw.toFixed(1) + '" height="' + H + '"/>';
    });
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    svg.innerHTML = out;
    histo = { start: start, size: size, bins: bins, bw: bw, W: W };
    const ticks = Math.min(8, nbShow);
    let axis = '';
    for (let k = 0; k <= ticks; k++) {
      const i = Math.round(k * (nbShow - 1) / ticks);
      const t = start + i * size;
      const lbl = size < 60000 ? fmtClock(t, true) : fmtClock(t, false);
      axis += '<span style="left:' + ((i + 0.5) * bw / W * 100).toFixed(2) + '%">' + lbl + '</span>';
    }
    $('#histoAxis').innerHTML = axis;
    const secs = size / 1000;
    $('#histoTitle').textContent = 'Alerts over time · ' + (secs < 60 ? secs + ' s' : (secs < 3600 ? secs / 60 + ' min' : secs / 3600 + ' h')) + ' buckets · peak ' + fmtInt(max);
  }
  $('#histoSvg').addEventListener('mousemove', (ev) => {
    const r = ev.target.closest('rect.hit');
    const tip = $('#histoTip');
    if (!r || !histo) { tip.hidden = true; return; }
    const i = +r.getAttribute('data-b');
    const b = histo.bins[i];
    const t = histo.start + i * histo.size;
    tip.innerHTML = '<div class="t">' + fmtClock(t, true) + ' – ' + fmtClock(t + histo.size, true) + '</div>' +
      (b.total ? SEVS.filter((s) => b[s]).map((s) => '<div class="r"><span class="sq ' + s + '"></span>' + SEV_LABEL[s] + ': ' + fmtInt(b[s]) + '</div>').join('') : '<div class="r dim">No alerts</div>');
    tip.hidden = false;
    const box = $('#histo').getBoundingClientRect();
    let x = ev.clientX - box.left + 12;
    if (x > box.width - 180) x -= 200;
    tip.style.left = x + 'px';
  });
  $('#histoSvg').addEventListener('mouseleave', () => { $('#histoTip').hidden = true; });
  $('#histoSvg').addEventListener('click', (ev) => {
    const r = ev.target.closest('rect.hit');
    if (!r || !histo) return;
    const i = +r.getAttribute('data-b');
    const t = histo.start + i * histo.size;
    if (state.range && state.range[0] === t) state.range = null;
    else state.range = [t, t + histo.size];
    markAll();
  });
  function renderTimeChip() {
    const chip = $('#timeChip');
    if (!state.range) { chip.hidden = true; return; }
    chip.hidden = false;
    $('#timeChipText').textContent = fmtClock(state.range[0], true) + ' – ' + fmtClock(state.range[1], true);
  }

  // ---------------------------------------------------------------- detail pane
  function findSelected() {
    if (!state.selected) return null;
    return state.rows.find((r) => rowKey(r) === state.selected) || (state.group ? null : state.alerts.find((a) => a.id === state.selected)) || null;
  }
  function fmtBytes(n) {
    if (n == null || Number.isNaN(+n)) return '—';
    n = +n;
    if (n >= 1e9) return (n / 1e9).toFixed(2) + ' GB';
    if (n >= 1e6) return (n / 1e6).toFixed(2) + ' MB';
    if (n >= 1e3) return (n / 1e3).toFixed(1) + ' KB';
    return fmtInt(n) + ' B';
  }
  function pct(v) { return v == null ? '—' : Math.round(+v * 100) + '%'; }
  function summary(a) {
    const e = a.ev || {};
    const src = mIp(a.src), dst = mIp(a.dst);
    switch (a.cls) {
      case 'DDoS': {
        if (e.flow_rate_per_s != null) {
          const fam = e.family ? e.family + (e.spoofed_sources_likely ? ' from spoofed-looking sources' : '') : 'flood';
          return fam + ' toward ' + (dst || 'one host') + ': ' + fmtNum(e.flow_rate_per_s, 0) + ' flows/s from ' + plural(e.distinct_sources || 0, 'source') + ' (source entropy ' + fmtNum(e.src_ip_entropy, 2) + ' bits).';
        }
        const bits = e.bps != null ? ' (' + fmtRate(e.bps, 'B/s') + ')' : '';
        return e.pps != null ? fmtRate(e.pps, 'packets/s') + bits + ' toward ' + dst + '.' : 'Flood toward ' + dst + '.';
      }
      case 'DGA': case 'DNS Tunnel': {
        if (e.rule === 'nxdomain_burst') return src + ': ' + fmtInt(e.nxdomain_replies) + ' of ' + fmtInt(e.replies) + ' replies were NXDOMAIN, across ' + plural(e.nxdomain_base_domains || 0, 'domain') + ' in ' + Math.round((e.window_s || 300) / 60) + ' min.';
        if (e.rule === 'record_type_anomaly') return src + ' sent ' + fmtInt(e.queries) + ' queries under ' + mDomain(e.base_domain) + ', ' + pct(e.rare_type_share) + ' of them ' + Object.keys(e.qtype_mix || {}).slice(0, 2).join('/') + ', ' + plural(e.unique_names || 0, 'distinct name') + '.';
        if (e.rule === 'subdomain_fanout') return src + ' queried ' + plural(e.unique_names || 0, 'distinct name') + ' under ' + mDomain(e.base_domain) + ' (leftmost labels ' + fmtNum(e.mean_label_len, 0) + ' characters on average).';
        const p = e.all_probs && (a.cls === 'DGA' ? e.all_probs.dga : e.all_probs.dns_tunnel);
        return 'DNS query for ' + (mDomain(a.domain) || 'an unknown name') + ' from ' + src + (p != null ? ' looks machine-generated (p = ' + fmtNum(p, 2) + ').' : '.');
      }
      case 'C2 Beacon': {
        const it = beaconGap(e);
        if (e.score != null) return src + ' checks in with ' + dst + (it ? ' about every ' + fmtNum(it, 1) + ' s' : '') + ': combined score ' + fmtNum(e.score, 3) + ' over ' + plural(e.checkins || 0, 'check-in') + ' (threshold ' + fmtNum(e.threshold, 2) + ').';
        return src + ' checks in with ' + dst + (it ? ' about every ' + fmtNum(it, 1) + ' s' : ' on a fixed schedule') + (e.coefficient_of_variation != null ? ' (timing CV ' + fmtNum(e.coefficient_of_variation, 2) + ').' : '.');
      }
      case 'Encrypted Malware': {
        if (e.blocklist) return src + ' used a blocklisted ' + String(e.blocklist.kind || '').toUpperCase() + ' (' + e.blocklist.label + ') talking to ' + dst + '.';
        return src + ' → ' + dst + ': ' + plural(e.sessions || 0, 'TLS session') + ' with a client fingerprint ' + (e.clients_with_fingerprint === 1 ? 'no other host here uses' : 'few hosts use') + ', at regular intervals' + (e.median_interval_s ? ' (~' + fmtNum(e.median_interval_s, 0) + ' s)' : '') + '.';
      }
      case 'Data Exfiltration': {
        const br = e.byte_ratio;
        if (e.out_in_ratio != null && br) return src + ' sent ' + fmtBytes(br.outbound) + ' to ' + dst + ' and received ' + fmtBytes(br.inbound) + ' (' + fmtNum(e.out_in_ratio, 1) + ':1) in ' + Math.round((e.window_s || 900) / 60) + ' min.';
        const kind = e.anomaly_type ? String(e.anomaly_type).replace(/_/g, ' ') : 'unusual outbound volume';
        return src + ': ' + kind + (br ? ', ' + fmtInt(br.outbound) + ' B out vs ' + fmtInt(br.inbound) + ' B in' : '') + (e.subdomain_length ? ', ' + e.subdomain_length + '-character subdomains' : '') + '.';
      }
      case 'Port Scan': {
        const x = e.evidence || {};
        if (x.sweep_hosts >= 32 && e.scan_type === 'horizontal') return src + ' probed port ' + x.sweep_port + ' on ' + plural(x.sweep_hosts, 'host') + ' in one minute.';
        const ports = x.distinct_ports, hosts = x.distinct_dst_ips;
        return src + ' probed ' + (ports != null ? plural(ports, 'port') : 'many ports') + (hosts != null ? ' on ' + plural(hosts, 'host') : '') + (e.scan_type ? ' (' + e.scan_type + ' scan)' : '') + '.';
      }
      default:
        return a.cls + ' from ' + src + (dst ? ' to ' + dst : '') + '.';
    }
  }
  function beaconGap(e) {
    if (e.median_gap_s != null) return e.median_gap_s;
    if (Array.isArray(e.iat) && e.iat.length) { const s = e.iat.slice().sort((x, y) => x - y); return s[Math.floor(s.length / 2)]; }
    return e.beacon_interval || e.periodicity_seconds || null;
  }
  function kvHtml(pairs) {
    return '<dl class="kv">' + pairs.filter((p) => p && p[1] != null && p[1] !== '').map((p) => '<dt>' + esc(p[0]) + '</dt><dd' + (p[2] ? ' class="mono"' : '') + '>' + p[1] + '</dd>').join('') + '</dl>';
  }
  function probBars(probs, hotKey) {
    const keys = Object.keys(probs);
    return keys.map((k) => {
      const v = +probs[k];
      return '<div class="prob-row"><span>' + esc(k.replace(/_/g, ' ')) + '</span><div class="prob-track"><div class="prob-fill' + (k === hotKey ? ' hot' : '') + '" style="width:' + (Math.max(0, Math.min(1, v)) * 100).toFixed(1) + '%"></div></div><span class="v">' + fmtNum(v, 3) + '</span></div>';
    }).join('');
  }
  function countBars(obj, hotSet) {
    const keys = Object.keys(obj || {});
    const max = Math.max(1, ...keys.map((k) => +obj[k] || 0));
    return keys.map((k) => '<div class="prob-row"><span>' + esc(k) + '</span><div class="prob-track"><div class="prob-fill' + (hotSet && hotSet.has(k) ? ' hot' : '') + '" style="width:' + ((+obj[k] || 0) / max * 100).toFixed(1) + '%"></div></div><span class="v">' + fmtInt(obj[k]) + '</span></div>').join('');
  }
  const COMP_LABEL = { T: 'timing (T)', F: 'FFT (F)', S: 'size (S)', R: 'rarity (R)', C: 'persistence (C)', P: 'shape (P)', H: 'hello (H)' };
  const COMP_WEIGHT_KEY = { R: 'rarity', T: 'timing', S: 'size', P: 'shape', H: 'hello' };
  function compBars(comp, weights) {
    return Object.keys(comp || {}).map((k) => {
      const v = +comp[k];
      const w = weights ? (weights[k] != null ? weights[k] : weights[COMP_WEIGHT_KEY[k]]) : null;
      return '<div class="prob-row"><span>' + esc(COMP_LABEL[k] || k) + '</span><div class="prob-track"><div class="prob-fill hot" style="width:' + (Math.max(0, Math.min(1, v)) * 100).toFixed(1) + '%"></div></div><span class="v">' + fmtNum(v, 2) + (w != null ? ' ×' + fmtNum(w, 2) : '') + '</span></div>';
    }).join('');
  }
  function byteBars(out, inb) {
    const max = Math.max(1, out, inb);
    const row = (label, v, hot) => '<div class="prob-row"><span>' + label + '</span><div class="prob-track"><div class="prob-fill' + (hot ? ' hot' : '') + '" style="width:' + (v / max * 100).toFixed(1) + '%"></div></div><span class="v">' + fmtBytes(v) + '</span></div>';
    return row('outbound', out, out > inb) + row('inbound', inb, false);
  }
  function iatSvg(iat) {
    const n = iat.length;
    if (n < 2) return '';
    const W = 420, H = 70, padL = 34, padR = 6, padT = 6, padB = 14;
    let lo = Math.min.apply(null, iat), hi = Math.max.apply(null, iat);
    const mean = iat.reduce((s, v) => s + v, 0) / n;
    if (hi - lo < 1e-6) { lo -= 1; hi += 1; }
    const m = (hi - lo) * 0.15; lo -= m; hi += m;
    const x = (i) => padL + i / (n - 1) * (W - padL - padR);
    const y = (v) => padT + (1 - (v - lo) / (hi - lo)) * (H - padT - padB);
    let s = '<svg class="iat-svg" viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none">';
    s += '<line class="mean" x1="' + padL + '" x2="' + (W - padR) + '" y1="' + y(mean).toFixed(1) + '" y2="' + y(mean).toFixed(1) + '"/>';
    for (let i = 0; i < n; i++) s += '<circle class="dotp" cx="' + x(i).toFixed(1) + '" cy="' + y(iat[i]).toFixed(1) + '" r="2.4"/>';
    s += '<text x="2" y="' + (padT + 8) + '">' + fmtNum(hi, 1) + 's</text><text x="2" y="' + (H - padB) + '">' + fmtNum(lo, 1) + 's</text>';
    s += '<text x="' + padL + '" y="' + (H - 2) + '">check-in 1</text><text x="' + (W - padR - 44) + '" y="' + (H - 2) + '">' + n + '</text>';
    return s + '</svg>';
  }
  function evidenceHtml(a) {
    const e = a.ev || {};
    let h = '';
    switch (a.cls) {
      case 'DDoS':
        h += kvHtml([
          ['Attack family', e.family ? esc(e.family) + (e.family_basis === 'flow' ? ' <span class="dim">(from the flow; window still filling)</span>' : '') : null],
          ['Spoofed sources', e.spoofed_sources_likely != null ? (e.spoofed_sources_likely ? '<span class="fail-text">likely</span> <span class="dim">(' + pct(e.new_source_share) + ' of flows from a new source, ' + pct(e.handshake_share) + ' handshakes)</span>' : 'no sign') : null],
          ['Flow rate', e.flow_rate_per_s != null ? fmtNum(e.flow_rate_per_s, 1) + ' flows/s' + (e.baseline_flow_rate_per_s != null ? ' <span class="dim">(baseline ' + fmtNum(e.baseline_flow_rate_per_s, 1) + ')</span>' : '') : null],
          ['Packet rate', e.packet_rate_per_s != null ? fmtRate(e.packet_rate_per_s, 'pps') : (e.pps != null ? fmtRate(e.pps, 'pps') : null)],
          ['Byte rate', e.byte_rate_bps != null ? fmtRate(e.byte_rate_bps, 'bps') : (e.bps != null ? fmtRate(e.bps, 'B/s') : null)],
          ['Sources', e.distinct_sources != null ? fmtInt(e.distinct_sources) + ' distinct in ' + fmtNum(e.window_span_s || e.window_s, 1) + ' s' : null],
          ['Source entropy', e.src_ip_entropy != null ? fmtNum(Math.abs(e.src_ip_entropy), 2) + ' bits' + (e.src_ip_entropy_norm != null ? ' <span class="dim">(' + fmtNum(e.src_ip_entropy_norm, 2) + ' of maximum)</span>' : '') : null],
          ['SYN-only share', e.syn_only_share != null ? pct(e.syn_only_share) : null],
          ['UDP share', e.udp_share != null && e.udp_share > 0 ? pct(e.udp_share) : null],
          ['Amplifier', e.amplifier_service ? esc(e.amplifier_service) + ' (source port ' + e.top_udp_src_port + ', ' + pct(e.top_udp_src_port_share) + ')' : null],
          ['Target port', e.top_dst_port != null && e.top_dst_port_share >= 0.5 ? e.top_dst_port + ' (' + pct(e.top_dst_port_share) + ')' : null],
          ['Model hint', e.multiclass_model_label ? esc(e.multiclass_model_label.label) + ' <span class="dim">p ' + fmtNum(e.multiclass_model_label.probability, 2) + ' · 18-class model, a hint only</span>' : null],
          ['Repeats held', e.flows_flagged_since_last_alert || e.alerts_suppressed_since_last ? fmtInt(e.flows_flagged_since_last_alert || e.alerts_suppressed_since_last) + ' since the last alert' : null],
        ]);
        if (Array.isArray(e.top_sources) && e.top_sources.length) h += '<div class="ev-note">Top sources: ' + e.top_sources.map((x) => esc(mIp(x[0])) + ' (' + x[1] + ')').join(', ') + '</div>';
        break;
      case 'DGA': case 'DNS Tunnel':
        if (e.rule) {
          h += kvHtml([
            ['Rule', esc(String(e.rule).replace(/_/g, ' '))],
            ['Base domain', e.base_domain ? esc(mDomain(e.base_domain)) : null, true],
            ['Window', e.window_s ? Math.round(e.window_s / 60) + ' min' : null],
            ['NXDOMAIN', e.nxdomain_rate != null ? fmtInt(e.nxdomain_replies) + ' of ' + fmtInt(e.replies) + ' replies (' + pct(e.nxdomain_rate) + ')' : (e.nxdomain_replies ? fmtInt(e.nxdomain_replies) + ' replies' : null)],
            ['Domains failing', e.nxdomain_base_domains != null ? fmtInt(e.nxdomain_base_domains) : null],
            ['Queries', e.queries != null ? fmtInt(e.queries) : null],
            ['Distinct names', e.unique_names != null ? fmtInt(e.unique_names) : null],
            ['Mean label', e.mean_label_len != null ? fmtNum(e.mean_label_len, 1) + ' chars' : null],
            ['Rare types', e.rare_type_share != null ? pct(e.rare_type_share) : null],
          ]);
          if (e.qtype_mix) h += '<div class="ev-note">Record types</div>' + countBars(e.qtype_mix, new Set(['TXT', 'NULL', 'CNAME', 'MX', 'SRV', 'ANY', 'PRIVATE']));
          if (e.byte_ratio) h += '<div class="ev-note">Bytes in queries vs replies (measured)</div>' + byteBars(+e.byte_ratio.outbound || 0, +e.byte_ratio.inbound || 0);
          const names = e.sample_nxdomain_names || e.sample_names;
          if (names && names.length) h += '<div class="ev-note">Examples: ' + names.map((n) => '<span class="mono">' + esc(mDomain(n)) + '</span>').join(', ') + '</div>';
          break;
        }
        h += kvHtml([
          ['Query', esc(mDomain(a.domain)), true],
          ['Record type', e.query_type != null ? esc(QTYPE[e.query_type] || e.query_type) : null],
          ['Name entropy', e.entropy != null ? fmtNum(e.entropy, 2) + ' bits/char' : null],
          ['Queries flagged', e.query_count != null ? fmtInt(e.query_count) + ' from this host under this domain' : null],
          ['Repeats held', e.alerts_suppressed_since_last ? fmtInt(e.alerts_suppressed_since_last) + ' since the last alert' : null],
          ['Host NXDOMAIN', e.host_dns && e.host_dns.nxdomain_rate != null ? pct(e.host_dns.nxdomain_rate) + ' of ' + fmtInt(e.host_dns.replies) + ' replies' : null],
        ]);
        if (e.all_probs) h += '<div style="margin-top:8px">' + probBars(e.all_probs, a.cls === 'DGA' ? 'dga' : 'dns_tunnel') + '</div>';
        break;
      case 'C2 Beacon': {
        const gap = beaconGap(e);
        h += kvHtml([
          ['Combined score', e.score != null ? fmtNum(e.score, 3) + ' <span class="dim">(alerts at ' + fmtNum(e.threshold, 2) + ')</span>' : null],
          ['Check-ins', e.checkins != null ? fmtInt(e.checkins) + ' over ' + fmtNum((e.span_s || 0) / 60, 0) + ' min' : null],
          ['Median gap', gap ? fmtNum(gap, 1) + ' s' : null],
          ['FFT prominence', e.fft_prominence != null ? fmtNum(e.fft_prominence, 2) : null],
          ['FFT period', e.score == null && e.periodicity_seconds != null ? fmtNum(e.periodicity_seconds, 1) + ' s' : null],
          ['Timing CV', e.coefficient_of_variation != null ? fmtNum(e.coefficient_of_variation, 3) : null],
          ['Sources to dst', e.sources_to_destination != null ? fmtInt(e.sources_to_destination) : null],
          ['Port', e.dst_port != null ? e.dst_port : null],
          ['BiLSTM+FFT', e.bilstm ? 'p ' + fmtNum(e.bilstm.probability, 3) + (e.bilstm.is_beacon ? ' · beacon' : ' · not beacon') + ' <span class="dim">(evidence, not the decision)</span>' : null],
        ]);
        if (e.components) h += '<div class="ev-note">Score terms and weights</div>' + compBars(e.components, e.weights);
        if (Array.isArray(e.iat) && e.iat.length > 1) h += '<div class="ev-note">Gaps between check-ins, in seconds (' + e.iat.length + ' shown). The dashed line is the mean.</div>' + iatSvg(e.iat);
        break;
      }
      case 'Encrypted Malware':
        h += kvHtml([
          ['JA4', e.ja4 ? '<span class="fp">' + esc(e.ja4) + '</span> <button class="copy" type="button" data-copy="' + esc(e.ja4) + '">Copy</button>' : null],
          ['JA3', e.ja3 ? '<span class="fp">' + esc(e.ja3) + '</span>' : null],
          ['JA3S', e.ja3s ? '<span class="fp">' + esc(e.ja3s) + '</span>' : null],
          ['SNI', e.sni ? esc(mDomain(e.sni)) : '<span class="dim">none sent</span>'],
          ['ALPN', e.alpn && e.alpn.length ? esc(e.alpn.join(', ')) : '<span class="dim">none</span>'],
          ['Versions', esc((e.offered_version || '—') + ' offered' + (e.negotiated_version ? ', ' + e.negotiated_version + ' used' : ''))],
          ['Cipher suites', e.cipher_count != null ? fmtInt(e.cipher_count) + ' offered' : null],
          ['Sessions', e.sessions != null ? fmtInt(e.sessions) + (e.median_interval_s ? ', every ~' + fmtNum(e.median_interval_s, 0) + ' s' : '') : null],
          ['Fingerprint use', e.clients_with_fingerprint != null ? fmtInt(e.clients_with_fingerprint) + ' of ' + fmtInt(e.sensor_tls_clients) + ' TLS clients here' : null],
          ['Hello flags', e.hello_flags && e.hello_flags.length ? esc(e.hello_flags.join(', ')) : null],
          ['Size sequence', e.splt_signature ? '<span class="mono">' + esc(e.splt_signature.join(' ')) + '</span> <span class="dim">(+ out, − in)</span>' : null],
          ['Blocklist', e.blocklist ? esc(e.blocklist.kind + ': ' + e.blocklist.label) : 'no match'],
        ]);
        if (e.components) h += '<div class="ev-note">Score terms and weights</div>' + compBars(e.components, e.weights);
        h += '<div class="ev-note">From the cleartext ClientHello/ServerHello and packet sizes and times only. Nothing was decrypted.</div>';
        break;
      case 'Data Exfiltration': {
        const br = e.byte_ratio;
        h += kvHtml([
          ['Pattern', e.anomaly_type ? esc(String(e.anomaly_type).replace(/_/g, ' ')) : null],
          ['Out / in', e.out_in_ratio != null ? fmtNum(e.out_in_ratio, 1) + ' : 1' : null],
          ['Connections', e.connections != null ? fmtInt(e.connections) + (e.dst_port ? ' to port ' + e.dst_port : '') : null],
          ['Rule', e.min_out_bytes != null ? '≥ ' + fmtBytes(e.min_out_bytes) + ' out and ≥ ' + e.min_ratio + '× in, ' + Math.round((e.window_s || 900) / 60) + ' min' : null],
          ['Reconstruction error', e.reconstruction_error != null ? fmtNum(e.reconstruction_error, 3) : null],
          ['Name entropy', e.dns_entropy != null ? fmtNum(e.dns_entropy, 2) + ' bits/char' : null],
          ['Subdomain length', e.subdomain_length != null ? e.subdomain_length + ' chars' : null],
          ['Queries flagged', e.query_count != null ? fmtInt(e.query_count) + ' from this host under this domain' : null],
          ['Repeats held', e.alerts_suppressed_since_last ? fmtInt(e.alerts_suppressed_since_last) + ' since the last alert' : null],
        ]);
        if (br && (br.outbound != null || br.inbound != null)) h += '<div style="margin-top:8px">' + byteBars(+br.outbound || 0, +br.inbound || 0) + '</div>' + (e.byte_ratio_source ? '<div class="ev-note">Bytes measured from DNS query and reply sizes.</div>' : '');
        break;
      }
      case 'Port Scan': {
        const x = e.evidence || {};
        h += kvHtml([
          ['Scan type', e.scan_type ? esc(e.scan_type) : null],
          ['Distinct ports', x.distinct_ports != null ? fmtInt(x.distinct_ports) : null],
          ['Target hosts', x.distinct_dst_ips != null ? fmtInt(x.distinct_dst_ips) : null],
          ['Host sweep', x.sweep_hosts ? fmtInt(x.sweep_hosts) + ' hosts on port ' + x.sweep_port : null],
          ['No reply (RWA)', x.rwa != null ? fmtInt(x.rwa) : null],
          ['Resets', x.rst != null ? fmtInt(x.rst) : null],
          ['ICMP errors', x.icmp_error != null ? fmtInt(x.icmp_error) : null],
          ['Unknown hosts', x.neip != null ? fmtInt(x.neip) : null],
          ['Flow model score', e.ml_flow_score != null ? fmtNum(e.ml_flow_score, 3) : null],
        ]);
        if (e.reason) h += '<div class="ev-note">Decision: ' + esc(mText(e.reason)) + '</div>';
        break;
      }
      default: {
        const pairs = [];
        for (const k of Object.keys(e)) {
          const v = e[k];
          if (v == null || typeof v === 'object') continue;
          pairs.push([k.replace(/_/g, ' '), esc(mText(typeof v === 'number' ? (Number.isInteger(v) ? fmtInt(v) : fmtNum(v, 3)) : v)), typeof v !== 'number']);
        }
        h += pairs.length ? kvHtml(pairs) : '<div class="dim">No evidence fields.</div>';
      }
    }
    return h;
  }
  const QTYPE = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 10: 'NULL', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 64: 'SVCB', 65: 'HTTPS', 255: 'ANY' };
  function schemaHtml(a) {
    const r = a.raw || {};
    const f = r.flow_id || {};
    const w = r.event_window;
    const lat = r.latency_ms || {};
    const tuple = f.scope === 'flow'
      ? esc(mIp(f.src_ip)) + ':' + f.src_port + ' → ' + esc(mIp(f.dst_ip)) + ':' + f.dst_port + ' ' + esc(f.protocol || '')
      : esc(mIp(f.src_ip) || '—') + ' → ' + esc(mIp(f.dst_ip) || (f.domain ? mDomain(f.domain) : '—')) + (f.dst_port ? ':' + f.dst_port : '') + (f.protocol ? ' ' + esc(f.protocol) : '');
    const fam = PS.find((p) => p.id === a.ps);
    return '<div class="d-sec schema-sec"><h4>Alert record · ' + esc(r.schema || 'legacy') + '</h4>' + kvHtml([
      ['Detected', fmtTime(a.ts, true), true],
      ['Event time', a.evTs ? fmtTime(a.evTs, true) : '—', true],
      ['Evidence window', w ? fmtNum(w.duration_s, w.duration_s < 10 ? 3 : 0) + ' s' + (w.duration_s > 0 ? ' <span class="dim">from ' + esc(fmtTime(Date.parse(w.start), true)) + '</span>' : '') : null, !!w],
      ['Flow ID', '<span class="dim">' + esc(SCOPE_LABEL[f.scope] || f.scope || '—') + '</span> ' + tuple, true],
      ['Community ID', f.community_id ? esc(f.community_id) + ' <button class="copy" type="button" data-copy="' + esc(f.community_id) + '">Copy</button>' : null, true],
      ['PS 26145', fam ? '(' + fam.id + ') ' + esc(fam.title) : null],
      ['Confidence', a.score == null ? null : a.score.toFixed(4) + ' <span class="dim">' + esc(String(a.confKind || '').replace(/_/g, ' ')) + '</span>'],
      ['Latency', (lat.ingest_to_alert != null ? fmtMs(lat.ingest_to_alert) + ' ingest → alert · ' : '') + fmtMs(lat.pipeline) + ' in the analyzer'],
    ]) + '</div>';
  }
  function renderDetail(reset) {
    const pane = $('#detail');
    const a = findSelected();
    if (!a) { if (reset || !state.selected) { pane.hidden = true; state.detailFor = null; } return; }
    const key = rowKey(a);
    if (!reset && state.detailFor === key) {
      // Same alert or group: only refresh the repeat counter, never rebuild (keeps scroll and verify output).
      const c = $('#dCount');
      if (c && a.count > 1) c.textContent = 'Seen ' + fmtInt(a.count) + ' times · first ' + fmtTime(a.first) + ' · last ' + fmtTime(a.ts) + '. Showing the most recent one.';
      return;
    }
    state.detailFor = key;
    pane.hidden = false;
    const sub = showSub(a);
    const mitre = a.mitre ? esc(a.mitre.technique || '') + (a.mitre.name ? ' · ' + esc(a.mitre.name) : '') + (a.mitre.tactic ? '<div class="dim">' + esc(a.mitre.tactic) + '</div>' : '') : null;
    let h = '<div class="d-head"><div class="d-top"><span class="sev-pill ' + a.sev + '">' + SEV_LABEL[a.sev] + '</span><span class="d-title">' + esc(a.cls) + (sub ? ' <span class="dim">· ' + esc(sub) + '</span>' : '') + '</span>' +
      '<button class="btn btn-quiet btn-small d-close" type="button" data-act="close" title="Close (Esc)">Close</button></div>' +
      '<div class="d-summary">' + esc(summary(a)) + '</div>';
    if (a.count > 1) h += '<div class="d-sub" id="dCount">Seen ' + fmtInt(a.count) + ' times · first ' + fmtTime(a.first) + ' · last ' + fmtTime(a.ts) + '. Showing the most recent one.</div>';
    h += '</div>';

    h += '<div class="d-sec">' + kvHtml([
      ['Alert ID', esc(a.id) + ' <button class="copy" type="button" data-copy="' + esc(a.id) + '">Copy</button>', true],
      ['Detector', esc(modelLabel(a)) + (a.model && MODEL_SHORT[a.model] ? ' <span class="dim mono">' + esc(a.model) + '</span>' : '')],
      ['ATT&CK', mitre],
    ]) + '</div>';
    h += schemaHtml(a);

    const sp = a.sport ? ':' + a.sport : '', dp = a.dport ? ':' + a.dport : '';
    h += '<div class="d-sec"><h4>Flow</h4><div class="flow-line"><span>' + esc(mIp(a.src)) + sp + '</span><span class="arrow">→</span><span>' + esc(mIp(a.dst) || '—') + dp + '</span>' + (a.proto ? '<span class="proto">' + esc(a.proto) + '</span>' : '') + '</div>' +
      (a.domain ? '<div class="flow-line" style="margin-top:4px"><span class="dim">query</span><span>' + esc(mDomain(a.domain)) + '</span></div>' : '') + '</div>';

    h += '<div class="d-sec"><h4>Evidence</h4>' + evidenceHtml(a) + '</div>';

    h += '<div class="d-sec"><h4>Integrity</h4>';
    if (a.receipt) {
      h += kvHtml([['Receipt', esc(short(a.receipt, 12, 8)) + ' <button class="copy" type="button" data-copy="' + esc(a.receipt) + '">Copy</button>', true]]);
    } else {
      h += '<div class="dim">No receipt was issued for this alert.</div>';
    }
    const live = !state.offline && state.conn === 'open';
    h += '<div class="btn-row">' +
      '<button class="btn btn-small" type="button" data-act="verify"' + (live ? '' : ' disabled') + '>Verify claims</button>' +
      '<button class="btn btn-small" type="button" data-act="replay"' + (live && a.receipt ? '' : ' disabled') + '>Replay inference</button>' +
      '<button class="btn btn-small" type="button" data-act="receipt"' + (live && a.receipt ? '' : ' disabled') + '>Show receipt</button>' +
      '</div>' + (live ? '' : '<div class="ev-note">' + (state.offline ? 'Verification needs the live sensor; this is a saved session.' : 'Verification needs the sensor to be connected.') + '</div>') +
      '<div id="dOut"></div></div>';

    let rawText = JSON.stringify(a.raw, null, 2);
    rawText = mText(rawText, a.domain);
    h += '<div class="d-sec"><details class="d-raw"><summary>Raw alert JSON</summary><pre class="raw">' + esc(rawText) + '</pre><div class="btn-row"><button class="btn btn-small" type="button" data-act="copy-json">Copy JSON</button></div></details></div>';
    pane.innerHTML = h;
    pane.scrollTop = 0;
    pane.dataset.alert = a.id;
  }

  $('#detail').addEventListener('click', async (ev) => {
    const cp = ev.target.closest('[data-copy]');
    if (cp) { copyText(cp.getAttribute('data-copy')); return; }
    const b = ev.target.closest('[data-act]');
    if (!b) return;
    const act = b.getAttribute('data-act');
    const a = findSelected();
    if (act === 'close') { state.selected = null; $('#detail').hidden = true; state.dirty.grid = true; state.dirty.histo = true; return; }
    if (!a) return;
    const out = $('#dOut');
    if (act === 'copy-json') { copyText(JSON.stringify(a.raw, null, 2)); return; }
    b.disabled = true;
    try {
      if (act === 'verify') {
        out.innerHTML = '<div class="ev-note">Checking…</div>';
        const r = await api('/api/integrity/verify/' + encodeURIComponent(a.id));
        out.innerHTML = claimsHtml(r);
      } else if (act === 'replay') {
        out.innerHTML = '<div class="ev-note">Re-running the model on the stored features…</div>';
        const r = await api('/api/integrity/replay/' + encodeURIComponent(a.id), { method: 'POST' });
        out.innerHTML = replayHtml(r);
      } else if (act === 'receipt') {
        out.innerHTML = '<div class="ev-note">Loading receipt…</div>';
        const r = await api('/api/integrity/receipt/' + encodeURIComponent(a.id));
        out.innerHTML = receiptHtml(r);
      }
    } catch (err) {
      out.innerHTML = '<div class="ev-note fail-text">' + esc(err.message) + '</div>';
    } finally {
      b.disabled = false;
    }
  });

  function badge(status) {
    const s = String(status || '').toUpperCase();
    if (s === 'PASS') return '<span class="badge pass">Pass</span>';
    if (s === 'FAIL') return '<span class="badge fail">Fail</span>';
    return '<span class="badge na">Unverifiable</span>';
  }
  function claimsHtml(r) {
    const cs = r.claims || [];
    const n = (s) => cs.filter((c) => String(c.status).toUpperCase() === s).length;
    const pass = n('PASS'), fail = n('FAIL'), na = cs.length - pass - fail;
    let h = '<div class="claims">' + cs.map((c) =>
      '<div class="claim"><span class="no">' + esc(c.claim_number) + '</span><span>' + esc(c.name) + '</span>' + badge(c.status) + (c.detail ? '<span class="dt">' + esc(c.detail) + '</span>' : '') + '</div>').join('') + '</div>';
    h += '<div class="claims-sum">' + pass + ' passed · ' + fail + ' failed · ' + na + ' unverifiable' +
      (r.anchor_strength ? ' · anchor strength: ' + esc(r.anchor_strength) : '') + (r.generated_at ? ' · checked ' + esc(r.generated_at) : '') + '</div>';
    return h;
  }
  function replayHtml(r) {
    const ok = String(r.status).toUpperCase() === 'PASS';
    return '<div style="margin-top:10px">' + kvHtml([
      ['Result', badge(r.status) + (r.detail ? ' <span class="dim">' + esc(r.detail) + '</span>' : '')],
      ['Class', esc(r.replayed_class) + (r.class_match ? ' <span class="ok-text">matches</span>' : ' <span class="fail-text">differs from ' + esc(r.committed_class) + '</span>')],
      ['Score (ppm)', fmtInt(r.replayed_score_ppm) + (r.score_match ? ' <span class="ok-text">matches</span>' : ' <span class="fail-text">committed ' + fmtInt(r.committed_score_ppm) + '</span>'), true],
      ['Model digest', r.model_digest_match ? '<span class="ok-text">matches the receipt</span>' : '<span class="fail-text">does not match</span>'],
    ]) + '</div>' + (ok ? '' : '');
  }
  function decodePayload(b64) {
    try {
      const bin = atob(b64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return JSON.parse(new TextDecoder().decode(bytes));
    } catch (e) { return null; }
  }
  function receiptHtml(r) {
    const env = r.envelope || {};
    const st = env.payload ? decodePayload(env.payload) : null;
    const p = (st && st.predicate) || {};
    const d = p.decision || {}, m = p.model || {}, s = p.sensor || {}, fp = p.feature_pipeline || {}, ev = p.evidence || {};
    if (s.id && s.id !== state.sensorId) { state.sensorId = s.id; state.dirty.chrome = true; }
    const sig = (env.signatures || [])[0] || {};
    const mp = r.merkle_proof || {};
    let h = '<div class="rcpt">' + kvHtml([
      ['Statement', st ? esc(st.predicateType || st._type || '') : '<span class="fail-text">payload could not be decoded</span>', true],
      ['Sensor', s.id ? esc(s.id) + (s.event_sequence != null ? ' · event ' + fmtInt(s.event_sequence) : '') : null, true],
      ['Capture window', s.capture_window ? esc(s.capture_window.start) + ' → ' + esc(s.capture_window.end) : null, true],
      ['Decision', d.class ? esc(d.class) + ' · score ' + fmtInt(d.score_ppm) + ' ppm (threshold ' + fmtInt(d.threshold_ppm) + ')' : null],
      ['Model', m.version ? esc(m.version) : null, true],
      ['Model digest', m.model_digest ? esc(short(m.model_digest, 16, 8)) : null, true],
      ['Evidence digest', ev.digest ? esc(short(ev.digest, 16, 8)) : null, true],
      ['Feature vector', fp.feature_vector_digest ? esc(short(fp.feature_vector_digest, 16, 8)) : null, true],
      ['Policy digest', d.policy_digest ? esc(short(d.policy_digest, 16, 8)) : null, true],
      ['Signed by', sig.keyid ? 'Ed25519 ' + esc(short(sig.keyid, 12, 6)) : null, true],
      ['Signature', sig.sig ? esc(short(sig.sig, 18, 6)) : null, true],
      ['Merkle proof', mp.tree_size != null ? 'leaf ' + fmtInt(mp.leaf_index) + ' of ' + fmtInt(mp.tree_size) + ' · ' + (mp.siblings ? mp.siblings.length : 0) + ' hashes' : null],
      ['Ledger block', r.block_index != null ? '#' + fmtInt(r.block_index) : null],
    ]) + '</div>';
    if (st) h += '<details class="d-raw" style="margin-top:8px"><summary>Decoded statement</summary><pre class="raw">' + esc(mText(JSON.stringify(st, null, 2))) + '</pre></details>';
    return h;
  }

  // ---------------------------------------------------------------- hosts
  function buildHosts() {
    const m = new Map();
    const touch = (ip, role, a) => {
      if (!ip) return;
      let h = m.get(ip);
      if (!h) { h = { ip: ip, scope: isInternal(ip) ? 'Internal' : 'External', asSrc: 0, asDst: 0, classes: new Map(), maxSev: 'info', first: a.ts, last: a.ts }; m.set(ip, h); }
      if (role === 'src') h.asSrc++; else h.asDst++;
      h.classes.set(a.cls, (h.classes.get(a.cls) || 0) + 1);
      if (SEV_RANK[a.sev] > SEV_RANK[h.maxSev]) h.maxSev = a.sev;
      if (a.ts < h.first) h.first = a.ts;
      if (a.ts > h.last) h.last = a.ts;
    };
    for (const a of state.alerts) { touch(a.src, 'src', a); if (a.dst && a.dst !== a.src) touch(a.dst, 'dst', a); }
    return Array.from(m.values());
  }
  function renderHosts() {
    if (state.view !== 'hosts') {
      const ips = new Set();
      for (const a of state.alerts) { if (a.src) ips.add(a.src); if (a.dst) ips.add(a.dst); }
      $('#countHosts').textContent = fmtInt(ips.size);
      return;
    }
    const hosts = buildHosts();
    $('#countHosts').textContent = fmtInt(hosts.length);
    const f = ($('#hostFilter').value || '').trim().toLowerCase();
    const internal = $('#hostInternalOnly').checked;
    let list = hosts.filter((h) => (!f || h.ip.toLowerCase().indexOf(f) >= 0 || Array.from(h.classes.keys()).join(' ').toLowerCase().indexOf(f) >= 0) && (!internal || h.scope === 'Internal'));
    const k = state.hostSort.key, dir = state.hostSort.dir;
    const val = (h) => k === 'maxSev' ? SEV_RANK[h.maxSev] : h[k];
    list.sort((x, y) => { const a = val(x), b = val(y); return a < b ? -dir : a > b ? dir : 0; });
    $('#hostTable tbody').innerHTML = list.slice(0, 1000).map((h) =>
      '<tr><td class="mono"><span class="host-link" data-ip="' + esc(h.ip) + '">' + esc(mIp(h.ip)) + '</span></td><td>' + h.scope + '</td>' +
      '<td class="num">' + fmtInt(h.asSrc) + '</td><td class="num">' + fmtInt(h.asDst) + '</td>' +
      '<td class="cls-list">' + Array.from(h.classes.entries()).sort((x, y) => y[1] - x[1]).map((c) => esc(c[0]) + ' <span class="dim">' + fmtInt(c[1]) + '</span>').join(', ') + '</td>' +
      '<td><span class="sev-cell"><span class="sq ' + h.maxSev + '"></span>' + SEV_LABEL[h.maxSev] + '</span></td>' +
      '<td class="mono">' + fmtTime(h.first) + '</td><td class="mono">' + fmtTime(h.last) + '</td></tr>').join('');
    $('#hostEmpty').hidden = list.length > 0;
    $$('#hostTable th[data-sort]').forEach((th) => {
      const on = th.getAttribute('data-sort') === k;
      th.innerHTML = th.textContent.replace(/[▲▼]/g, '') + (on ? ' <span style="color:var(--accent);font-size:10px">' + (dir < 0 ? '▼' : '▲') + '</span>' : '');
    });
  }
  $('#hostTable thead').addEventListener('click', (ev) => {
    const th = ev.target.closest('th[data-sort]');
    if (!th) return;
    const k = th.getAttribute('data-sort');
    if (state.hostSort.key === k) state.hostSort.dir = -state.hostSort.dir; else state.hostSort = { key: k, dir: k === 'ip' || k === 'scope' ? 1 : -1 };
    state.dirty.hosts = true;
  });
  $('#hostTable tbody').addEventListener('click', (ev) => {
    const l = ev.target.closest('[data-ip]');
    if (!l) return;
    state.filterText = 'ip:' + l.getAttribute('data-ip');
    $('#filterInput').value = state.filterText;
    showView('alerts');
    markAll();
  });
  $('#hostFilter').addEventListener('input', () => { state.dirty.hosts = true; });
  $('#hostInternalOnly').addEventListener('change', () => { state.dirty.hosts = true; });

  // ---------------------------------------------------------------- models
  function latFor(names) {
    const lat = ((state.metrics && state.metrics.latency_ms) || {}).detector || {};
    let best = null;
    for (const n of names) { const v = lat[n]; if (v && v.n && (!best || v.n > best.n)) best = v; }
    return best;
  }
  function renderModels() {
    if (state.view !== 'models') return;
    const hm = (state.health && state.health.models) || {};
    const loaded = hm.models_loaded || {}, digests = hm.model_digests || {};
    const rules = {};
    for (const r of ((state.detectors && state.detectors.rules) || [])) rules[r.key] = r;
    const ruleDig = hm.rule_detectors || {};
    const byDet = new Map();
    for (const a of state.alerts) byDet.set(a.model, (byDet.get(a.model) || 0) + 1);
    $('#modelTable tbody').innerHTML = DETECTORS.map((d) => {
      let st, dig;
      if (d.kind === 'model') {
        const k = MODEL_LOADED_KEY[d.key];
        const isLoaded = loaded[k];
        st = isLoaded == null ? '<span class="dim">Unknown</span>' : isLoaded ? '<span class="ok-text">Loaded</span>' : '<span class="fail-text">Not loaded</span>';
        dig = digests[d.key];
      } else {
        const r = rules[d.key] || ruleDig[d.key];
        st = r ? '<span class="ok-text">Running</span>' : (state.health ? '<span class="dim">Unknown</span>' : '<span class="dim">—</span>');
        dig = r && r.digest;
      }
      const n = d.det.reduce((s2, k) => s2 + (byDet.get(k) || 0), 0);
      const l = latFor(d.lat);
      return '<tr><td>' + esc(d.name) + '<div class="dim" style="font-size:11.5px">' + esc(d.model) + '</div></td>' +
        '<td><span class="kind ' + d.kind + '">' + (d.kind === 'model' ? 'Model' : 'Rule') + '</span></td>' +
        '<td class="mono">' + (d.ps ? '(' + d.ps + ')' : '—') + '</td><td>' + st + '</td>' +
        '<td class="mono" title="' + esc(dig || '') + '">' + esc(dig ? short(dig, 12, 6) : '—') + (dig ? ' <button class="copy" type="button" data-copy="' + esc(dig) + '">Copy</button>' : '') + '</td>' +
        '<td class="num">' + fmtInt(n) + '</td><td class="num mono">' + (l ? fmtNum(l.p50, 3) : '—') + '</td><td class="num mono">' + (l ? fmtNum(l.p95, 3) : '—') + '</td></tr>';
    }).join('');
    const rp = (state.detectors && state.detectors.rules) || [];
    $('#ruleParams').innerHTML = rp.length ? rp.map((r) => '<div class="rp"><b>' + esc(r.name) + '</b> <span class="dim mono">v' + esc(r.version) + '</span>' +
      (r.runs != null ? '<div class="dim" style="font-size:11.5px">evaluated ' + fmtInt(r.runs) + ' · alerts ' + fmtInt(r.alerts) + (r.suppressed ? ' · repeats held ' + fmtInt(r.suppressed) : '') + (r.skipped_group_destinations ? ' · multicast/broadcast flows left out ' + fmtInt(r.skipped_group_destinations) : '') + (r.skipped_external_service_flows ? ' · web/DNS/NTP flows to the internet left out ' + fmtInt(r.skipped_external_service_flows) : '') + '</div>' : '') +
      '<pre class="mono">' + esc(JSON.stringify(r.params, null, 1)) + '</pre></div>').join('') : '<div class="dim">' + (state.offline ? 'Not available in a saved session.' : 'Loading…') + '</div>';
    const st = state.stats || (state.health && state.health.pipeline) || {};
    $('#pipelineFacts').innerHTML = fact('Events analysed', fmtInt(st.flows_processed)) + fact('Alerts raised (sensor)', fmtInt(st.total_alerts)) +
      fact('Alerts in this console', fmtInt(state.alerts.length)) + fact('Schema violations', fmtInt(st.schema_violations || 0));
    const dist = st.threat_distribution || {};
    const drows = Object.entries(dist).sort((x, y) => y[1] - x[1]);
    $('#distTable tbody').innerHTML = drows.length ? drows.map((r) => '<tr><td>' + esc(r[0]) + '</td><td class="num">' + fmtInt(r[1]) + '</td></tr>').join('') : '<tr><td colspan="2" class="dim">No alerts yet.</td></tr>';
    const ett = st.ett_classifications || {};
    const erows = Object.entries(ett).sort((x, y) => y[1] - x[1]);
    const emax = erows.length ? erows[0][1] : 1;
    const etot = erows.reduce((s2, r) => s2 + r[1], 0);
    const ec = st.ett_counts || {};
    $('#ettBars').innerHTML = erows.length ? erows.map((r) =>
      '<div class="bar-row"><span class="lbl">' + esc(r[0]) + '</span><div class="bar-track"><div class="bar-fill" style="width:' + (r[1] / emax * 100).toFixed(1) + '%"></div></div><span class="v">' + fmtInt(r[1]) + '</span></div>').join('') +
      '<div class="ev-note">' + fmtInt(etot) + ' flows labelled' + (ec.flows ? ' of ' + fmtInt(ec.flows) + ' (the classifier samples above 50 flows/s; it is telemetry)' : '') + '.</div>' : '<div class="dim">No encrypted flows classified yet.</div>';
  }

  // ---------------------------------------------------------------- overview
  function sevCounts(list) {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const a of list) c[a.sev]++;
    return c;
  }
  function renderOverview() {
    if (state.view !== 'overview') return;
    const psLive = state.ps && state.ps.threats ? state.ps.threats : null;
    const byFam = {};
    for (const f of PS) byFam[f.id] = [];
    for (const a of state.alerts) if (byFam[a.ps]) byFam[a.ps].push(a);
    $('#tiles').innerHTML = PS.map((f) => {
      const list = byFam[f.id];
      const live = psLive && psLive.find((t) => t.id === f.id);
      const c = sevCounts(list);
      const tot = list.length;
      const last = list.length ? list[list.length - 1] : null;
      const stateCls = live ? (live.active ? 'on' : 'off') : '';
      const stateTxt = live ? (live.active ? 'Active' : 'Not loaded') : (state.offline ? 'Saved session' : '—');
      const bar = tot ? SEVS.map((s2) => c[s2] ? '<span class="' + s2 + '" style="flex:' + c[s2] + '" title="' + SEV_LABEL[s2] + ' ' + c[s2] + '"></span>' : '').join('') : '';
      return '<button type="button" class="tile" data-ps="' + f.id + '">' +
        '<div class="tile-top"><span class="tile-letter">' + f.id + '</span><span class="tile-title">' + esc(f.title) + '</span><span class="tile-state ' + stateCls + '"><span class="dot"></span>' + stateTxt + '</span></div>' +
        '<div class="tile-ps">' + esc(f.ps) + '</div>' +
        '<div class="tile-mid"><span class="tile-n' + (tot ? '' : ' zero') + '">' + fmtInt(tot) + '</span><span class="tile-sub">alert' + (tot === 1 ? '' : 's') + ' in this console' + (live && live.alerts !== tot ? ' · ' + fmtInt(live.alerts) + ' on sensor' : '') + '</span></div>' +
        '<div class="sevbar">' + bar + '</div>' +
        '<div class="tile-last">' + (last ? fmtTime(last.ts) + ' · ' + esc(showSub(last) || last.cls) + ' · ' + esc(mIp(last.src) || mIp(last.dst)) : '<span class="dim">No detections yet</span>') + '</div>' +
        '<div class="tile-det">' + esc(f.det) + '</div></button>';
    }).join('');
    $('#ovSchema').textContent = 'Alert schema ' + ((state.ps && state.ps.schema) || 'netsentinel.alert/v1');
    renderThroughput();
    renderLatency();
    renderConstraints();
    renderWatch();
  }
  $('#tiles').addEventListener('click', (ev) => {
    const t = ev.target.closest('[data-ps]');
    if (!t) return;
    state.filterText = 'ps:' + t.getAttribute('data-ps');
    $('#filterInput').value = state.filterText;
    showView('alerts');
  });

  function sourceLabel() {
    const src = state.metrics && state.metrics.source;
    if (state.offline) return 'Saved session';
    if (!src || src.kind === 'idle') return 'Idle';
    if (src.kind === 'sim') return 'Simulator · ' + src.detail + ' (synthetic)';
    if (src.kind === 'live') return 'Live capture · ' + src.detail;
    if (src.kind === 'replay') return 'Replay · ' + src.detail;
    return src.kind;
  }
  function renderThroughput() {
    const m = state.metrics;
    $('#tpSource').textContent = sourceLabel();
    if (!m) {
      $('#tpKpis').innerHTML = '<div class="kpi" style="grid-column:1/-1"><div class="k">Throughput</div><div class="v dim" style="font-size:13px">' + (state.offline ? 'Not recorded in a saved session.' : 'Waiting for the sensor…') + '</div></div>';
      $('#sparkFlows').innerHTML = ''; $('#sparkMbps').innerHTML = '';
      $('#benchLine').innerHTML = '';
      return;
    }
    const t = m.throughput || {}, p = m.peak_throughput || {};
    const kpi = (k, v, peak) => '<div class="kpi"><div class="k">' + k + '</div><div class="v">' + v + '</div><div class="p">peak ' + peak + '</div></div>';
    $('#tpKpis').innerHTML =
      kpi('Flows / s', fmtNum(t.flows_per_s, 1), fmtNum(p.flows_per_s, 1)) +
      kpi('Packets / s', fmtRate(t.packets_per_s, '').trim() || '0', fmtRate(p.packets_per_s, '').trim() || '0') +
      kpi('Mbps', fmtNum(t.mbps, 2), fmtNum(p.mbps, 2)) +
      kpi('Events / s', fmtNum(t.events_per_s, 1), fmtNum(p.events_per_s, 1));
    const series = m.series || [];
    drawSpark('#sparkFlows', series.map((r) => [r[0], r[3]]), '#sparkFlowsMax', (v) => fmtNum(v, 0) + ' flows/s');
    drawSpark('#sparkMbps', series.map((r) => [r[0], r[2] * 8 / 1e6]), '#sparkMbpsMax', (v) => fmtNum(v, 2) + ' Mbps');
    if (m.source && m.source.kind === 'sim' && !(p.mbps > 0)) $('#sparkMbpsMax').textContent = 'simulator events carry no packets';
    const b = (state.bench && state.bench.result) || null;
    const running = state.bench && (state.bench.status === 'running' || state.bench.status === 'generating');
    $('#benchLine').innerHTML = (b
      ? '<span>Last benchmark:</span><b>' + fmtInt(b.packets_per_s) + ' packets/s</b><b>' + fmtNum(b.mbps, 1) + ' Mbps</b><b>' + fmtInt(b.flows_per_s) + ' flows/s</b><span class="muted">' + esc(b.kind) + ' · ' + esc(b.file) + ' · ' + esc((b.machine && b.machine.cpu) || '') + ' · ' + esc(String(b.measured_at || '').slice(0, 16).replace('T', ' ')) + ' UTC</span>'
      : '<span class="muted">No benchmark run yet on this sensor.</span>') +
      '<span class="spacer"></span><button class="btn btn-small" type="button" id="ovBench"' + (running || state.offline || state.conn !== 'open' ? ' disabled' : '') + '>' + (running ? 'Benchmark running…' : 'Run benchmark') + '</button>';
  }
  function drawSpark(sel, pts, maxSel, fmt) {
    const svg = $(sel);
    const W = Math.max(200, svg.clientWidth || 400), H = 42;
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    if (!pts.length) { svg.innerHTML = ''; $(maxSel).textContent = ''; return; }
    let max = 0;
    for (const p of pts) if (p[1] > max) max = p[1];
    $(maxSel).textContent = 'max ' + fmt(max);
    const top = max > 0 ? max * 1.15 : 1;
    const x = (i) => i / Math.max(1, pts.length - 1) * W;
    const y = (v) => H - 1 - (v / top) * (H - 4);
    let d = '';
    pts.forEach((p, i) => { d += (i ? 'L' : 'M') + x(i).toFixed(1) + ' ' + y(p[1]).toFixed(1); });
    const area = d + 'L' + W + ' ' + (H - 1) + 'L0 ' + (H - 1) + 'Z';
    svg.innerHTML = '<line class="base" x1="0" x2="' + W + '" y1="' + (H - 0.5) + '" y2="' + (H - 0.5) + '"/><path class="area" d="' + area + '"/><path class="line" d="' + d + '"/><line class="cross" id="' + sel.slice(1) + 'X" x1="-10" x2="-10" y1="0" y2="' + H + '"/>';
    svg._pts = pts; svg._fmt = fmt;
  }
  ['#sparkFlows', '#sparkMbps'].forEach((sel) => {
    const svg = $(sel);
    svg.addEventListener('mousemove', (ev) => {
      const pts = svg._pts;
      if (!pts || !pts.length) return;
      const r = svg.getBoundingClientRect();
      const i = Math.max(0, Math.min(pts.length - 1, Math.round((ev.clientX - r.left) / r.width * (pts.length - 1))));
      const W = Math.max(200, svg.clientWidth || 400);
      const xl = i / Math.max(1, pts.length - 1) * W;
      const c = $(sel + 'X'); if (c) { c.setAttribute('x1', xl); c.setAttribute('x2', xl); }
      const tip = $('#sparkTip');
      tip.innerHTML = '<span class="mono">' + fmtClock(pts[i][0] * 1000, true) + '</span> · ' + svg._fmt(pts[i][1]);
      tip.hidden = false;
      const wrap = svg.parentElement.getBoundingClientRect();
      let left = ev.clientX - wrap.left + 10;
      if (left > wrap.width - 170) left -= 180;
      tip.style.left = left + 'px';
      tip.style.top = (r.top - wrap.top - 26) + 'px';
    });
    svg.addEventListener('mouseleave', () => { $('#sparkTip').hidden = true; const c = $(sel + 'X'); if (c) { c.setAttribute('x1', -10); c.setAttribute('x2', -10); } });
  });

  const LAT_ROWS = [
    ['group', 'Per event (analyzer entry to exit)'],
    ['event', 'flow', 'Flow'], ['event', 'dns', 'DNS query'], ['event', 'dns_response', 'DNS reply'], ['event', 'stub', 'Probe (one packet)'], ['event', 'session', 'C2 session (100 flows)'],
    ['i2a', '', 'Ingest → alert'],
    ['group', 'Per detector call'],
    ['detector', 'ddos_xgboost', 'DDoS XGBoost'], ['detector', 'ddos_window', 'DDoS window update'], ['detector', 'ddos_rule', 'DDoS rate/entropy rule'],
    ['detector', 'c2_combined', 'C2 combined score'], ['detector', 'c2_bilstm', 'C2 BiLSTM+FFT'],
    ['detector', 'dga_cnn_bilstm', 'DGA CNN-BiLSTM'], ['detector', 'dns_behaviour', 'DNS behaviour rules'],
    ['detector', 'tls_sessions', 'TLS session profile'], ['detector', 'portscan_window', 'Port-scan window (60 s batch)'],
    ['detector', 'exfil_ratio', 'Exfil byte ratio'], ['detector', 'exfil_vae', 'Exfil VAE'], ['detector', 'ett_transformer', 'Encrypted-app classifier'],
  ];
  function renderLatency() {
    const lat = state.metrics && state.metrics.latency_ms;
    if (!lat) { $('#latTable tbody').innerHTML = '<tr><td colspan="5" class="dim">' + (state.offline ? 'Not recorded in a saved session.' : 'Waiting for the sensor…') + '</td></tr>'; $('#latNote').textContent = ''; return; }
    let h = '';
    for (const r of LAT_ROWS) {
      if (r[0] === 'group') { h += '<tr class="grp"><td colspan="5">' + esc(r[1]) + '</td></tr>'; continue; }
      const v = r[0] === 'i2a' ? lat.ingest_to_alert : ((lat[r[0]] || {})[r[1]]);
      if (!v || !v.n) continue;
      h += '<tr><td>' + esc(r[2]) + '</td><td class="num mono">' + fmtNum(v.p50, 3) + '</td><td class="num mono">' + fmtNum(v.p95, 3) + '</td><td class="num mono">' + fmtNum(v.p99, 3) + '</td><td class="num">' + fmtInt(v.n) + '</td></tr>';
    }
    $('#latTable tbody').innerHTML = h || '<tr><td colspan="5" class="dim">No events analysed yet.</td></tr>';
    $('#latNote').textContent = 'Last 4,096 samples of each. Bounded by design: a flow reaches the detectors when it closes, after 120 s idle or 300 s active, an unanswered probe after 5 s; windowed detectors add their window (DDoS 10 s, port scan 60 s, DNS behaviour 5 min, C2 at least 30 min of check-ins).';
  }
  function badgeFor(status) {
    const s2 = String(status || '');
    if (s2 === 'met') return '<span class="badge met">Met</span>';
    if (s2 === 'measured') return '<span class="badge pass">Measured</span>';
    if (s2 === 'attention') return '<span class="badge fail">Check</span>';
    return '<span class="badge na">' + esc(s2.charAt(0).toUpperCase() + s2.slice(1)) + '</span>';
  }
  function liveBits(id, live, c) {
    if (!live) return '';
    const b = (k, v) => '<span>' + esc(k) + ' <b>' + v + '</b></span>';
    switch (id) {
      case 'a': return b('source now', esc(sourceLabel()));
      case 'b': return b('TLS hellos parsed', fmtInt(live.tls_client_hellos || 0)) + b('TLS sessions profiled', fmtInt(live.tls_sessions_profiled || 0)) + b('QUIC Initial parsing', live.quic_initial_parse ? 'ON' : 'off') + (live.quic_initial_parse ? b('QUIC hellos', fmtInt(live.quic_client_hellos || 0)) : '');
      case 'c': return b('flow p95', fmtMs(live.flow_event_p95_ms)) + b('DNS p95', fmtMs(live.dns_event_p95_ms)) + b('ingest → alert p95', fmtMs(live.ingest_to_alert_p95_ms)) + b('dropped', fmtInt(live.dropped_events || 0));
      case 'd': {
        const n = live.now || {}, bm = c.benchmark;
        return b('now', fmtNum(n.flows_per_s, 1) + ' flows/s · ' + fmtNum(n.mbps, 2) + ' Mbps') + (bm ? b('benchmark', fmtInt(bm.packets_per_s) + ' pkt/s · ' + fmtNum(bm.mbps, 1) + ' Mbps · ' + fmtInt(bm.flows_per_s) + ' flows/s (' + esc(bm.kind) + ')') : b('benchmark', 'not run'));
      }
      case 'e': return b('alerts', fmtInt(live.alerts)) + b('schema violations', fmtInt(live.schema_violations || 0)) + b('required fields', fmtInt((live.required_fields || []).length));
      default: return '';
    }
  }
  function renderConstraints() {
    const cs = state.ps && state.ps.constraints;
    if (!cs) { $('#constraints').innerHTML = '<div class="empty-note">' + (state.offline ? 'Constraint status comes from the live sensor.' : 'Loading…') + '</div>'; $('#deliverables').innerHTML = ''; return; }
    $('#constraints').innerHTML = cs.map((c) => '<div class="cons"><span class="id">(' + c.id + ')</span><span class="t">' + esc(c.title) + '</span><span>' + badgeFor(c.status) + '</span><div><div class="how">' + esc(c.how) + '</div><div class="live">' + liveBits(c.id, c.live, c) + '</div></div></div>').join('');
    $('#deliverables').innerHTML = (state.ps.deliverables || []).map((d) => '<div class="d"><b>' + esc(d.title) + '</b><span>' + esc(d.detail) + '</span></div>').join('');
  }
  function renderWatch() {
    const w = (state.metrics && state.metrics.c2_watchlist) || [];
    $('#c2Watch').innerHTML = w.length ? w.map((r) => {
      const hot = r.score >= 0.8;
      const comp = ['T', 'F', 'S', 'R', 'C'].map((k) => '<span title="' + COMP_LABEL[k] + ' ' + fmtNum(r[k], 2) + '"><i style="width:' + (Math.max(0, Math.min(1, r[k])) * 100).toFixed(0) + '%"></i></span>').join('');
      return '<div class="watch-row"><div><div class="pair">' + esc(mIp(r.src)) + ' → ' + esc(mIp(r.dst)) + '</div><div class="meta">' + fmtInt(r.n) + ' check-ins · every ~' + fmtNum(r.median_gap_s, 0) + ' s</div><div class="comp">' + comp + '</div></div><div class="sc' + (hot ? ' hot' : '') + '">' + fmtNum(r.score, 3) + '</div></div>';
    }).join('') + '<div class="ev-note">Pairs with at least 20 check-ins over 30 minutes. Alerts at 0.80. Bars: T F S R C.</div>' : '<div class="empty-note">No pair has 20 check-ins over 30 minutes yet. The score needs time by definition.</div>';
    const fps = (state.metrics && state.metrics.tls_fingerprints) || [];
    $('#tlsFps').innerHTML = fps.length ? '<div class="mini-list">' + fps.map((f) => '<div class="row"><span class="l fp" title="' + esc(f.ja4) + '">' + esc(f.ja4) + '</span><span class="r">' + fmtInt(f.sessions) + ' sess · ' + fmtInt(f.clients) + ' host' + (f.clients === 1 ? '' : 's') + '</span></div>').join('') + '</div>' : '<div class="empty-note">No TLS handshakes seen yet.</div>';
    const hi = state.alerts.filter((a) => a.sev === 'critical' || a.sev === 'high').slice(-8).reverse();
    $('#recentHigh').innerHTML = hi.length ? '<div class="mini-list">' + hi.map((a) => '<div class="row click" data-open="' + esc(a.id) + '"><span class="l"><span class="sq ' + a.sev + '"></span> ' + esc(a.cls) + (showSub(a) ? ' <span class="dim">· ' + esc(showSub(a)) + '</span>' : '') + '</span><span class="r mono">' + fmtTime(a.ts).slice(0, 8) + '</span></div>').join('') + '</div>' : '<div class="empty-note">None yet.</div>';
  }
  $('#recentHigh').addEventListener('click', (ev) => {
    const r = ev.target.closest('[data-open]');
    if (!r) return;
    state.filterText = ''; $('#filterInput').value = '';
    showView('alerts');
    select(r.getAttribute('data-open'));
  });
  $('#tpPanel').addEventListener('click', (ev) => { if (ev.target.closest('#ovBench')) startBenchmark(null, 50000); });

  function fact(k, v, mono, cls) { return '<div class="fact"><div class="k">' + esc(k) + '</div><div class="v' + (mono ? ' mono' : '') + (cls ? ' ' + cls : '') + '">' + v + '</div></div>'; }
  $('#modelTable').addEventListener('click', (ev) => { const c = ev.target.closest('[data-copy]'); if (c) copyText(c.getAttribute('data-copy')); });

  // ---------------------------------------------------------------- integrity
  async function loadLedger() {
    if (state.offline || state.conn !== 'open') { state.dirty.integrity = true; return; }
    try {
      const [c, k] = await Promise.all([api('/api/integrity/consistency'), api('/api/integrity/checkpoints')]);
      state.ledger = c; state.checkpoints = k.checkpoints || [];
      $('#ledgerMsg').textContent = '';
    } catch (err) {
      state.ledger = { error: err.message };
    }
    state.dirty.integrity = true;
  }
  function renderIntegrity() {
    const withR = state.alerts.filter((a) => a.receipt).length;
    if (state.view !== 'integrity') return;
    const L = state.ledger;
    let f = '';
    if (!L) f = fact('Ledger', state.offline ? 'Not available in a saved session' : (state.conn === 'open' ? 'Loading…' : 'Sensor not connected'));
    else if (L.error) f = fact('Ledger', '<span class="fail-text">' + esc(L.error) + '</span>');
    else {
      const s = L.latest_sth || {};
      f = fact('Hash chain', L.chain_valid ? '<span class="ok-text">Intact</span>' : '<span class="fail-text">Broken at block ' + esc(L.bad_block_index) + '</span>') +
        fact('Blocks', fmtInt(L.ledger_size)) +
        fact('Latest checkpoint', s.checkpoint_sequence != null ? '#' + fmtInt(s.checkpoint_sequence) + ' · tree size ' + fmtInt(s.tree_size) : '—') +
        fact('Receipts waiting', fmtInt(L.anchor_buffer_size)) +
        fact('Root hash', s.root_hash ? esc(short(s.root_hash, 16, 8)) : '—', true) +
        fact('Signed by', s.nid_pubkey ? 'Ed25519 ' + esc(short(s.nid_pubkey, 10, 6)) : '—', true) +
        fact('Published', s.timestamp_rfc3339 ? esc(s.timestamp_rfc3339) : '—', true) +
        fact('Signature', s.signature ? esc(short(s.signature, 12, 6)) : '—', true);
    }
    $('#ledgerFacts').innerHTML = f;
    const cps = (state.checkpoints || []).slice().reverse();
    $('#cpTable tbody').innerHTML = cps.slice(0, 200).map((c) =>
      '<tr><td class="num">' + fmtInt(c.checkpoint_sequence) + '</td><td class="num">' + fmtInt(c.tree_size) + '</td><td class="mono" title="' + esc(c.root_hash) + '">' + esc(short(c.root_hash, 20, 8)) + '</td>' +
      '<td class="mono">' + esc(c.timestamp_rfc3339 || '') + '</td><td class="mono">' + esc(short(c.nid_pubkey, 10, 6)) + '</td></tr>').join('');
    $('#cpEmpty').hidden = cps.length > 0;
    $('#receiptFacts').innerHTML = fact('Alerts in this console with a signed receipt', fmtInt(withR) + ' of ' + fmtInt(state.alerts.length));
    const dis = state.offline || state.conn !== 'open';
    $('#flushBtn').disabled = dis; $('#sthBtn').disabled = dis;
  }
  $('#flushBtn').addEventListener('click', async () => {
    try {
      const r = await api('/api/integrity/flush', { method: 'POST' });
      const b = r.block || {};
      $('#ledgerMsg').textContent = b.index != null ? 'Sealed block #' + b.index + ' with ' + plural(b.alert_count || 0, 'receipt') + '.' : 'Nothing to seal.';
    } catch (err) { $('#ledgerMsg').textContent = err.message; }
    loadLedger();
  });
  $('#sthBtn').addEventListener('click', async () => {
    try {
      const r = await api('/api/integrity/publish-sth', { method: 'POST' });
      const s = r.sth || {};
      const at = (r.attestations || [])[0];
      $('#ledgerMsg').textContent = 'Checkpoint #' + s.checkpoint_sequence + ' published (tree size ' + s.tree_size + ')' + (at ? ', anchored by ' + at.type + ' (' + at.strength + ' strength).' : '.');
    } catch (err) { $('#ledgerMsg').textContent = err.message; }
    loadLedger();
  });
  $('#ledgerRefresh').addEventListener('click', loadLedger);

  // ---------------------------------------------------------------- ingest
  function renderIngest() {
    if (state.view !== 'ingest') return;
    const x = state.extractor;
    if (!x) { $('#extractorFacts').innerHTML = fact('Status', state.offline ? 'Saved session' : 'No data from the sensor yet'); return; }
    const src = x.replay && !x.live_capture_active ? x.replay : x;
    const fe = src.flow_extractor || {}, dn = src.dns_extractor || {}, sb = src.session_builder || {};
    $('#extractorFacts').innerHTML =
      fact('Live capture', x.live_capture_active ? '<span class="ok-text">Running</span>' : 'Stopped') +
      fact('Showing', src === x ? 'live processor' : 'last replay (' + esc(src.reader || '—') + ' reader)') +
      fact('Packets processed', fmtInt(src.packets_processed)) + fact('Bytes processed', fmtBytes(src.bytes_processed)) +
      fact('Events generated', fmtInt(src.events_generated)) +
      fact('Active flows', fmtInt(fe.active_flows)) + fact('Completed flows', fmtInt(fe.completed_flows)) +
      fact('Probe stubs (1 packet)', fmtInt(fe.probe_stubs)) + fact('Teardown packets absorbed', fmtInt(fe.teardown_packets_absorbed)) +
      fact('TLS ClientHellos read', fmtInt(fe.tls_client_hellos)) +
      fact('QUIC Initial parsing', fe.quic_initial_parse ? '<span class="fail-text">ON</span> · ' + fmtInt(fe.quic_client_hellos) + ' hellos' : 'off (default)') +
      fact('DNS queries / replies', fmtInt(dn.total_dns_queries) + ' / ' + fmtInt(dn.total_dns_responses)) + fact('NXDOMAIN replies', fmtInt(dn.total_nxdomains)) +
      fact('Host pairs (C2 sessions)', fmtInt(sb.tracked_pairs)) + fact('Sessions scored', fmtInt(sb.sessions_emitted));
    renderBench();
    const dis = state.offline || state.conn !== 'open';
    $$('#pcapUpload, #pcapProcess, #capStart, #capStop, #resetBtn, #simButtons button').forEach((b) => { b.disabled = dis; });
  }
  function renderBench() {
    const b = state.bench || {};
    const running = b.status === 'running' || b.status === 'generating';
    $('#benchRun').disabled = running || state.offline || state.conn !== 'open';
    $('#benchRun').textContent = running ? (b.status === 'generating' ? 'Generating capture…' : 'Running…') : 'Run benchmark';
    const prog = $('#benchProgress');
    if (running && b.progress) {
      prog.hidden = false;
      const pr = b.progress;
      const frac = pr.of ? pr.generated / pr.of : null;
      $('#benchProgressBar').style.width = frac != null ? (frac * 100).toFixed(1) + '%' : '100%';
      msg('#benchMsg', pr.of ? 'Generating synthetic capture: ' + fmtInt(pr.generated) + ' of ' + fmtInt(pr.of) + ' packets (first run only)…' : 'Replaying: ' + fmtInt(pr.packets) + ' packets in ' + fmtNum(pr.elapsed_s, 1) + ' s…');
    } else prog.hidden = true;
    if (b.status === 'error') msg('#benchMsg', b.error || 'Benchmark failed.', true);
    const r = b.result;
    const box = $('#benchFacts');
    if (!r) { box.hidden = true; return; }
    box.hidden = false;
    const ev = (r.latency_ms && r.latency_ms.event) || {};
    const fl = ev.flow || {};
    box.innerHTML = fact('Packets / s', fmtInt(r.packets_per_s)) + fact('Mbps', fmtNum(r.mbps, 1)) + fact('Flows / s', fmtInt(r.flows_per_s)) + fact('Events / s', fmtInt(r.events_per_s)) +
      fact('Input', esc(r.kind) + ' · ' + esc(r.file)) + fact('Packets · avg size', fmtInt(r.packets) + ' · ' + fmtNum(r.avg_packet_bytes, 0) + ' B') +
      fact('Elapsed', fmtNum(r.elapsed_s, 2) + ' s' + (r.realtime_factor ? ' (' + fmtNum(r.realtime_factor, 1) + '× real time)' : '')) +
      fact('Flow event p50 / p95', fmtMs(fl.p50) + ' / ' + fmtMs(fl.p95)) +
      fact('Read + extract', fmtNum(r.stage_s && r.stage_s.read_and_extract, 2) + ' s') + fact('Detect', fmtNum(r.stage_s && r.stage_s.detect, 2) + ' s') +
      fact('Machine', esc((r.machine && r.machine.cpu) || '—') + ', 1 of ' + fmtInt(r.machine && r.machine.logical_cpus) + ' CPUs') +
      fact('Measured', esc(String(r.measured_at || '').slice(0, 19).replace('T', ' ')) + ' UTC');
  }
  async function startBenchmark(path, n) {
    try {
      const r = await api('/api/benchmark', { method: 'POST', body: path ? { pcap_path: path } : { synthetic_packets: n } });
      state.bench = Object.assign({}, state.bench || {}, { status: 'running', progress: null, error: null });
      msg('#benchMsg', 'Started: ' + (r.input || ''));
      state.dirty.ingest = true; state.dirty.overview = true;
      pollBench();
    } catch (err) { msg('#benchMsg', err.message, true); toast(err.message); }
  }
  let benchTimer = null;
  async function pollBench() {
    clearTimeout(benchTimer);
    if (state.offline || state.conn !== 'open') return;
    try { state.bench = await api('/api/benchmark'); } catch (e) { /* keep last */ }
    state.dirty.ingest = true; state.dirty.overview = true;
    if (state.bench && (state.bench.status === 'running' || state.bench.status === 'generating')) benchTimer = setTimeout(pollBench, 1000);
    else if (state.bench && state.bench.status === 'done') { msg('#benchMsg', 'Done.'); refreshPs(); }
  }
  $('#benchRun').addEventListener('click', () => {
    const p = $('#benchPath').value.trim();
    startBenchmark(p || null, +$('#benchSize').value || 50000);
  });
  function msg(id, text, err) { const el = $(id); el.textContent = text; el.classList.toggle('err', !!err); }
  $('#pcapUpload').addEventListener('click', () => {
    const f = $('#pcapFile').files[0];
    if (!f) { msg('#pcapMsg', 'Choose a .pcap or .pcapng file first.', true); return; }
    const fd = new FormData();
    fd.append('file', f, f.name);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', cfg.backend + '/api/pcap/upload');
    $('#pcapProgress').hidden = false;
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) $('#pcapProgressBar').style.width = (e.loaded / e.total * 100).toFixed(1) + '%'; };
    xhr.onload = () => {
      $('#pcapProgress').hidden = true; $('#pcapProgressBar').style.width = '0';
      let r = {};
      try { r = JSON.parse(xhr.responseText); } catch (e) { /* not JSON */ }
      if (xhr.status >= 400 || r.error) { msg('#pcapMsg', r.error || ('Upload failed: HTTP ' + xhr.status), true); return; }
      state.replay = { name: r.filename || f.name, active: true, started: Date.now() };
      state.dirty.chrome = true;
      msg('#pcapMsg', 'Uploaded ' + (r.filename || f.name) + ' (' + fmtInt(r.size_bytes) + ' bytes). Replaying — alerts will appear in the Alerts tab.');
    };
    xhr.onerror = () => { $('#pcapProgress').hidden = true; msg('#pcapMsg', 'Upload failed: the sensor did not answer.', true); };
    xhr.send(fd);
    msg('#pcapMsg', 'Uploading ' + f.name + '…');
  });
  $('#pcapProcess').addEventListener('click', async () => {
    const p = $('#pcapPath').value.trim();
    if (!p) { msg('#pcapMsg', 'Enter a path on the sensor machine.', true); return; }
    try {
      const r = await api('/api/pcap/process', { method: 'POST', body: { filepath: p } });
      state.replay = { name: r.filename || p, active: true, started: Date.now() };
      state.dirty.chrome = true;
      msg('#pcapMsg', 'Processing ' + (r.filename || p) + ' (' + fmtInt(r.size_bytes) + ' bytes).');
    } catch (err) { msg('#pcapMsg', err.message, true); }
  });
  $('#capStart').addEventListener('click', async () => {
    const iface = $('#ifaceName').value.trim() || 'Ethernet';
    try { const r = await api('/api/capture/start?interface=' + encodeURIComponent(iface), { method: 'POST' }); state.liveIface = iface; msg('#capMsg', r.status || 'Started.'); pollExtractor(); }
    catch (err) { msg('#capMsg', err.message, true); }
  });
  $('#capStop').addEventListener('click', async () => {
    try { const r = await api('/api/capture/stop', { method: 'POST' }); msg('#capMsg', r.status || 'Stopped.'); pollExtractor(); }
    catch (err) { msg('#capMsg', err.message, true); }
  });
  $('#simButtons').addEventListener('click', async (ev) => {
    const b = ev.target.closest('[data-sim]');
    if (!b) return;
    const mode = b.getAttribute('data-sim');
    try {
      const r = await api('/api/simulate/' + mode, { method: 'POST' });
      msg('#simMsg', r.status || 'OK');
      if (mode === 'stop') { state.simMode = null; } else { state.simMode = mode; state.simSeenAt = Date.now(); }
      state.dirty.chrome = true;
    } catch (err) { msg('#simMsg', err.message, true); }
  });
  $('#resetBtn').addEventListener('click', async () => {
    if (!confirmReset()) return;
    try {
      await api('/api/reset', { method: 'POST' });
      state.alerts = []; state.ids.clear(); state.arrived.clear(); state.selected = null; $('#detail').hidden = true;
      msg('#resetMsg', 'Alerts cleared on the sensor and in this console.');
      markAll(); refreshStats();
    } catch (err) { msg('#resetMsg', err.message, true); }
  });
  let resetArmed = 0;
  function confirmReset() {
    if (Date.now() - resetArmed < 4000) { resetArmed = 0; $('#resetBtn').textContent = 'Clear alerts on sensor'; return true; }
    resetArmed = Date.now();
    $('#resetBtn').textContent = 'Click again to confirm';
    setTimeout(() => { if (resetArmed && Date.now() - resetArmed >= 4000) { $('#resetBtn').textContent = 'Clear alerts on sensor'; resetArmed = 0; } }, 4100);
    return false;
  }

  // ---------------------------------------------------------------- sessions (save / open)
  $('#saveBtn').addEventListener('click', () => {
    const data = {
      format: 'netsentinel-session', version: 1, saved_at: new Date().toISOString(),
      sensor_url: state.offline ? null : cfg.backend, sensor_id: state.sensorId,
      source: $('#sourceChip .label').textContent,
      stats: state.stats, health: state.health,
      alerts: state.alerts.map((a) => a.raw),
    };
    const blob = new Blob([JSON.stringify(data)], { type: 'application/json' });
    const d = new Date();
    const name = 'netsentinel-session-' + d.getFullYear() + pad(d.getMonth() + 1) + pad(d.getDate()) + '-' + pad(d.getHours()) + pad(d.getMinutes()) + '.json';
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url; link.download = name;
    document.body.appendChild(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    toast('Saved ' + plural(state.alerts.length, 'alert') + ' to ' + name + '.');
  });
  $('#openBtn').addEventListener('click', () => {
    if (state.offline) { goLive(); return; }
    $('#openFile').click();
  });
  $('#openFile').addEventListener('change', (ev) => {
    const f = ev.target.files[0];
    ev.target.value = '';
    if (!f) return;
    const rd = new FileReader();
    rd.onload = () => {
      let data;
      try { data = JSON.parse(rd.result); } catch (e) { toast('That file is not valid JSON.'); return; }
      const alerts = Array.isArray(data) ? data : data.alerts;
      if (!Array.isArray(alerts)) { toast('No alerts found in that file.'); return; }
      goOffline(f.name, data);
      ingest(alerts, false);
      toast('Opened ' + f.name + ': ' + plural(state.alerts.length, 'alert') + '.');
    };
    rd.readAsText(f);
  });
  function goOffline(name, data) {
    state.offline = true; state.offlineName = name;
    if (ws) { try { ws.onclose = null; ws.close(); } catch (e) { /* ignore */ } ws = null; }
    clearTimeout(wsTimer);
    state.alerts = []; state.ids.clear(); state.arrived.clear(); state.selected = null; $('#detail').hidden = true;
    state.stats = data && data.stats || null; state.health = data && data.health || null; state.extractor = null;
    state.ledger = null; state.checkpoints = null;
    state.metrics = null; state.ps = null; state.detectors = null; state.bench = null;
    if (data && data.sensor_id) state.sensorId = data.sensor_id;
    setConn('offline', 'Saved session');
    $('#openBtn').textContent = 'Go live';
    markAll();
  }
  function goLive() {
    state.offline = false; state.offlineName = '';
    state.alerts = []; state.ids.clear(); state.arrived.clear(); state.selected = null; $('#detail').hidden = true;
    state.stats = null; state.health = null;
    $('#openBtn').textContent = 'Open…';
    backoff = 1000; connect();
    markAll();
  }

  // ---------------------------------------------------------------- network
  async function api(path, opts) {
    opts = opts || {};
    const init = { method: opts.method || 'GET' };
    if (opts.body !== undefined) { init.headers = { 'Content-Type': 'application/json' }; init.body = JSON.stringify(opts.body); }
    let res;
    try { res = await fetch(cfg.backend + path, init); }
    catch (e) { throw new Error('The sensor did not answer (' + cfg.backend + ').'); }
    let data = null;
    try { data = await res.json(); } catch (e) { /* not JSON */ }
    if (!res.ok) throw new Error((data && (data.detail || data.error)) || ('HTTP ' + res.status));
    if (data && data.error) throw new Error(data.error);
    return data;
  }
  let ws = null, wsTimer = null, backoff = 1000;
  function wsUrl() { return cfg.backend.replace(/^http/i, 'ws').replace(/\/+$/, '') + '/ws'; }
  function setConn(s, text) {
    state.conn = s;
    const el = $('#conn');
    el.setAttribute('data-state', s);
    $('#connText').textContent = text;
    state.dirty.chrome = true; state.dirty.grid = true;
  }
  function connect() {
    if (state.offline) return;
    clearTimeout(wsTimer);
    if (ws) { try { ws.onclose = null; ws.close(); } catch (e) { /* ignore */ } ws = null; }
    setConn('connecting', 'Connecting');
    let sock;
    try { sock = new WebSocket(wsUrl()); } catch (e) { scheduleReconnect(); return; }
    ws = sock;
    sock.onopen = () => { backoff = 1000; setConn('open', 'Connected'); bootstrap(); };
    sock.onmessage = (ev) => {
      let m;
      try { m = JSON.parse(ev.data); } catch (e) { return; }
      if (m.type === 'alert' && m.data) { (state.paused ? state.held : state.queue).push(m.data); if (state.paused) renderPause(); }
      else if (m.type === 'stats' && m.data) onStats(m.data);
      else if (m.type === 'metrics' && m.data) { state.metrics = m.data; state.dirty.overview = true; state.dirty.chrome = true; if (state.view === 'models') state.dirty.models = true; }
      else if (m.type === 'benchmark' && m.data) { if (m.data.phase === 'done' || m.data.phase === 'error') pollBench(); else { state.bench = Object.assign({}, state.bench || {}, { status: m.data.phase === 'generating' ? 'generating' : 'running', progress: m.data.packets != null && m.data.phase === 'running' ? { packets: m.data.packets, elapsed_s: m.data.elapsed_s } : (state.bench && state.bench.progress) }); state.dirty.ingest = true; } }
    };
    sock.onclose = () => { if (ws === sock) { ws = null; if (!state.offline) scheduleReconnect(); } };
    sock.onerror = () => { /* onclose follows */ };
  }
  function scheduleReconnect() {
    const s = Math.round(backoff / 1000);
    setConn('closed', 'Not connected · retrying in ' + s + ' s');
    wsTimer = setTimeout(connect, backoff);
    backoff = Math.min(backoff * 2, 10000);
  }
  async function bootstrap() {
    await Promise.all([refreshHealth(), refreshStats(), pollExtractor(), refreshPs(), refreshMetrics(), refreshDetectors(), pollBench(), refreshTier2(false), loadFigures()]);
    try {
      const r = await api('/api/alerts?limit=1000');
      ingest((r.alerts || []).slice().reverse(), false);
      if (!state.lastEventAt && state.alerts.length) state.lastEventAt = state.alerts[state.alerts.length - 1].ts;
    } catch (e) { /* older sensors: rely on the stream */ }
    if (state.view === 'integrity') loadLedger();
  }
  async function refreshHealth() { if (state.offline || state.conn !== 'open') return; try { state.health = await api('/api/health'); state.dirty.models = true; } catch (e) { /* keep last */ } }
  async function refreshStats() { if (state.offline || state.conn !== 'open') return; try { state.stats = await api('/api/stats'); state.dirty.models = true; state.dirty.chrome = true; } catch (e) { /* keep last */ } }
  async function pollExtractor() { if (state.offline || state.conn !== 'open') return; try { state.extractor = await api('/api/extractor/stats'); state.dirty.ingest = true; state.dirty.chrome = true; } catch (e) { /* keep last */ } }
  async function refreshPs() { if (state.offline || state.conn !== 'open') return; try { state.ps = await api('/api/ps26145'); state.dirty.overview = true; } catch (e) { /* older sensor */ } }
  async function refreshMetrics() { if (state.offline || state.conn !== 'open') return; try { state.metrics = await api('/api/metrics'); state.dirty.overview = true; state.dirty.chrome = true; } catch (e) { /* older sensor */ } }
  async function refreshDetectors() { if (state.offline || state.conn !== 'open') return; try { state.detectors = await api('/api/detectors'); state.dirty.models = true; } catch (e) { /* older sensor */ } }
  async function refreshTier2(refresh) {
    if (state.offline || state.conn !== 'open') return;
    try {
      state.tier2 = await api('/api/tier2' + (refresh ? '?refresh=true' : ''));
      const dm = state.tier2.demo;
      if (dm && !t2Polling && (!state.t2demo || state.t2demo.status !== 'running')) {
        state.t2demo = dm;
        if (dm.lines && dm.lines.length >= state.t2lines.length) state.t2lines = dm.lines.slice();
      }
      state.dirty.tier2 = true; state.dirty.overview = true;
    }
    catch (e) { state.tier2 = { error: e.message }; state.dirty.tier2 = true; }
    if (state.tier2 && state.tier2.demo && state.tier2.demo.status === 'running' && !t2Polling) pollT2Demo();
  }
  async function loadFigures() {
    if (state.offline || state.conn !== 'open') return;
    try { state.figs = await api('/api/figures'); state.dirty.figs = true; } catch (e) { /* older sensor */ }
  }

  // ---------------------------------------------------------------- tier 2 (Inspector-Sentry)
  let t2Polling = false;
  async function startT2Demo() {
    const full = $('#t2Full').checked;
    $('#t2Run').disabled = true;
    msg('#t2Msg', 'Starting…');
    try {
      await api('/api/tier2/demo', { method: 'POST', body: { fast: !full } });
      state.t2lines = []; state.t2demo = { status: 'running', result: {} };
      state.dirty.tier2 = true;
      pollT2Demo();
    } catch (e) { msg('#t2Msg', e.message, true); $('#t2Run').disabled = false; }
  }
  async function pollT2Demo() {
    t2Polling = true;
    try {
      for (;;) {
        const snap = await api('/api/tier2/demo?since=' + state.t2lines.length);
        if (snap.lines && snap.lines.length) state.t2lines = state.t2lines.concat(snap.lines);
        state.t2demo = snap;
        state.dirty.tier2 = true;
        if (snap.status !== 'running') break;
        await new Promise((r) => setTimeout(r, 900));
      }
    } catch (e) { msg('#t2Msg', e.message, true); }
    t2Polling = false;
    state.dirty.tier2 = true;
  }
  function t2StatusHtml(t) {
    if (!t) return 'Loading…';
    if (t.error) return 'This sensor does not serve Tier 2 (' + esc(t.error) + ').';
    if (!t.present) return 'The <code>tier2/</code> folder is not next to this sensor.';
    const torch = t.torch;
    let s = 'Tier 2 lives in <code>tier2/</code>. ' + esc(t.why_not_wired || '');
    if (torch) s += torch.ok ? ' PyTorch ' + esc(torch.detail || '') + ' is available to <code>' + esc(t.python) + '</code>, so the cascade can run here.'
      : ' PyTorch is not available to <code>' + esc(t.python) + '</code>: install it (<code>pip install torch --index-url https://download.pytorch.org/whl/cpu</code>) or set <code>NETSENTINEL_TIER2_PYTHON</code> to a Python that has it. The numbers and charts below do not need it.';
    return s;
  }
  function t2NumbersHtml(groups) {
    if (!groups || !groups.length) return '<span class="muted">No Tier 2 result files found.</span>';
    return groups.map((g) => '<div class="t2-group"><div class="t2-group-h">' + esc(g.title) + ' <span class="badge ' + (g.kind === 'real' ? 'pass' : 'na') + '">' + (g.kind === 'real' ? 'real data' : 'synthetic') + '</span></div>' +
      '<table class="table table-compact t2-table"><tbody>' + g.rows.map((r) =>
        '<tr><td class="t2-label">' + esc(r.label) + (r.note ? '<div class="dim t2-note">' + esc(r.note) + '</div>' : '') + '</td>' +
        '<td class="num mono t2-val">' + esc(r.display) + '</td>' +
        '<td class="mono dim t2-src">' + esc(r.source) + '</td>' +
        '<td><span class="badge ' + (r.status === 'matches' ? 'pass' : r.status === 'differs' ? 'fail' : 'na') + '" title="' + esc(r.documented != null ? 'documented: ' + JSON.stringify(r.documented) : '') + '">' + (r.status === 'matches' ? 'matches docs' : r.status === 'differs' ? 'differs' : 'reported') + '</span></td></tr>').join('') +
      '</tbody></table></div>').join('');
  }
  function renderTier2() {
    const t = state.tier2;
    $('#t2Status').innerHTML = t2StatusHtml(t);
    $('#t2Numbers').innerHTML = t2NumbersHtml(t && t.numbers);
    const figs = (t && t.figures) || [];
    const f1 = figs.find((f) => f.name === 'chart_escalation_budget.png'), f2 = figs.find((f) => f.name === 'chart_geometry_diagnostic.png');
    if (f1 && $('#t2Fig1').getAttribute('src') !== cfg.backend + f1.url) { $('#t2Fig1').src = cfg.backend + f1.url; $('#t2Fig1Cap').textContent = f1.caption; }
    if (f2 && $('#t2Fig2').getAttribute('src') !== cfg.backend + f2.url) { $('#t2Fig2').src = cfg.backend + f2.url; $('#t2Fig2Cap').textContent = f2.caption; }
    const d = state.t2demo || (t && t.demo) || { status: 'idle' };
    const running = d.status === 'running';
    const canRun = !!(t && t.present) && !state.offline && state.conn === 'open';
    $('#t2Run').disabled = running || !canRun;
    $('#t2Run').textContent = running ? 'Running…' : (d.status === 'done' ? 'Run again' : 'Run the cascade');
    if (running) msg('#t2Msg', 'Running' + (d.fast ? ' (fast)' : '') + '… ' + state.t2lines.length + ' lines');
    else if (d.status === 'done') msg('#t2Msg', 'Finished in ' + fmtNum((d.finished - d.started) || 0, 0) + ' s.');
    else if (d.status === 'error') msg('#t2Msg', d.error || 'The run failed.', true);
    const log = $('#t2Log');
    if (state.t2lines.length) {
      log.hidden = false;
      const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 30;
      log.textContent = state.t2lines.join('\n');
      if (atBottom || running) log.scrollTop = log.scrollHeight;
    }
    const r = d.result || {};
    const k = $('#t2Kpis');
    if (d.status === 'done' && r.router_auc) {
      k.hidden = false;
      const reached = r.attack_reached ? r.attack_reached : null;
      k.innerHTML = [
        ['Sentry agrees with Inspector', 'AUC ' + r.router_auc, 'ranking of host-windows'],
        ['Inspector flags recovered', (r.recovered_pct || '—') + '%', 'at a 5% escalation budget'],
        ['Host-days never escalated', (r.never_woken_pct || '—') + '%', 'settled by the Sentry alone'],
        ['Model size', r.params ? Number(r.params[0]).toLocaleString() + ' → ' + Number(r.params[1]).toLocaleString() : '—', r.params ? r.params[2] + '× smaller' : ''],
      ].map((x) => '<div class="kpi"><div class="k">' + esc(x[0]) + '</div><div class="v">' + esc(x[1]) + '</div><div class="p">' + esc(x[2]) + '</div></div>').join('') +
        (reached ? '<div class="t2-kpi-note">Attack windows that reached the Inspector: ' + esc(reached[0]) + ' (' + esc(reached[1]) + '%) — synthetic, indicative only.</div>' : '');
    } else if (!running) { k.hidden = true; }
  }
  function renderT2Teaser() {
    const el = $('#t2TeaserBody');
    if (!el) return;
    const t = state.tier2;
    if (!t || t.error || !t.present) { el.innerHTML = '<span class="muted">' + (t && t.error ? 'Not served by this sensor.' : (t ? 'tier2/ not found next to this sensor.' : 'Loading…')) + '</span>'; return; }
    const rows = [];
    (t.numbers || []).forEach((g) => g.rows.forEach((r) => rows.push(r)));
    const pick = (re) => rows.find((r) => re.test(r.label));
    const items = [
      [pick(/flags recovered/), 'of what the Inspector would flag reaches it at a 5% budget (real data)'],
      [pick(/Model size/), 'Sentry at the edge vs Inspector'],
      [pick(/within a host/), 'within-host AUC on real data — the weakest number'],
      [pick(/commodity implant/), 'Telegram-C2 per-window AUC: bounded, not solved'],
    ].filter((x) => x[0]);
    el.innerHTML = items.map((x) => '<div class="t2-teaser-item"><div class="v mono">' + esc(x[0].display) + '</div><div class="k">' + esc(x[1]) + '</div></div>').join('') +
      '<div class="t2-teaser-note muted">Verified standalone and not wired into the live sensor. Numbers re-derived from <code>tier2/*.json</code> now.</div>';
  }
  function figsHtml(list) {
    if (!list || !list.length) return '<span class="muted">None found.</span>';
    return list.map((f) => '<figure class="fig"><a href="' + esc(cfg.backend + f.url) + '" target="_blank" rel="noopener"><img loading="lazy" src="' + esc(cfg.backend + f.url) + '" alt="' + esc(f.caption) + '"></a><figcaption>' + esc(f.caption) + '</figcaption></figure>').join('');
  }
  function renderFigs() {
    const f = state.figs;
    if (!f) return;
    $('#modelFigs').innerHTML = figsHtml(f.models);
    $('#psFigs').innerHTML = figsHtml(f.ps26145);
  }
  $('#t2Run').addEventListener('click', startT2Demo);
  document.addEventListener('click', (ev) => { const g = ev.target.closest('[data-goto]'); if (g) { ev.preventDefault(); showView(g.getAttribute('data-goto')); } });
  function onStats(d) {
    state.stats = Object.assign({}, state.stats || {}, d);
    if (d.simulation_mode) { state.simMode = d.simulation_mode; state.simSeenAt = Date.now(); }
    if (d.pcap_complete) {
      state.replay = { name: d.pcap_file || (state.replay && state.replay.name) || 'capture', active: false, done: true, events: d.events_processed, alerts: d.alerts_generated };
      toast('Replay of ' + state.replay.name + ' finished: ' + fmtInt(d.events_processed) + ' events, ' + plural(d.alerts_generated || 0, 'alert') + '.');
    }
    state.dirty.models = true; state.dirty.chrome = true;
  }

  // ---------------------------------------------------------------- chrome (title, status bar)
  function renderChrome() {
    let kind = 'idle', label = 'Idle';
    if (state.offline) { kind = 'file'; label = 'Session file · ' + state.offlineName; }
    else if (state.conn !== 'open') { kind = 'idle'; label = 'No sensor'; }
    else if (state.extractor && state.extractor.live_capture_active) { kind = 'live'; label = 'Live capture' + (state.liveIface ? ' · ' + state.liveIface : ''); }
    else if (state.replay && state.replay.active) { kind = 'replay'; label = 'Replaying · ' + state.replay.name; }
    else if ((state.simMode && Date.now() - state.simSeenAt < 6000) || (state.metrics && state.metrics.source && state.metrics.source.kind === 'sim' && state.metrics.throughput && state.metrics.throughput.events_per_s > 0)) { kind = 'sim'; label = 'Simulator · ' + (state.simMode || state.metrics.source.detail) + ' (synthetic)'; }
    else if (state.replay && state.replay.done) { kind = 'replay'; label = 'Replayed · ' + state.replay.name; }
    const chip = $('#sourceChip');
    chip.setAttribute('data-kind', kind);
    $('.label', chip).textContent = label;
    const sen = $('#sensorLabel');
    if (state.sensorId) { sen.hidden = false; sen.textContent = 'Sensor ' + state.sensorId; } else sen.hidden = true;

    $('#countAlerts').textContent = fmtInt(state.alerts.length);
    const st = state.stats || {};
    $('#sbConn').textContent = state.offline ? 'Viewing ' + state.offlineName : (state.conn === 'open' ? 'Connected to ' + cfg.backend.replace(/^https?:\/\//, '') : 'Not connected to ' + cfg.backend.replace(/^https?:\/\//, ''));
    $('#sbFlows').textContent = 'Flows ' + fmtInt(st.flows_processed || 0);
    $('#sbAlerts').textContent = 'Alerts ' + fmtInt(state.alerts.length);
    $('#sbReceipts').textContent = 'Signed ' + fmtInt(state.alerts.filter((a) => a.receipt).length);
    $('#sbLast').textContent = state.offline ? 'Saved session (not live)' : (state.lastEventAt ? 'Last alert ' + fmtAgo(state.lastEventAt) : 'No alerts yet');
    const mt = state.metrics && state.metrics.throughput;
    $('#sbRate').textContent = mt ? fmtNum(mt.flows_per_s, 1) + ' flows/s · ' + fmtNum(mt.mbps, 2) + ' Mbps' : '— flows/s';
    const fl = state.metrics && state.metrics.latency_ms && state.metrics.latency_ms.event && state.metrics.latency_ms.event.flow;
    $('#sbLat').textContent = fl && fl.n ? 'flow p95 ' + fmtMs(fl.p95) : 'p95 —';
  }
  function tickClock() {
    const d = new Date();
    if (cfg.tz === 'utc') $('#clock').textContent = d.toISOString().slice(11, 19) + ' UTC';
    else $('#clock').textContent = pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }

  // ---------------------------------------------------------------- views & keys
  function showView(v) {
    state.view = v;
    $$('.tab').forEach((t) => t.classList.toggle('active', t.getAttribute('data-view') === v));
    $$('.view').forEach((s) => s.classList.toggle('active', s.getAttribute('data-view') === v));
    if (v === 'integrity') loadLedger();
    if (v === 'ingest') { pollExtractor(); pollBench(); }
    if (v === 'models') { refreshHealth(); refreshDetectors(); refreshMetrics(); if (!state.figs) loadFigures(); }
    if (v === 'tier2') { refreshTier2(!state.tier2 || !state.tier2.torch); }
    if (v === 'overview') { refreshPs(); refreshMetrics(); }
    markAll();
  }
  $('#tabs').addEventListener('click', (ev) => { const t = ev.target.closest('.tab'); if (t) showView(t.getAttribute('data-view')); });

  document.addEventListener('keydown', (ev) => {
    const tag = (ev.target.tagName || '').toLowerCase();
    const typing = tag === 'input' || tag === 'textarea' || tag === 'select';
    if (ev.key === 'Escape') {
      if (typing) { ev.target.blur(); return; }
      if (state.selected) { state.selected = null; $('#detail').hidden = true; state.dirty.grid = true; }
      return;
    }
    if (typing || ev.ctrlKey || ev.metaKey || ev.altKey || $('#settingsDialog').open) return;
    if (ev.key === '/') { ev.preventDefault(); showView('alerts'); $('#filterInput').focus(); $('#filterInput').select(); }
    else if (state.view === 'alerts' && (ev.key === 'j' || ev.key === 'ArrowDown')) { ev.preventDefault(); moveSelection(1); }
    else if (state.view === 'alerts' && (ev.key === 'k' || ev.key === 'ArrowUp')) { ev.preventDefault(); moveSelection(-1); }
    else if (ev.key === 'p') togglePause();
    else if (ev.key === 'g') { const g = $('#groupToggle'); g.checked = !g.checked; g.dispatchEvent(new Event('change')); }
  });

  // ---------------------------------------------------------------- settings dialog
  function openSettings() {
    $('#setBackend').value = cfg.backend;
    $('#setTheme').value = cfg.theme;
    $('#setTz').value = cfg.tz;
    $('#setMax').value = String(cfg.max);
    $('#setMaskIp').checked = cfg.maskIp;
    $('#setMaskDomain').checked = cfg.maskDomain;
    $('#settingsDialog').showModal();
  }
  $('#settingsBtn').addEventListener('click', openSettings);
  $('#settingsDialog').addEventListener('close', () => {
    if ($('#settingsDialog').returnValue !== 'save') return;
    const prev = cfg.backend;
    cfg.backend = ($('#setBackend').value.trim() || defaultBackend()).replace(/\/+$/, '');
    cfg.theme = $('#setTheme').value;
    cfg.tz = $('#setTz').value;
    cfg.max = +$('#setMax').value || 5000;
    cfg.maskIp = $('#setMaskIp').checked;
    cfg.maskDomain = $('#setMaskDomain').checked;
    store.set('backend', cfg.backend === defaultBackend() ? '' : cfg.backend);
    store.set('theme', cfg.theme); store.set('tz', cfg.tz); store.set('max', cfg.max);
    store.set('maskIp', cfg.maskIp); store.set('maskDomain', cfg.maskDomain);
    applyTheme();
    state.detailFor = null;
    if (cfg.backend !== prev && !state.offline) { state.alerts = []; state.ids.clear(); state.arrived.clear(); backoff = 1000; connect(); }
    markAll();
  });

  // ---------------------------------------------------------------- misc
  let toastTimer = null;
  function toast(text) {
    const t = $('#toast');
    t.textContent = text; t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, 4500);
  }
  function copyText(s) {
    const done = () => toast('Copied.');
    if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(s).then(done, () => fallbackCopy(s, done)); }
    else fallbackCopy(s, done);
  }
  function fallbackCopy(s, done) {
    const ta = document.createElement('textarea');
    ta.value = s; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); done(); } catch (e) { toast('Copy failed.'); }
    ta.remove();
  }

  // ---------------------------------------------------------------- render loop
  let lastRows = -1;
  function tick() {
    if (state.queue.length) { const q = state.queue; state.queue = []; ingest(q, true); }
    if (state.paused) renderPause();
    const d = state.dirty;
    if (state.view === 'alerts') {
      if (d.grid) {
        const sel = state.selected;
        buildRows();
        renderSevToggles(); renderClassSelect(); renderTimeChip();
        renderGrid();
        if (sel && !state.rows.some((r) => rowKey(r) === sel) && state.group) { state.selected = null; $('#detail').hidden = true; }
        renderDetail(false);
        d.grid = false;
        lastRows = state.rows.length;
      }
      if (d.histo) { renderHisto(); d.histo = false; }
    }
    if (d.overview && state.view === 'overview') { renderOverview(); renderT2Teaser(); d.overview = false; }
    if (d.hosts) { renderHosts(); d.hosts = false; }
    if (d.models && state.view === 'models') { renderModels(); d.models = false; }
    if (d.figs && state.view === 'models') { renderFigs(); d.figs = false; }
    if (d.tier2 && state.view === 'tier2') { renderTier2(); d.tier2 = false; }
    if (d.integrity && state.view === 'integrity') { renderIntegrity(); d.integrity = false; }
    if (d.ingest && state.view === 'ingest') { renderIngest(); d.ingest = false; }
    if (d.chrome) { renderChrome(); d.chrome = false; }
  }

  renderHead();
  renderSevToggles();
  tickClock();
  setInterval(tickClock, 1000);
  setInterval(tick, 250);
  setInterval(() => { state.dirty.chrome = true; if (state.arrived.size) { const now = Date.now(); for (const [id, t] of state.arrived) if (now - t > 2000) state.arrived.delete(id); } }, 1000);
  setInterval(() => { refreshHealth(); refreshStats(); }, 10000);
  setInterval(() => { if (state.view === 'ingest' || (state.extractor && state.extractor.live_capture_active)) pollExtractor(); }, 2000);
  setInterval(() => { if (state.view === 'integrity') loadLedger(); }, 15000);
  setInterval(() => { if (state.view === 'overview') refreshPs(); if (state.view === 'models') refreshDetectors(); }, 5000);
  setInterval(() => { if (!ws || ws.readyState !== 1) refreshMetrics(); }, 5000);
  window.addEventListener('resize', () => { state.dirty.histo = true; state.dirty.grid = true; });
  connect();
})();
