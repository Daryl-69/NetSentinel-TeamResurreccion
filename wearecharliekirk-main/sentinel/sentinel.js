/* NetSentinel — Inspector·Sentry view driver.
   Left: the live cascade (real Tier 2 models, streamed hour by hour from the backend).
   Right + charts: live detections from the sensor's /ws feed and /api/ps26145.  */
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var API = "";                                   // same origin as the page
  var el = {};
  ["tpNow","evNow","alertNow","conn","connText","clock","phaseTrack","hostGrid","boot","bootTitle",
   "bootLog","liveHosts","budgetPct","escN","verdicts","dayN","hourClock","totline","inspectorCore",
   "sentryParams","inspParams","flowSvg","cascadeBody","sparkAlerts","scoreChart","scoreHost","latBars",
   "compA","compB","compX","chainHost","chainSteps","c2Timeline","c2Gaps","c2Side","famTiles","ticker",
   "criteria","banner","modeBadge","cascadeHint"].forEach(function (k) { el[k] = $(k); });

  var CHAIN = [
    { key: "Recon_API",       icon: "01", name: "Recon API",   d: "enumerate" },
    { key: "Code_Repo_Paste", icon: "02", name: "Code / paste", d: "stage" },
    { key: "Messaging_API",   icon: "03", name: "Messaging",   d: "beacon" },
    { key: "Cloud_Storage",   icon: "04", name: "Cloud store",  d: "exfil" }
  ];
  // seven PS 26145 families as feed tiles (a..f, with DGA/tunnel split for clarity)
  var FAM = [
    { k: "a", cls: "DDoS",              lbl: "DDoS" },
    { k: "b", cls: "C2 Beacon",         lbl: "C2 beacon" },
    { k: "c", cls: "DGA",               lbl: "DGA" },
    { k: "c", cls: "DNS Tunnel",        lbl: "DNS tunnel" },
    { k: "d", cls: "Encrypted Malware", lbl: "Encrypted" },
    { k: "e", cls: "Port Scan",         lbl: "Recon / scan" },
    { k: "f", cls: "Data Exfiltration", lbl: "Exfil" }
  ];
  var SEV = {
    CRITICAL: { c: "#ff4d4d", b: "rgba(255,77,77,.18)" },
    HIGH:     { c: "#ff7a1a", b: "rgba(255,122,26,.18)" },
    MEDIUM:   { c: "#ffb02e", b: "rgba(255,176,46,.16)" },
    LOW:      { c: "#8f8c85", b: "rgba(140,140,140,.14)" },
    INFO:     { c: "#8f8c85", b: "rgba(140,140,140,.12)" }
  };

  var famCount = {}, famEl = {}, seenAlert = {};
  var alertTotal = 0, evTotal = 0, tps = new Array(90).fill(0);
  var meta = null, lastSeq = 0, lastHour = null, hostEl = {}, targetId = null;
  var scoreHist = [];                    // watched host's Sentry score per hour
  var c2Drawn = false;

  /* ---------------- family tiles + criteria ---------------- */
  function buildFam() {
    el.famTiles.innerHTML = "";
    FAM.forEach(function (f, i) {
      famCount[f.cls] = 0;
      var d = document.createElement("div");
      d.className = "ftile";
      d.innerHTML = '<div class="fk">' + f.k + '</div><div class="fn">0</div><div class="fl">' + f.lbl + '</div>';
      el.famTiles.appendChild(d);
      famEl[i] = d;
    });
  }
  function bumpFam(cls) {
    for (var i = 0; i < FAM.length; i++) {
      if (FAM[i].cls === cls) {
        famCount[cls]++;
        var d = famEl[i];
        d.querySelector(".fn").textContent = famCount[cls];
        d.classList.add("hot"); d.classList.remove("pulse");
        void d.offsetWidth; d.classList.add("pulse");
        return;
      }
    }
  }
  function loadCriteria() {
    fetch(API + "/api/ps26145").then(function (r) { return r.json(); }).then(function (d) {
      var h = '<span class="crit-h">PS 26145</span>';
      (d.threats || []).forEach(function (t) {
        var on = t.active;
        h += '<div class="crumb ' + (on ? "ok" : "") + '"><span class="ck">' + t.id + '</span>' +
             (t.title || "") + '</div>';
      });
      h += '<span class="crit-sep"></span>';
      (d.constraints || []).forEach(function (c) {
        var ok = c.status === "met" || c.status === "measured";
        h += '<div class="crumb ' + (ok ? "ok" : "") + '"><span class="ck">' + (ok ? "✓" : "·") +
             '</span>' + (c.title || "") + '</div>';
      });
      el.criteria.innerHTML = h;
    }).catch(function () {});
  }

  /* ---------------- live feed (WebSocket) ---------------- */
  function connect() {
    var proto = location.protocol === "https:" ? "wss:" : "ws:";
    var ws;
    try { ws = new WebSocket(proto + "//" + location.host + "/ws"); }
    catch (e) { el.conn.dataset.s = "down"; el.connText.textContent = "offline"; return; }
    ws.onopen = function () { el.conn.dataset.s = "open"; el.connText.textContent = "live feed"; };
    ws.onclose = function () { el.conn.dataset.s = "down"; el.connText.textContent = "reconnecting"; setTimeout(connect, 2000); };
    ws.onerror = function () { try { ws.close(); } catch (e) {} };
    ws.onmessage = function (ev) {
      var m; try { m = JSON.parse(ev.data); } catch (e) { return; }
      if (m.type === "alert" && m.data) onAlert(m.data, true);
      else if (m.type === "metrics" && m.data) onMetrics(m.data);
      else if (m.type === "stats" && m.data) onStats(m.data);
    };
  }
  // backfill recent alerts so the page is correct whenever it opens
  function backfill() {
    fetch(API + "/api/alerts?limit=80").then(function (r) { return r.json(); }).then(function (d) {
      var arr = (d.alerts || []).slice().reverse();     // oldest first
      arr.forEach(function (a) { onAlert(a, false); });
    }).catch(function () {});
  }
  function onMetrics(mx) {
    var tp = mx.throughput || {};
    el.tpNow.textContent = fmt(Math.round(tp.events_per_s || 0));
    if (mx.totals) { evTotal = mx.totals.events || evTotal; el.evNow.textContent = fmt(evTotal); }
  }
  function onStats(s) {
    if (s && s.total_alerts != null) { /* handled by counter */ }
  }
  function onAlert(a, live) {
    if (a.id) { if (seenAlert[a.id]) return; seenAlert[a.id] = 1; }
    alertTotal++; el.alertNow.textContent = fmt(alertTotal);
    if (live) tps[tps.length - 1]++;
    bumpFam(a.threat_class);
    addTicker(a);
    if (a.threat_class === "C2 Beacon" && a.evidence) drawC2(a);
  }
  function addTicker(a) {
    var sev = SEV[a.severity] || SEV.LOW;
    var t = document.createElement("div");
    t.className = "trow";
    t.style.setProperty("--sc", sev.c); t.style.setProperty("--sb", sev.b);
    var conf = a.confidence != null ? (Math.round(a.confidence * 100) + "%") : "";
    t.innerHTML = '<span class="tt">' + hhmmss(a.timestamp) + '</span>' +
      '<span class="tb">' + (a.severity || "") + '</span>' +
      '<span class="tc">' + esc(a.threat_class) + ' <span>' + esc(a.threat_subtype || "") + '</span></span>' +
      '<span class="ts">' + conf + '</span>';
    var em = el.ticker.querySelector(".ticker-empty"); if (em) em.remove();
    el.ticker.insertBefore(t, el.ticker.firstChild);
    while (el.ticker.children.length > 40) el.ticker.removeChild(el.ticker.lastChild);
  }

  /* ---------------- C2 timeline ---------------- */
  function drawC2(a) {
    var ev = a.evidence || {}, iat = ev.iat;
    if (!iat || !iat.length) return;
    c2Drawn = true;
    // reconstruct check-in times from inter-arrivals
    var times = [0], t = 0;
    for (var i = 0; i < iat.length; i++) { t += iat[i]; times.push(t); }
    var span = times[times.length - 1] || 1;
    var d1 = dims(el.c2Timeline, 62), W = d1.w;
    var s1 = el.c2Timeline; s1.innerHTML = "";
    line(s1, 0, 26, W, 26, "#2a2d36", 1);
    times.forEach(function (tt) {
      var x = tt / span * (W - 2) + 1;
      mk(s1, "line", { x1: x, y1: 8, x2: x, y2: 44, stroke: "#ff7a1a", "stroke-width": 1.5 });
    });
    txt(s1, 1, 58, "check-ins on a fixed interval — " + (ev.checkins || "") + " calls to one host");
    // gaps chart
    var d2 = dims(el.c2Gaps, 74); W = d2.w;
    var s2 = el.c2Gaps; s2.innerHTML = "";
    var mx = Math.max.apply(null, iat), mn = Math.min.apply(null, iat);
    var mid = ev.beacon_interval || (mx + mn) / 2;
    var lo = mid * 0.8, hi = mid * 1.2, rng = hi - lo || 1;
    var bw = W / iat.length;
    iat.forEach(function (g, i) {
      var hnorm = Math.max(4, Math.min(54, (1 - (g - lo) / rng) * 50 + 4));
      mk(s2, "rect", { x: i * bw + .6, y: 58 - hnorm, width: Math.max(1, bw - 1.2), height: hnorm, rx: 1, fill: "#ff9a4a" });
    });
    txt(s2, 1, 71, "gap between calls ≈ " + (mid ? mid.toFixed(0) : "?") + " s, barely varying");
    // side stats
    var cv = ev.coefficient_of_variation, comp = ev.components || {};
    var side = '<div class="c2-big">' + (a.confidence != null ? Math.round(a.confidence * 100) + "%" : "") +
      ' <small>periodicity</small></div>' +
      '<div class="c2-kv">' + esc(a.source_ip || "host") + ' → ' + esc(a.dest_ip || "one host") + ' :' + (ev.dst_port || "") + '</div>' +
      '<div class="c2-kv">gap <b>' + (ev.median_gap_s ? ev.median_gap_s.toFixed(1) : "?") + ' s</b> · jitter <b>' +
      (cv != null ? (cv * 100).toFixed(1) + "%" : "?") + '</b></div>';
    var order = [["T", "timing"], ["F", "spectrum"], ["S", "size"], ["R", "rarity"], ["C", "persistence"]];
    order.forEach(function (o) {
      var v = comp[o[0]]; if (v == null) return;
      side += '<div class="comp"><span>' + o[1] + '</span><span class="ct"><span class="cf" style="width:' +
        Math.round(v * 100) + '%"></span></span><span class="cv">' + v.toFixed(2) + '</span></div>';
    });
    el.c2Side.innerHTML = side;
  }

  /* ---------------- detections-per-second spark ---------------- */
  function drawSpark() {
    var H = 112, pad = 16, d = dims(el.sparkAlerts, H), W = d.w, s = el.sparkAlerts; s.innerHTML = "";
    var mx = Math.max(1, Math.max.apply(null, tps));
    line(s, 0, H - pad, W, H - pad, "#22252e", 1);
    txt(s, 0, 11, "peak " + mx + " / s");
    var pts = tps.map(function (v, i) {
      var x = i / (tps.length - 1) * W;
      var y = (H - pad) - (v / mx) * (H - pad - 14);
      return x + "," + y;
    });
    var area = "0," + (H - pad) + " " + pts.join(" ") + " " + W + "," + (H - pad);
    if (!s.querySelector("defs")) {
      var defs = mk(s, "defs", {});
      var g = mk(defs, "linearGradient", { id: "sg", x1: 0, y1: 0, x2: 0, y2: 1 });
      mk(g, "stop", { offset: 0, "stop-color": "#ff7a1a", "stop-opacity": .45 });
      mk(g, "stop", { offset: 1, "stop-color": "#ff7a1a", "stop-opacity": 0 });
    }
    mk(s, "polygon", { points: area, fill: "url(#sg)", stroke: "none" });
    mk(s, "polyline", { points: pts.join(" "), fill: "none", stroke: "#ff7a1a", "stroke-width": 2 });
  }
  function drawScoreChart() {
    var H = 112, pad = 16, d = dims(el.scoreChart, H), W = d.w, s = el.scoreChart; s.innerHTML = "";
    line(s, 0, H - pad, W, H - pad, "#22252e", 1);
    var ymax = 1.6;
    var thY = (H - pad) - (1 / ymax) * (H - pad - 16);
    mk(s, "line", { x1: 0, y1: thY, x2: W, y2: thY, stroke: "#ffb02e", "stroke-width": 1, "stroke-dasharray": "4 4" });
    txt(s, 1, thY - 4, "flag line").setAttribute("fill", "#ffb02e");
    if (scoreHist.length < 2) { txt(s, 2, H - pad - 6, "waiting for the watched host…").setAttribute("fill", "#7f7c75"); return; }
    var pts = scoreHist.map(function (v, i) {
      var x = i / Math.max(1, scoreHist.length - 1) * W;
      var y = (H - pad) - (Math.min(v.score, ymax) / ymax) * (H - pad - 16);
      return { x: x, y: y, f: v.flagged, atk: v.attack };
    });
    mk(s, "polyline", { points: pts.map(function (p) { return p.x + "," + p.y; }).join(" "),
      fill: "none", stroke: "#ff7a1a", "stroke-width": 2 });
    pts.forEach(function (p) {
      mk(s, "circle", { cx: p.x, cy: p.y, r: p.f ? 3.4 : 2, fill: p.f ? "#ff4d4d" : (p.atk ? "#ffb02e" : "#ff9a4a") });
    });
  }

  /* ---------------- cascade (Tier 2 stream) ---------------- */
  function startCascade() {
    fetch(API + "/api/cascade/start", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ tick: 0.9 }) })
      .then(function () { pollCascade(); })
      .catch(function () { el.bootTitle.textContent = "Cascade backend not reachable"; });
  }
  function pollCascade() {
    fetch(API + "/api/cascade/state?since=" + lastSeq).then(function (r) { return r.json(); }).then(function (st) {
      applyCascade(st);
      setTimeout(pollCascade, 600);
    }).catch(function () { setTimeout(pollCascade, 1500); });
  }

  function applyCascade(st) {
    // boot log / phase track
    setPhase(st.stage);
    if (st.status === "error") {
      el.boot.hidden = false;
      el.bootTitle.textContent = "The cascade could not start";
      el.bootLog.innerHTML = '<div class="boot-err">' + esc(st.error || "unknown error") + '</div>';
      return;
    }
    if (st.status !== "running" || (st.mode === "real" && st.meta && st.meta.hosts && !st.meta.hosts.length)) {
      el.boot.hidden = false;
      if (st.mode === "real" && st.status === "running")
        el.bootTitle.textContent = st.meta.threshold ? "Watching real traffic — waiting for the first connections…"
                                                     : "Collecting real traffic to commission the Inspector…";
      if (st.logs && st.logs.length) el.bootLog.innerHTML = st.logs.slice(-4).map(function (l) { return "<div>" + esc(l) + "</div>"; }).join("");
      return;
    }
    showMode(st.mode, st);
    // running: build the grid once -- and again whenever the real device set changes
    if (st.meta && st.meta.hosts && (!meta || (st.meta.version || 0) !== (meta.version || 0))) {
      meta = st.meta;
      targetId = meta.target ? meta.target.id : null;
      buildGrid(meta);
      el.boot.hidden = true;
      if (meta.params) {
        el.sentryParams.textContent = fmt(meta.params.sentry) + " params";
        el.inspParams.textContent = fmt(meta.params.inspector) + " params";
        el.compA.textContent = fmt(meta.params.inspector);
        el.compB.textContent = fmt(meta.params.sentry);
        el.compX.textContent = meta.params.ratio + "×";
      }
      if (meta.budget != null) el.budgetPct.textContent = Math.round(meta.budget * 100) + "%";
      targetId = meta.target ? meta.target.id : null;
      buildChain();
    }
    // apply the newest hour we haven't seen
    if (st.hours && st.hours.length) {
      st.hours.forEach(function (h) { lastSeq = Math.max(lastSeq, h.seq); });
      renderHour(st.hours[st.hours.length - 1], st);
    }
  }

  function showMode(mode, st) {
    if (!mode) return;
    el.modeBadge.hidden = false;
    el.modeBadge.className = "mode-badge" + (mode === "real" ? " real" : "");
    if (mode === "real") {
      var ins = st.inspector || {}, live = ins.live || {}, base = ins.baseline || {};
      el.modeBadge.textContent = "REAL TRAFFIC" + (st.iface ? " · " + st.iface : "");
      el.cascadeHint.textContent = "your devices, hour by hour · commissioned on " + (base.host_days || 0) +
        " baseline + " + ((ins.model || {}).live_host_days || 0) + " live device-days · live corpus " +
        (live.windows || 0) + " windows" + (ins.training ? " · retraining…" : "") +
        (ins.calibration && !ins.calibration.done ? " · calibrating to this network " +
          ins.calibration.device_hours + "/" + ins.calibration.needed + " device-hours (no alerts yet)" : "");
    } else {
      el.modeBadge.textContent = "SYNTHETIC DEMO";
    }
  }

  function setPhase(stage) {
    var idx = { building: 1, commissioning: 1, distilling: 2, watching: 3 }[stage] || 0;
    Array.prototype.forEach.call(el.phaseTrack.children, function (c) {
      var n = +c.dataset.ph;
      c.classList.toggle("active", n === idx);
      c.classList.toggle("done", n < idx);
    });
  }

  function buildGrid(m) {
    var hosts = m.hosts, n = hosts.length;
    var cols = Math.ceil(Math.sqrt(n * 1.5));
    // a real network may have one or two devices: keep tiles tile-sized
    if (n < 12) cols = Math.max(4, cols);
    el.hostGrid.style.gridTemplateColumns = "repeat(" + cols + ",1fr)";
    el.hostGrid.style.gridAutoRows = n < 12 ? "72px" : "1fr";
    el.hostGrid.innerHTML = "";
    hostEl = {};
    hosts.forEach(function (h) {
      var parts = h.name.split("-");
      var d = document.createElement("div");
      if (h.ip) d.title = h.ip;
      d.className = "host off" + (targetId === h.id ? " target" : "");
      d.innerHTML = '<span class="hr">' + esc(parts[0]) + '</span><span class="hn">' + esc(parts[1] || "") + '</span>';
      el.hostGrid.appendChild(d);
      hostEl[h.id] = d;
    });
  }

  // orange ramp for a Sentry score in [0, ~1.3]
  function ramp(v) {
    var t = Math.max(0, Math.min(1, v / 1.15));
    var r = Math.round(22 + t * 233), g = Math.round(24 + t * 98), b = Math.round(31 - t * 25);
    return "rgb(" + r + "," + g + "," + b + ")";
  }

  function renderHour(h, st) {
    renderHour._seen = renderHour._seen || {};
    el.dayN.textContent = h.day;
    el.hourClock.textContent = h.clock;
    el.liveHosts.textContent = h.live_hosts;
    el.escN.textContent = h.escalated.length;

    // hosts
    var esc = {}; (h.escalated || []).forEach(function (id) { esc[id] = true; });
    var flagged = {}; (h.verdicts || []).forEach(function (v) { if (v.flagged) flagged[v.host] = true; });
    (h.sentry || []).forEach(function (score, id) {
      var d = hostEl[id]; if (!d) return;
      d.classList.remove("off", "hot", "escalated", "flagged");
      if (score == null) { d.classList.add("off"); d.style.background = ""; return; }
      d.style.background = ramp(score);
      if (score > 0.55) d.classList.add("hot");
      if (esc[id]) d.classList.add("escalated");
      if (flagged[id]) d.classList.add("flagged");
    });

    // inspector core state
    el.inspectorCore.classList.toggle("busy", h.escalated.length > 0);
    var targetFlag = h.verdicts.some(function (v) { return v.host === h.target && v.flagged; });
    el.inspectorCore.classList.toggle("alarm", targetFlag);

    // verdict rows (escalated hosts this hour)
    var vh = "";
    (h.verdicts || []).slice(0, 6).forEach(function (v) {
      var flag = v.flagged, isT = v.host === h.target;
      var ratio = (v.error / (h.threshold || 1));
      vh += '<div class="vrow ' + (flag ? "flag" : "clear") + '">' +
        '<span class="vv"></span>' +
        '<span class="vt">' + (isT ? "▶ " : "") + '</span>' +
        '<span class="vn">' + esc2(v.name) + '</span>' +
        '<span class="vc">' + (flag ? "FLAG " : "clear ") + '×' + ratio.toFixed(2) + '</span>' +
        (flag && v.categories && v.categories.length ?
          '<span class="vcat">' + v.categories.slice(0, 4).join(" · ") + '</span>' : '') +
        '</div>';
    });
    el.verdicts.innerHTML = vh || '<div class="ticker-empty">no host crossed the escalation budget this hour</div>';

    // flow lines from escalated hosts to inspector
    drawFlow(h.escalated || []);

    // totals
    var tt = h.totals || {};
    el.totline.innerHTML =
      '<span><b>' + fmt(tt.scored || 0) + '</b>host-hours watched</span>' +
      '<span class="amb"><b>' + fmt(tt.escalated || 0) + '</b>escalated</span>' +
      '<span class="red"><b>' + fmt(tt.confirmed || 0) + '</b>flagged</span>';

    // latency bars
    drawLat(h.sentry_ms, h.inspector_ms);

    // watched host's score chart
    var tv = (h.sentry && h.target != null) ? h.sentry[h.target] : null;
    if (tv != null) {
      scoreHist.push({ score: tv, flagged: targetFlag, attack: h.attack_active });
      if (scoreHist.length > 48) scoreHist.shift();
      if (meta && meta.target) el.scoreHost.textContent = meta.target.name;
      drawScoreChart();
    }

    // chain
    updateChain(h);

    // real traffic: banner once per flagged device and hour
    if (h.mode === "real") {
      (h.verdicts || []).forEach(function (v) {
        var key = v.host + "@" + (h.date || "") + h.hour;
        if (v.flagged && !renderHour._seen[key]) {
          renderHour._seen[key] = true;
          banner("Inspector flagged " + v.name + (v.ip ? " (" + v.ip + ")" : ""),
            (v.categories || []).join("  ›  "), true);
        }
      });
      return;
    }
    // banner on a fresh target flag
    if (targetFlag && !renderHour._flagged) {
      renderHour._flagged = true;
      banner("Inspector flagged " + (meta.target ? meta.target.name : "the watched host"),
        h.target_categories && h.target_categories.length ? h.target_categories.join("  ›  ") : "", true);
    }
    if (!h.attack_active) renderHour._flagged = false;
  }

  function drawFlow(escIds) {
    var svg = el.flowSvg;
    if (!svg.getAttribute("viewBox")) {
      var r = el.cascadeBody.getBoundingClientRect();
      svg.setAttribute("viewBox", "0 0 " + r.width + " " + r.height);
    }
    svg.innerHTML = "";
    var body = el.cascadeBody.getBoundingClientRect();
    var core = el.inspectorCore.getBoundingClientRect();
    var tx = core.left - body.left, ty = core.top - body.top + core.height / 2;
    escIds.slice(0, 8).forEach(function (id) {
      var d = hostEl[id]; if (!d) return;
      var b = d.getBoundingClientRect();
      var sx = b.right - body.left, sy = b.top - body.top + b.height / 2;
      var mx = (sx + tx) / 2;
      var dd = "M" + sx + "," + sy + " C" + mx + "," + sy + " " + mx + "," + ty + " " + tx + "," + ty;
      // faint continuous rail
      mk(svg, "path", { d: dd, fill: "none", stroke: "rgba(255,176,46,.28)", "stroke-width": 1.4, "vector-effect": "non-scaling-stroke" });
      // bright travelling pulse along it
      var p = mk(svg, "path", { d: dd, fill: "none", stroke: "#ffb02e", "stroke-width": 2, "vector-effect": "non-scaling-stroke",
        "stroke-linecap": "round", "stroke-dasharray": "14 120" });
      mk(p, "animate", { attributeName: "stroke-dashoffset", from: 134, to: 0, dur: "1.1s", repeatCount: "indefinite" });
    });
  }

  function drawLat(sMs, iMs) {
    var mx = Math.max(sMs || 0, iMs || 0, 1);
    el.latBars.innerHTML =
      latRow("Sentry", "every host", sMs, mx, "linear-gradient(90deg,#d9580a,#ff7a1a)") +
      latRow("Inspector", "escalated only", iMs, mx, "linear-gradient(90deg,#c98a00,#ffb02e)");
  }
  function latRow(name, sub, ms, mx, grad) {
    var w = Math.max(3, (ms || 0) / mx * 100);
    return '<div class="latbar"><div class="lh"><span>' + name + ' <span class="dim">' + sub + '</span></span>' +
      '<b>' + (ms != null ? ms.toFixed(1) : "—") + ' ms</b></div>' +
      '<div class="lt"><div class="lf" style="width:' + w + '%;background:' + grad + '"></div></div></div>';
  }

  /* ---------------- chain ---------------- */
  function buildChain() {
    el.chainSteps.innerHTML = CHAIN.map(function (c) {
      return '<div class="cstep" data-k="' + c.key + '"><div class="ci">' + c.icon + '</div>' +
        '<div class="cn">' + c.name + '</div><div class="cd">' + c.d + '</div></div>';
    }).join("");
  }
  function updateChain(h) {
    var on = {}; (h.target_categories || []).forEach(function (c) { on[c] = true; });
    var active = h.attack_active || h.mode === "real";
    var reached = -1;
    CHAIN.forEach(function (c, i) { if (on[c.key]) reached = i; });
    Array.prototype.forEach.call(el.chainSteps.children, function (node, i) {
      node.classList.remove("on", "done");
      if (!active) return;
      if (on[CHAIN[i].key]) node.classList.add("on");
      else if (i < reached) node.classList.add("done");
    });
    if (h.mode === "real" && meta && meta.target) {
      el.chainHost.innerHTML = 'Real traffic · watching <b>' + esc2(meta.target.name) + '</b> — this hour: ' +
        ((h.target_categories || []).length ? esc2(h.target_categories.join(" · ")) : "no traffic");
    } else if (active && meta && meta.target) {
      var stepName = reached >= 0 ? CHAIN[reached].name : "starting";
      el.chainHost.innerHTML = 'Watching <b>' + esc2(meta.target.name) + '</b> — now at <span class="red">' + esc2(stepName) + '</span>';
    } else if (meta && meta.target) {
      el.chainHost.innerHTML = '<b>' + esc2(meta.target.name) + '</b> is the host to watch — behaving normally so far';
    }
  }

  /* ---------------- banner ---------------- */
  var bannerT = null;
  function banner(text, sub, red) {
    el.banner.hidden = false;
    el.banner.className = "banner" + (red ? " red" : "");
    el.banner.innerHTML = esc2(text) + (sub ? '<small>' + esc2(sub) + '</small>' : "");
    clearTimeout(bannerT);
    bannerT = setTimeout(function () { el.banner.hidden = true; }, 7000);
  }

  /* ---------------- svg + util helpers ---------------- */
  // measure the svg in real pixels and give it a matching viewBox, so text is never stretched
  function dims(s, h) {
    var w = s.clientWidth || s.parentNode.clientWidth || 380;
    s.setAttribute("viewBox", "0 0 " + w + " " + h);
    s.setAttribute("preserveAspectRatio", "none");
    return { w: w, h: h };
  }
  function mk(parent, tag, attrs) {
    var e = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    parent.appendChild(e); return e;
  }
  function line(s, x1, y1, x2, y2, col, w) { mk(s, "line", { x1: x1, y1: y1, x2: x2, y2: y2, stroke: col, "stroke-width": w }); }
  function txt(s, x, y, str) { var t = mk(s, "text", { x: x, y: y }); t.textContent = str; return t; }
  function fmt(n) { return (n == null ? 0 : n).toLocaleString("en-US"); }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]; }); }
  function esc2(s) { return esc(s); }
  function hhmmss(ts) { try { return new Date(ts).toLocaleTimeString("en-GB"); } catch (e) { return ""; } }

  function tickClock() {
    el.clock.textContent = new Date().toLocaleTimeString("en-GB");
    // roll the per-second detection buffer
    tps.push(0); if (tps.length > 90) tps.shift();
    drawSpark();
  }

  /* ---------------- boot ---------------- */
  buildFam();
  loadCriteria();
  connect();
  backfill();
  startCascade();
  drawSpark(); drawScoreChart();
  tickClock(); setInterval(tickClock, 1000);
  setInterval(loadCriteria, 8000);
  setInterval(backfill, 9000);          // self-heal any alert the socket missed
  window.addEventListener("resize", function () { el.flowSvg.removeAttribute("viewBox"); if (lastHour) drawFlow(lastHour.escalated || []); });
})();
