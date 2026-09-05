#!/usr/bin/env python3
"""Build results_card.html -- the one page you screen-record for the video.

Every number is read from the result JSONs. Nothing is typed by hand, because
in this project every hand-typed number has eventually turned out to be from a
superseded run.

    python make_card.py                 # writes results_card.html
    python make_card.py --open          # and opens it
"""
from __future__ import annotations

import argparse, json, os, statistics as st, webbrowser
from datetime import date

BUDGETS = [0.005, 0.01, 0.02, 0.03, 0.05, 0.075, 0.1, 0.15, 0.2, 0.3]
I5 = BUDGETS.index(0.05)


def load(p):
    return json.load(open(p)) if os.path.exists(p) else None


def agg(runs, fn):
    v = []
    for r in runs:
        try:
            x = fn(r)
        except (KeyError, IndexError, TypeError):
            continue
        if x is not None:
            v.append(float(x))
    if not v:
        return float("nan"), 0.0
    return st.mean(v), (st.pstdev(v) if len(v) > 1 else 0.0)


def pm(m, s, pct=False, dp=3):
    if m != m:
        return "n/a"
    if pct:
        return f"{m*100:.1f}%" + (f" <span class='sd'>&plusmn; {s*100:.1f}</span>" if s else "")
    return f"{m:.{dp}f}" + (f" <span class='sd'>&plusmn; {s:.3f}</span>" if s else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lanl", default="lanl_novelty.json")
    ap.add_argument("--shift", default="shift_results.json")
    ap.add_argument("--out", default="results_card.html")
    ap.add_argument("--open", action="store_true")
    a = ap.parse_args()

    L, S = load(a.lanl), load(a.shift)
    if not L:
        print(f"no {a.lanl} -- run train_real.py --lanl first"); return
    R = L["runs"]

    A_auc = agg(R, lambda r: r["router_auc"]["A_distilled_detector"])
    A_rec = agg(R, lambda r: r["curves"]["A_distilled_detector"][I5]["recall_teacher"])
    B_auc = agg(R, lambda r: r["router_auc"]["B_encoder_mahalanobis"])
    B_rec = agg(R, lambda r: r["curves"]["B_encoder_mahalanobis"][I5]["recall_teacher"])
    flag = agg(R, lambda r: r["flag_rate"])
    within = agg(R, lambda r: r["oracle"]["within_host_auc_mean"])
    glob = agg(R, lambda r: r["oracle"]["auc_vs_attack_window"])
    knn = agg(R, lambda r: r["geometry"]["knn_overlap@20"])
    pi, ps = R[0]["n_params"]

    cats = sorted(L["category_counts"].items(), key=lambda kv: -kv[1])
    tot = max(sum(v for _, v in cats), 1)
    catrows = "".join(
        f"<tr><td>{k}</td><td class='n'>{v:,}</td>"
        f"<td class='share'><div><span style='width:{v/tot*100:.1f}%'></span></div></td>"
        f"<td class='n'>{v/tot*100:.1f}%</td></tr>"
        for k, v in cats if v)

    sh = ""
    if S:
        ag_ = S["aggregate"]
        sh = f"""
  <section>
    <h2>4 &nbsp; Distribution shift &mdash; trained on org A, deployed cold to org B</h2>
    <div class="wrapx"><table>
      <tr><th>metric</th><th class="n">world A</th><th class="n">world B</th></tr>
      <tr><td>Inspector AUC vs attack</td>
          <td class="n">{ag_['A']['oracle_auc'][0]:.3f}</td>
          <td class="n">{ag_['B']['oracle_auc'][0]:.3f}</td></tr>
      <tr><td>Router AUC</td>
          <td class="n">{ag_['A']['router_auc'][0]:.3f}</td>
          <td class="n">{ag_['B']['router_auc'][0]:.3f}</td></tr>
      <tr class="flag"><td>Flag rate &mdash; target 1.00%</td>
          <td class="n">{ag_['A']['flag_rate'][0]*100:.2f}%</td>
          <td class="n">{ag_['B']['flag_rate'][0]*100:.2f}%</td></tr>
    </table></div>
    <p class="note">The mechanism transfers; the <strong>calibration does not</strong> &mdash; and
      it misses in world A's own later period too, so this is temporal decay, not merely a
      cross-network effect. Every deployment needs its own calibration window plus rolling
      re-calibration.</p>
  </section>"""
    html = f"""<title>Inspector&ndash;Sentry, Measured</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Newsreader:ital,opsz,wght@0,6..72,400;0,6..72,500;0,6..72,600;1,6..72,400&family=IBM+Plex+Mono:wght@400;500;600&display=swap">
<style>
  :root {{
    --paper:#f5f4f0; --panel:#fbfaf8; --ink:#1a1c1f; --dim:#6d7079;
    --rule:#ded9d0; --rule-soft:#eae6df;
    --accent:#1f5f7a; --good:#2c6a52; --bad:#9d3b28; --bad-soft:#f0e2dd;
  }}
  @media (prefers-color-scheme: dark) {{ :root:not([data-theme="light"]) {{
    --paper:#14161a; --panel:#1a1d22; --ink:#e9e7e3; --dim:#9599a3;
    --rule:#2b2f36; --rule-soft:#23262c;
    --accent:#6fb2c9; --good:#65c69b; --bad:#e08b6e; --bad-soft:#2e2320;
  }} }}
  :root[data-theme="dark"] {{
    --paper:#14161a; --panel:#1a1d22; --ink:#e9e7e3; --dim:#9599a3;
    --rule:#2b2f36; --rule-soft:#23262c;
    --accent:#6fb2c9; --good:#65c69b; --bad:#e08b6e; --bad-soft:#2e2320;
  }}
  * {{ box-sizing:border-box; }}
  body {{
    background:var(--paper); color:var(--ink); margin:0;
    padding:44px 22px 64px;
    font:400 16px/1.6 Newsreader, Georgia, "Times New Roman", serif;
    -webkit-font-smoothing:antialiased;
  }}
  .sheet {{ max-width:860px; margin:0 auto; }}
  .mono {{ font-family:"IBM Plex Mono", ui-monospace, Menlo, Consolas, monospace; }}

  header {{ border-bottom:2px solid var(--ink); padding-bottom:14px; margin-bottom:8px; }}
  h1 {{ font-size:30px; font-weight:600; line-height:1.15; margin:0 0 10px;
        letter-spacing:-.015em; text-wrap:balance; }}
  .prov {{ font-family:"IBM Plex Mono", ui-monospace, monospace; font-size:12px;
           color:var(--dim); letter-spacing:.01em; }}
  .prov b {{ color:var(--ink); font-weight:500; }}

  section {{ padding:26px 0; border-bottom:1px solid var(--rule-soft); }}
  h2 {{ font-family:"IBM Plex Mono", ui-monospace, monospace;
        font-size:11px; font-weight:600; letter-spacing:.13em; text-transform:uppercase;
        color:var(--dim); margin:0 0 20px; }}

  .figures {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
              gap:26px 34px; }}
  .fig .v {{ font-family:"IBM Plex Mono", ui-monospace, monospace;
             font-size:33px; font-weight:500; letter-spacing:-.03em;
             font-variant-numeric:tabular-nums; line-height:1.05; }}
  .fig .v.good {{ color:var(--good); }}
  .fig .v.bad {{ color:var(--bad); }}
  .sd {{ font-size:.5em; color:var(--dim); font-weight:400; letter-spacing:0; }}
  .fig .k {{ font-size:14.5px; color:var(--dim); margin-top:7px; line-height:1.45; }}
  .fig .k em {{ font-style:italic; }}

  p {{ margin:16px 0 0; max-width:64ch; }}
  .note {{ font-size:15px; color:var(--dim); }}
  .note strong, .note b {{ color:var(--ink); font-weight:600; }}

  /* The one lifted element on the page: the finding that argues against us. */
  .finding {{
    background:var(--bad-soft); border-left:3px solid var(--bad);
    padding:18px 22px; margin-top:22px; max-width:none;
    font-size:15.5px;
  }}
  .finding b {{ color:var(--bad); font-weight:600; }}

  .wrapx {{ overflow-x:auto; margin-top:4px; }}
  table {{ border-collapse:collapse; width:100%;
           font-family:"IBM Plex Mono", ui-monospace, monospace; font-size:13px; }}
  th {{ text-align:left; font-weight:600; font-size:10.5px; letter-spacing:.1em;
        text-transform:uppercase; color:var(--dim); padding:0 14px 9px 0;
        border-bottom:1px solid var(--rule); white-space:nowrap; }}
  td {{ padding:8px 14px 8px 0; border-bottom:1px solid var(--rule-soft);
        font-variant-numeric:tabular-nums; }}
  td.n {{ text-align:right; white-space:nowrap; }}
  td.share {{ width:34%; padding-right:14px; }}
  td.share div {{ background:var(--rule-soft); height:6px; }}
  td.share span {{ display:block; height:6px; background:var(--accent); opacity:.85; }}
  tr.flag td {{ color:var(--bad); }}
  tr:last-child td {{ border-bottom:none; }}

  .claim {{ border:1px solid var(--rule); border-left:3px solid var(--good);
            background:var(--panel); padding:22px 24px; margin-top:26px; }}
  .claim h3 {{ font-family:"IBM Plex Mono", ui-monospace, monospace; font-size:11px;
               letter-spacing:.13em; text-transform:uppercase; color:var(--good);
               margin:0 0 12px; font-weight:600; }}
  .claim p {{ margin:0; font-size:16px; }}
  .claim b {{ font-weight:600; }}

  footer {{ font-family:"IBM Plex Mono", ui-monospace, monospace; font-size:11.5px;
            color:var(--dim); margin-top:26px; line-height:1.7; }}
  @media (max-width:560px) {{
    body {{ padding:30px 16px 48px; }}
    h1 {{ font-size:25px; }}
    .fig .v {{ font-size:28px; }}
  }}
</style>
<div class="sheet">
  <header>
    <h1>Inspector&ndash;Sentry, measured against a real red team</h1>
    <div class="prov mono">LANL <b>cyber1</b> &nbsp;&middot;&nbsp; {L['hosts']} hosts
      &nbsp;&middot;&nbsp; {L['days']} days &nbsp;&middot;&nbsp; {L['seeds']} seeds
      &nbsp;&middot;&nbsp; n={L['n_attack_windows']} attack windows / {L['n_live_windows']:,} live
      &nbsp;&middot;&nbsp; {date.today().isoformat()}</div>
  </header>

  <section>
    <h2>1 &nbsp; The cascade &mdash; what holds</h2>
    <div class="figures">
      <div class="fig"><div class="v good">{pm(*A_rec, pct=True)}</div>
        <div class="k">of the Inspector's flags recovered at a 5% escalation budget</div></div>
      <div class="fig"><div class="v good">{pm(*A_auc)}</div>
        <div class="k">router A agreement with the Inspector <em>(AUC)</em></div></div>
      <div class="fig"><div class="v">{pi/ps:.1f}&times;</div>
        <div class="k">smaller &mdash; {pi:,} &rarr; {ps:,} parameters, CPU only</div></div>
    </div>
    <p class="note">Router B (encoder + Mahalanobis) reaches {B_auc[0]:.3f} AUC and
      {B_rec[0]*100:.1f}% recall on the same data. The distilled detector wins decisively,
      reversing the recommendation made on synthetic data. kNN geometry overlap {knn[0]:.3f}.</p>
  </section>

  <section>
    <h2>2 &nbsp; Detection &mdash; what does not</h2>
    <div class="figures">
      <div class="fig"><div class="v">{pm(*glob)}</div>
        <div class="k">global AUC vs the red team <em>&mdash; confounded</em></div></div>
      <div class="fig"><div class="v bad">{pm(*within)}</div>
        <div class="k">within-host AUC &mdash; each host scored against itself</div></div>
      <div class="fig"><div class="v">{L['live_density_attacked']:.2f} <span class="sd">vs</span> {L['live_density_other']:.2f}</div>
        <div class="k">activity density: attacked hosts vs everyone else</div></div>
    </div>
    <p class="finding">The global figure is a <b>between-host effect</b>. Red-team targets are the
      busiest machines, so the model ranks <em>which</em> host is unusual, not <em>when</em> it was
      attacked. Remove that axis and the signal is <b>chance</b>. We built this check ourselves,
      ran it, and it argues against us &mdash; across {L['seeds']} seeds, so it is a measurement,
      not noise.</p>
  </section>

  <section>
    <h2>3 &nbsp; Internal asset taxonomy &mdash; what the resolver produced</h2>
    <div class="wrapx"><table>
      <tr><th>asset class</th><th class="n">edges</th><th></th><th class="n">share</th></tr>
      {catrows}
    </table></div>
    <p class="note">Nine of nine classes in use, largest {cats[0][1]/tot*100:.0f}% &mdash; a real
      split, not a collapse. Inspector flag rate on test {pm(*flag, pct=True)} against a 1.0%
      target, which is the calibration problem below.</p>
  </section>
{sh}
  <div class="claim">
    <h3>The claim we can defend</h3>
    <p>On {L['days']} days of real enterprise traffic the Sentry recovers
      <b>{A_rec[0]*100:.1f}% of everything the Inspector would flag</b>, at {pi/ps:.1f}&times;
      fewer parameters on CPU. Against the real red team the Inspector is
      <b>at chance within-host ({within[0]:.3f})</b> &mdash; the cascade faithfully compresses a
      teacher that does not separate credential-based lateral movement, and we say so. The
      {A_rec[0]*100:.1f}% is <b>agreement with the teacher</b>: an efficiency number, never a
      detection rate.</p>
  </div>

  <footer>
    Generated by <span>make_card.py</span> from {a.lanl}{' and ' + a.shift if S else ''}.<br>
    Regenerate rather than edit &mdash; every hand-typed number in this project has at some point
    come from a superseded run.
  </footer>
</div>
"""
    open(a.out, "w", encoding="utf-8").write(html)
    print(f"wrote {a.out}")
    if a.open:
        webbrowser.open("file://" + os.path.abspath(a.out))


if __name__ == "__main__":
    main()
