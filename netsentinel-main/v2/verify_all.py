#!/usr/bin/env python3
"""
verify_all.py -- one command that re-checks the whole project.

Run this before any submission, any deck rebuild, any claim. It FAILS LOUDLY
rather than printing a reassuring summary:

  1. TESTS      runs every test suite and checks the EXIT CODE, not the text.
                (A grep for "all N checks passed" silently missed four passing
                suites earlier because prose followed the summary line.)
  2. NUMBERS    re-derives every headline figure from its source .json.
                Figures that legitimately move between runs -- wall-clock
                throughput on a shared container -- are checked as
                RELATIONSHIPS, not equalities, and printed for the reader.
  3. CLAIMS     greps every .md for wording that measurement has retired, and
                lists every hit it chose to allow, because a silent allowance
                is how a real violation gets through. Two negative controls
                prove the scan still catches a claim stated plainly.
  4. HYGIENE    checks the audit findings stayed fixed.
  5. CODE       every .py parses, every module imports, every .json a document
                cites exists on disk.

Exit code 0 only if everything passes.
"""
from __future__ import annotations

import glob, json, os, re, subprocess, sys
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
FAIL = []


def head(t):
    print("\n" + "=" * 70); print(f"  {t}"); print("=" * 70)


def ok(name, cond, detail=""):
    print(("  ok    " if cond else "  FAIL  ") + name + ("" if cond else f"   {detail}"))
    if not cond:
        FAIL.append(name)


# ------------------------------------------------------------------ 1. tests
head("1. TEST SUITES  (exit code, not text)")
for t in sorted(glob.glob("test_*.py")):
    r = subprocess.run([sys.executable, t], capture_output=True, timeout=1800)
    ok(f"{t}", r.returncode == 0, f"exit={r.returncode}")


# ---------------------------------------------------------------- 2. numbers
head("2. NUMBERS  (documents vs source .json)")
# Every file the checks below key on. Named explicitly, because each check is
# written as `if "x.json" in J:` -- so a deleted or corrupt file would make its
# checks SILENTLY DISAPPEAR and this script would still print ALL CLEAR with a
# smaller number in the summary. A checker that gets quieter as evidence goes
# missing is worse than no checker.
REQUIRED = [
    "lanl_novelty.json", "lanl_novelty_hn.json", "lanl_p0b.json",
    "paired_synth.json", "escalate.json", "ablation_order_hard.json",
    "bench_beacon.json", "sweep_threshold.json", "results_8seed.json",
    "ci_report.json", "telegram_c2.json",
]
J = {}
broken = []
for f in glob.glob("*.json"):
    try:
        J[f] = json.load(open(f))
    except Exception as e:
        broken.append(f"{f} ({type(e).__name__})")
ok("every evidence file this script needs is present",
   not [f for f in REQUIRED if f not in J],
   f"missing or unreadable: {[f for f in REQUIRED if f not in J]}")
ok("no .json in this directory is unparseable", not broken, f"{broken}")


def mean_runs(d, fn):
    return float(np.mean([fn(r) for r in d["runs"]]))


CHECKS = []
SHAPE = []          # relationships that must hold; values that legitimately move
if "lanl_novelty.json" in J:
    d = J["lanl_novelty.json"]
    CHECKS += [
        ("router A agreement 0.992", mean_runs(d, lambda r: r["router_auc"]["A_distilled_detector"]), 0.992, 0.0015),
        ("router B 0.634", mean_runs(d, lambda r: r["router_auc"]["B_encoder_mahalanobis"]), 0.634, 0.0015),
        ("pooled AUC 0.745", mean_runs(d, lambda r: r["oracle"]["auc_vs_attack_window"]), 0.745, 0.0015),
        ("within-host 0.557", mean_runs(d, lambda r: r["oracle"]["within_host_auc_mean"]), 0.557, 0.0015),
        ("density attacked 0.811", d["live_density_attacked"], 0.811, 0.001),
        ("density other 0.530", d["live_density_other"], 0.530, 0.001),
    ]
    # The two most-quoted figures in the project, and until now neither was
    # checked here. They are LANL, i.e. real data, and therefore untouched by
    # the synthetic-generator defect in AUDIT B7 -- which is exactly why it is
    # worth pinning them: if they ever move, something serious has changed.
    at5 = lambda lbl, key: float(np.mean([
        [b for b in r["curves"][lbl] if abs(b["budget"] - 0.05) < 1e-9][0][key]
        for r in d["runs"]]))
    CHECKS += [
        ("96.9% of the Inspector's flags recovered at a 5% budget",
         at5("A_distilled_detector", "recall_teacher"), 0.969, 0.0015),
        ("35.6% attack recall at the same budget",
         at5("A_distilled_detector", "recall_attack"), 0.356, 0.0015),
    ]
if "lanl_novelty_hn.json" in J:
    d = J["lanl_novelty_hn.json"]
    CHECKS += [("host-norm pooled 0.618", mean_runs(d, lambda r: r["oracle"]["auc_vs_attack_window"]), 0.618, 0.002)]
if "lanl_p0b.json" in J:
    d = J["lanl_p0b.json"]
    CHECKS += [("p0b sign test 0.731", d["paired"]["sign_test_p"], 0.731, 0.002),
               ("bag within-host 0.578", d["bag_within_host_auc_mean"], 0.578, 0.002)]
if "paired_synth.json" in J:
    d = J["paired_synth.json"]
    CHECKS += [("synth paired p 0.51", d["pooled_sign_test_p"], 0.512, 0.005),
               ("synth mean paired diff +0.026", d["mean_paired_diff"], 0.0255, 0.001)]
    if "median_paired_diff" in d:
        CHECKS += [("synth median paired diff -0.006", d["median_paired_diff"], -0.0057, 0.001)]
    SHAPE += [("synth: mean favours the Inspector, median does not",
               d["mean_paired_diff"] > 0 > d.get("median_paired_diff", -1),
               "wins large on a minority, loses small on the majority -- "
               "the whole finding, and it needs both statistics")]
if "escalate.json" in J:
    d = J["escalate.json"]
    # NOT an equality check. Two runs of escalate.py on this same container
    # returned 70,950 and 104,385 Inspector windows/s -- best-of-3 does not
    # remove contention when the cores are busy. Asserting a throughput to the
    # unit would fail for a reason that has nothing to do with the code, and
    # would train whoever sees it to ignore this file. Assert the ORDERING,
    # which is the actual claim, and print the numbers for the reader.
    CHECKS += [("scatter ~49% of host-days",
                d["host_days_inspected"] / d["host_days_total"], 0.487, 0.02),
               ("confirmation precision ~12.7%", d["confirm_precision"], 0.127, 0.01)]
    SHAPE += [("cohort is the cheapest stage",
               d["cohort_win_per_s"] > d["sentry_win_per_s"] > d["inspector_win_per_s"],
               f"cohort {d['cohort_win_per_s']:,.0f} > sentry {d['sentry_win_per_s']:,.0f}"
               f" > inspector {d['inspector_win_per_s']:,.0f} win/s"),
              ("Sentry:Inspector ratio in 5-12x",
               5.0 <= d["sentry_speedup"] <= 12.0,
               f"{d['sentry_speedup']:.2f}x this run"),
              ("cascade costs less than full inspection",
               d["cascade_seconds"] < d["full_inspect_seconds"],
               f"{d['cascade_seconds']:.3f}s < {d['full_inspect_seconds']:.3f}s")]
if "ablation_order_hard.json" in J:
    m = J["ablation_order_hard.json"]["mean_std"]
    CHECKS += [("order A 0.998", m["A_full"][0], 0.998, 0.0015),
               ("order B 0.998 (blind)", m["B_shuffled_at_score"][0], 0.998, 0.0015),
               ("order-free D 1.000", m["D_bag_of_categories"][0], 1.000, 0.0015),
               ("diode cost F 0.996", m["F_no_reverse_direction"][0], 0.996, 0.0015)]
if "bench_beacon.json" in J:
    d = J["bench_beacon.json"]
    by = d["by_shape"]
    avg = lambda f: float(np.mean([by[k]["aucs"][f]["auc"] for k in by]))
    CHECKS += [("beacon iat_cv 0.878", avg("iat_cv"), 0.878, 0.002),
               ("beacon fft_prominence 0.623", avg("fft_prominence"), 0.623, 0.002)]
if "sweep_threshold.json" in J:
    d = J["sweep_threshold.json"]
    rows = d["sweep"]
    best = d["best_f1"]
    lo = [r for r in rows if r["sigma"] <= best["sigma"]]
    SHAPE += [("threshold sweep: precision rises with sigma",
               all(b["precision"] >= a["precision"] - 1e-9 for a, b in zip(lo, lo[1:])),
               "precision must be monotone up to the best-F1 cut"),
              ("threshold sweep: the current 3.0 cut is too loose",
               best["sigma"] > 3.0,
               f"best F1 at {best['sigma']:.1f} sigma, not 3.0"),
              ("threshold sweep: tightening buys more precision than it costs recall",
               (best["precision"] - d["current_3sigma"]["precision"]) >
               (d["current_3sigma"]["recall"] - best["recall"]),
               f"3.0->{best['sigma']:.1f} sigma: precision "
               f"{d['current_3sigma']['precision']:.1%}->{best['precision']:.1%}, "
               f"recall {d['current_3sigma']['recall']:.1%}->{best['recall']:.1%}, "
               f"alerts/1k {d['current_3sigma']['alerts_per_1k_host_days']:.0f}->"
               f"{best['alerts_per_1k_host_days']:.0f}"),
              ("threshold sweep records its difficulty",
               "stealth" in d and "hard_negatives" in d,
               "a precision number without its stealth setting is not comparable"),
              ("threshold sweep tests itself against random routing",
               "vs_random" in d and "p_value" in d["vs_random"],
               "recall at a budget means nothing without the random baseline")]

if "results_8seed.json" in J:
    d = J["results_8seed.json"]
    lab = ("A_distilled_detector", "B_encoder_mahalanobis", "C_deferral_head")
    V = {k: np.array([r["router_auc_vs_teacher"][k] for r in d["runs"]]) for k in lab}
    CHECKS += [("router A synthetic 0.833 (8 seeds)", float(V[lab[0]].mean()), 0.833, 0.002),
               ("router B synthetic 0.804 (8 seeds)", float(V[lab[1]].mean()), 0.804, 0.002),
               ("router C synthetic 0.839 (8 seeds)", float(V[lab[2]].mean()), 0.839, 0.002)]
    from scipy import stats as _st
    spread = float(V[lab[0]].max() - V[lab[0]].min())
    SHAPE += [("8 seeds recorded, and the config with them",
               len(d["runs"]) == 8 and "config" in d,
               f"{len(d['runs'])} seeds, config {d.get('config', {}).get('hard_negatives')}"),
              ("no pair of routers is separable on synthetic data",
               all(_st.wilcoxon(V[a], V[b]).pvalue > 0.05
                   for a, b in ((lab[0], lab[1]), (lab[0], lab[2]), (lab[1], lab[2]))),
               "if this ever fails, a real ranking exists and the docs must say so"),
              ("router A's own seed spread swamps the gaps between routers",
               spread > abs(V[lab[0]].mean() - V[lab[2]].mean()),
               f"A spans {spread:.3f} across seeds vs an A-C gap of "
               f"{abs(V[lab[0]].mean() - V[lab[2]].mean()):.3f}")]

if "telegram_c2.json" in J:
    d = J["telegram_c2.json"]
    fr, lad = d["frontier"], d["ladder"]
    days = [r["days_to_detect"] for r in fr["curve"]]
    caught = [r for r in fr["curve"] if not r["lost_in_noise"]]
    lost = [r for r in fr["curve"] if r["lost_in_noise"]]
    auc0 = lad["rungs"][0]["per_window_auc_best"]
    aucN = lad["rungs"][-1]["per_window_auc_best"]
    SHAPE += [
        ("telegram bound: detection delay falls as footprint rises",
         all(a > b for a, b in zip(days, days[1:])),
         "the conservation law -- smaller footprint, longer delay"),
        ("telegram bound: an operational floor exists and is finite",
         fr["floor_kb_per_day"] is not None and len(lost) >= 1,
         f"floor {fr['floor_kb_per_day']} KB/day; below it the true alarm "
         f"is no faster than a false one"),
        ("telegram bound: every caught footprint beats a false alarm",
         all(c["days_to_detect"] < fr["arl0_measured_days"] for c in caught),
         "caught = detected before the false-alarm interval"),
        ("telegram ladder: per-window detection collapses under mimicry",
         auc0 > 0.95 and aucN < 0.75,
         f"per-window AUC {auc0:.2f} (commodity) -> {aucN:.2f} (full mimicry) "
         f"-- the honest 'we do NOT catch it in a window'"),
        ("telegram claim is stated as a bound, not a detection",
         "bounded not solved" in d.get("claim", ""),
         "the json must carry the honest framing, not a detection boast"),
    ]

if "ci_report.json" in J:
    d = J["ci_report.json"]
    SHAPE += [("error bars are documented as population sd, not a CI",
               d["sd_convention"].startswith("population"), d["sd_convention"]),
              ("a 95% interval is wider than the printed +/-",
               d["ci95_multiplier_on_sample_sd"] > 2.0,
               f"{d['ci95_multiplier_on_sample_sd']:.2f}x the sample sd at n="
               f"{d['n_seeds']}")]

for name, got, want, tol in CHECKS:
    ok(name, abs(got - want) <= tol, f"json={got:.4f} doc={want}")
for name, cond, detail in SHAPE:
    ok(name, cond, detail)
    if cond and detail:
        print(f"           {detail}")


# ----------------------------------------------------------------- 3. claims
head("3. RETIRED CLAIMS  (must not appear in any .md as a live claim)")

# A retired claim legitimately appears in three places: a "never say" list, a
# correction, and a retraction notice. Suppressing those SILENTLY is how a real
# violation slips through, so every suppressed hit is printed below the result.
# The allowance is granted on the hit's own neighbourhood PLUS the label of the
# section it sits under -- prohibition lists are always under a heading, a bold
# line, or a table header that says what the list is for.
BANNED = [
    (r"we detect the sequence", "withdrawn by the order ablation (A-B = 0.000)"),
    (r"94\.7\s*%\s*(GPU )?reduction", "withdrawn -- wrong budget granularity"),
    (r"13\.7\s*[x\u00d7]\s*(faster|speed)", "13.7 is a parameter ratio, not a speed"),
    (r"55\s*%\s*of DNS", "retracted -- no denominator for hidden queries"),
    (r"95%\s*recall", "never claimed; 96.9% is teacher-flag recovery"),
    (r"low `?ks_uniform`? plus low `?fft_prominence`?", "fft_prominence measures 0.623, near chance"),
]
MARKERS = re.compile(
    # Deliberately NARROW. Generic words like "wrong" or "false" appear near
    # plenty of live prose, and a marker that broad excuses real violations --
    # the negative control below fails the moment one creeps back in.
    r"never|must not|withdraw|retract|prohibit|do not|don't|supersed|refut|"
    r"not met|aspirational|unsupported|no longer|was once proposed|"
    r"things to avoid|avoid saying|things not to|corrected|must change|"
    r"\bnot\b\s+(to\s+)?(say|show|claim|quote|use|put)|"
    r"\bnot\b.{0,20}\b(true|supported|measured|tested)\b",
    re.I)


def _section_label(lines, i):
    """Walk up to the nearest heading, bold-only line, or table header.

    A prohibition table's rows carry no marker of their own -- the word
    'must not be said' is in the header two dozen rows above. Without this,
    AUDIT.md's entire 'never say' table reads as a set of live claims.
    """
    out = []
    in_table = lines[i].lstrip().startswith("|")
    for j in range(i - 1, max(-1, i - 40), -1):
        ln = lines[j]
        if in_table and not ln.lstrip().startswith("|") and ln.strip():
            in_table = False
            out.append(ln)          # the line introducing the table
        if ln.lstrip().startswith("#"):
            out.append(ln)
            break
        if re.fullmatch(r"\s*\*\*[^*]+\*\*[:\s]*", ln):
            out.append(ln)
            break
    if in_table:                    # header row of the table itself
        for j in range(i - 1, max(-1, i - 40), -1):
            if not lines[j].lstrip().startswith("|"):
                out.append(lines[j + 1] if j + 1 < len(lines) else "")
                break
    return " ".join(out)


def scan(paths, texts=None):
    """-> {pattern: (live_hits, suppressed_hits)}. `texts` lets the self-test
    below feed strings instead of files."""
    out = {}
    for pat, _why in BANNED:
        live, allow = [], []
        for f in paths:
            txt = texts[f] if texts else open(f, encoding="utf-8", errors="replace").read()
            lines = txt.split("\n")
            for m in re.finditer(pat, txt, re.I):
                i = txt[:m.start()].count("\n")
                ctx = " ".join(lines[max(0, i - 2):i + 3]) + " " + _section_label(lines, i)
                (allow if MARKERS.search(ctx) else live).append(f"{f}:{i + 1}")
        out[pat] = (live, allow)
    return out


# NEGATIVE CONTROL. A permissive allowance is worse than no check at all,
# because it reports "all clear" over a real violation. So before trusting the
# scan, prove it still catches a claim stated plainly, and that a bare denial
# word nearby is not enough to excuse one.
_probe = {
    "LIVE.md": "# Results\n\nNetSentinel reaches 95% recall at a 5% budget.\n",
    "SNEAKY.md": ("# Notes\n\nThere is nothing wrong with the pipeline.\n"
                  "The cascade delivers a 94.7% reduction in GPU spend.\n"),
}
_p = scan(list(_probe), _probe)
_k1, _k2 = BANNED[4][0], BANNED[1][0]
_g1, _g2 = _p[_k1][0], _p[_k2][0]
ok("scanner still catches a plain live claim",
   _g1 == ["LIVE.md:3"], f"got {_g1}")
ok("scanner not fooled by an unrelated 'wrong' two lines up",
   _g2 == ["SNEAKY.md:4"], f"got {_g2}")

mds = sorted(f for f in glob.glob("*.md") if f != "ERASER_PROMPTS.md")
res = scan(mds)
allowed_total = []
for pat, why in BANNED:
    live, allow = res[pat]
    allowed_total += allow
    ok(f"'{pat[:34]}' not stated live", not live, f"{why} -- LIVE at {live[:4]}")
    if allow:
        print(f"           ({len(allow)} in retraction/prohibition context: "
              f"{', '.join(allow[:6])}{' ...' if len(allow) > 6 else ''})")
print(f"\n  {len(allowed_total)} suppressed hits listed above, across {len(mds)} "
      f"files -- if one of\n  those lines is actually making the claim, the "
      f"suppression is the bug.")


# ---------------------------------------------------------------- 4. hygiene
head("4. AUDIT FINDINGS  (must stay fixed)")
cp = J.get("capture_probe.json", {})
ok("F2 browsing hostnames not persisted",
   "top_named" not in cp, "capture_probe.json carries top_named again")
req = open("requirements.txt", encoding="utf-8").read()
ok("F5 cryptography version-pinned", re.search(r"cryptography\s*[><=]=", req))
zl = open("netsentinel_v2/zeek_loader.py", encoding="utf-8").read()
ok("IPv6 private-address test present",
   "_PRIVATE_V6" in zl and "class _PrivateMatcher" in zl)
p2t = open("pcap_to_tensor.py", encoding="utf-8").read()
ok("pcap IATs are session-level, not packet-level",
   "_session_starts" in p2t and "SESSION_IDLE_GAP" in p2t)
ok("nanosecond timestamps honoured (if_tsresol read)",
   "if_tsresol" in p2t and "code == 9" in p2t)
sy = open("netsentinel_v2/synth.py", encoding="utf-8").read()
ok("beacon generator documents its circularity",
   "CIRCULARITY" in sy.upper() and 'shape="uniform"' in sy)
tc = open("telegram_c2.py", encoding="utf-8").read()
ok("telegram_c2 states 'bounded not solved', not a detection claim",
   "bounded rather" in tc and "DO NOT CLAIM WE DETECT IT IN A WINDOW" in tc)
ok("telegram_c2 calibrates on the real lognormal stream, not Siegmund",
   "arl_mc" in tc and "Production uses arl_mc" in tc)
cats = open("netsentinel_v2/categories.py", encoding="utf-8").read()
ok("ROLE_PREPATH is ordered (no hash-order RNG drift)",
   "ROLE_PREPATH" in cats and not re.search(
       r"ROLE_PREPATH\s*=\s*\{[^}]*:\s*\{", cats, re.S),
   "a set here makes synth.generate(seed=n) differ per process")
ok("determinism test exists and runs in section 1",
   os.path.exists("test_determinism.py"))
for f in ("run_experiment.py", "shift_test.py"):
    ok(f"{f} records its config in the output",
       "config=vars(a)" in open(f, encoding="utf-8").read(),
       "a results file that cannot say which flags produced it is not evidence")

# ------------------------------------------------------------ 5. code health
head("5. CODE HEALTH  (every file parses, every module imports)")
import ast as _ast, importlib, pkgutil

pyfiles = sorted(glob.glob("*.py") + glob.glob("netsentinel_v2/*.py"))
syn = []
for f in pyfiles:
    try:
        _ast.parse(open(f, encoding="utf-8").read())
    except SyntaxError as e:
        syn.append(f"{f}:{e.lineno}")
ok(f"all {len(pyfiles)} .py files parse", not syn, f"broken: {syn}")

import netsentinel_v2
bad = []
for m in pkgutil.iter_modules(netsentinel_v2.__path__):
    try:
        importlib.import_module("netsentinel_v2." + m.name)
    except Exception as e:
        bad.append(f"{m.name} ({type(e).__name__})")
ok("every netsentinel_v2 module imports", not bad, f"failed: {bad}")

# Every .json a document quotes should exist; a doc citing a file that was
# never produced is the easiest way to end up quoting a remembered number.
# Absent on purpose, each with a reason. Anything absent and NOT listed here
# is a document quoting a file that was never produced -- the easiest way to
# end up publishing a remembered number.
EXPECTED_ABSENT = {
    "capture_probe.json": "sensor output; gitignored, lives only on the capture host",
    "lanl_results.json":  "a filename in an example command in DATASETS.md, not an artefact",
    "lanl_src.json":      "stale, deleted on purpose (POST_8SEP.md)",
    "lanl_dst.json":      "stale, deleted on purpose (POST_8SEP.md)",
    "lanl_both.json":     "stale, deleted on purpose (POST_8SEP.md)",
}
cited = set()
for f in mds:
    cited |= set(re.findall(r"`([A-Za-z0-9_]+\.json)`",
                            open(f, encoding="utf-8", errors="replace").read()))
missing = sorted(c for c in cited if not os.path.exists(c))
unexplained = [c for c in missing if c not in EXPECTED_ABSENT]
ok(f"every .json cited by a document exists or is explained ({len(cited)} cited)",
   not unexplained, f"unexplained: {unexplained}")
for c in missing:
    print(f"           absent by design: {c} -- {EXPECTED_ABSENT.get(c, '??')}")
stale = [c for c in EXPECTED_ABSENT if os.path.exists(c) and "stale" in EXPECTED_ABSENT[c]]
ok("no file marked stale has reappeared", not stale, f"{stale} exist again")


# A count that can only go up. If a future edit deletes checks -- or a missing
# evidence file removes a whole block -- this fails rather than reporting a
# smaller, cheerful total.
MIN_CHECKS, MIN_SHAPE = 25, 14
ok(f"at least {MIN_CHECKS} numeric checks ran", len(CHECKS) >= MIN_CHECKS,
   f"only {len(CHECKS)} -- checks have been lost, raise the floor deliberately "
   f"or find what went missing")
ok(f"at least {MIN_SHAPE} relationship checks ran", len(SHAPE) >= MIN_SHAPE,
   f"only {len(SHAPE)}")

print()
print("=" * 70)
if FAIL:
    print(f"  {len(FAIL)} CHECK(S) FAILED")
    for f in FAIL:
        print("   -", f)
    sys.exit(1)
print(f"  ALL CLEAR -- {len(glob.glob('test_*.py'))} suites passed, "
      f"{len(CHECKS)} numbers re-derived from source .json,\n"
      f"  {len(SHAPE)} relationships checked, {len(allowed_total)} retired-claim "
      f"mentions reviewed,\n  0 stated live.")
print("  This does not mean the project is right. It means the documents and "
      "the\n  .json files agree, and nothing that was withdrawn has come back.")
sys.exit(0)
