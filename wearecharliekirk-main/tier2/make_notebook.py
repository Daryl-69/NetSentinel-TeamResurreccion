#!/usr/bin/env python3
"""Generate the Kaggle notebook from the real source files, so it never drifts.

    python make_notebook.py            -> netsentinel_v2_kaggle.ipynb
"""
import json, os

MODULES = ["categories", "synth", "models", "baseline", "diagnostics",
           "train", "cost_model", "zeek_loader"]
SCRIPTS = ["run_experiment.py", "shift_test.py", "make_charts.py"]


def md(*lines):
    return {"cell_type": "markdown", "metadata": {}, "source": "\n".join(lines)}


def code(*lines):
    return {"cell_type": "code", "metadata": {}, "execution_count": None,
            "outputs": [], "source": "\n".join(lines)}


def writefile(path, body):
    return code(f"%%writefile {path}", body.rstrip("\n"))


cells = [
md("# NetSentinel V2 — Inspector–Sentry harness",
   "",
   "Trains the **Inspector** (E-GraphSAGE + Transformer denoising autoencoder), distils a",
   "**Sentry** ~14× smaller, and races three routers at equal escalation budget. Then runs the",
   "**distribution-shift stress test** and, optionally, loads **real Zeek traffic**.",
   "",
   "---",
   "### Read this before you turn on a GPU",
   "",
   "**You almost certainly don't need one.** The default run is ~2 min/seed on CPU. A GPU helps",
   "only once you scale up (`--hosts 2000`, bigger encoder, real capture). Turn it on when the",
   "cell timings tell you to, not before — Kaggle's 30 GPU-hours/week are worth saving.",
   "",
   "### Kaggle settings you do need",
   "",
   "| Setting | Value | Why |",
   "|---|---|---|",
   "| Accelerator | **None** (CPU) to start | the harness is CPU-bound and small |",
   "| Internet | **On** | only for the real-data section (needs phone verification) |",
   "| Persistence | Variables & files | keeps `results.json` between sessions |",
   "",
   "### Honest scope",
   "",
   "The generator is a **stand-in, not a dataset**. Router-vs-Inspector agreement is meaningful",
   "(the Inspector is the reference oracle); **attack-recall numbers are indicative only** until",
   "real capture replaces it. See `DATASETS.md`."),

code("import sys, platform, os, time",
     "import numpy as np",
     "try:",
     "    import torch",
     "    print('torch', torch.__version__, '| CUDA', torch.cuda.is_available())",
     "    if torch.cuda.is_available():",
     "        print('   ', torch.cuda.get_device_name(0))",
     "except ImportError:",
     "    print('installing torch...'); os.system('pip -q install torch')",
     "print('python', platform.python_version(), '| cpus', os.cpu_count())",
     "os.makedirs('/kaggle/working/netsentinel_v2', exist_ok=True)",
     "os.chdir('/kaggle/working')",
     "print('cwd', os.getcwd())"),

md("## 1 · Write the package",
  "",
  "Self-contained on purpose — no upload step, no GitHub dependency. Re-run these cells after",
  "editing anything."),
]

here = os.path.dirname(os.path.abspath(__file__))
for m in MODULES:
    src = open(os.path.join(here, "netsentinel_v2", f"{m}.py"), encoding="utf-8").read()
    cells.append(writefile(f"netsentinel_v2/{m}.py", src))
cells.append(writefile("netsentinel_v2/__init__.py", ""))
for s in SCRIPTS:
    src = open(os.path.join(here, s), encoding="utf-8").read()
    cells.append(writefile(s, src))

cells += [
md("## 2 · Smoke test (~30 s)",
   "Small and fast. Confirms the whole path runs before you spend real time."),
code("!python run_experiment.py --seeds 1 --hosts 60 --days 16 "
     "--epochs-teacher 3 --epochs-student 3 --out smoke.json"),

md("## 3 · The main experiment",
   "",
   "3 seeds, 300 hosts, 24 days. ~2 min/seed on CPU.",
   "",
   "Protocol enforced in code: strictly monotonic **train → validate → test in time** (no random",
   "splits), thresholds calibrated on **validation only**, multi-seed ± σ, rank-based budget",
   "selection so score ties can't fake 100% recall."),
code("!python run_experiment.py --seeds 3 --hosts 300 --days 24 "
     "--epochs-teacher 12 --epochs-student 14 --out results.json"),

md("### The chart"),
code("!pip -q install matplotlib >/dev/null 2>&1",
     "!python make_charts.py results.json",
     "from IPython.display import Image, display",
     "display(Image('chart_escalation_budget.png'))",
     "display(Image('chart_geometry_diagnostic.png'))"),

md("## 4 · Distribution-shift stress test",
   "",
   "The question a judge will ask: *your model learned normal from your own generator — what",
   "happens on a network it has never seen?*",
   "",
   "**World A** (dev-heavy software org) trains the encoder. **World B** (OT/plant-heavy: different",
   "role mix, slower human rhythms, lower volumes, longer working day) is deployed to cold —",
   "baselines re-fit on B's own commissioning window, but **A's threshold and A's standardiser",
   "applied unchanged**, because that is the mistake a real deployment makes.",
   "",
   "Watch the **flag rate** row. If A's 99th-percentile threshold doesn't produce ~1% in B,",
   "calibration does not transfer and every deployment needs its own calibration window."),
code("!python shift_test.py --seeds 3 --hosts 300 --days 24 "
     "--epochs-teacher 12 --epochs-student 14 --out shift_results.json"),

md("## 5 · Real traffic (optional — needs Internet ON)",
   "",
   "Everything above is synthetic. This section swaps in **real benign capture** so the encoder",
   "learns what traffic actually looks like.",
   "",
   "Sources and their limits are in `DATASETS.md`. Short version: Stratosphere Normal Captures are",
   "real human/host activity in Zeek format, free — good for **encoder pretraining**, useless for",
   "multi-day per-host baselines (the captures are only hours long). For baselines you need your",
   "own machines recording for weeks."),
code("# Stratosphere Normal Captures — real benign, Bro/Zeek format.",
     "# Browse https://www.stratosphereips.org/datasets-normal for the full list.",
     "BASE = 'https://mcfp.felk.cvut.cz/publicDatasets'",
     "CAPTURES = ['CTU-Normal-7', 'CTU-Normal-12']   # add more once one works",
     "",
     "import os, subprocess",
     "os.makedirs('data', exist_ok=True)",
     "for c in CAPTURES:",
     "    print('---', c)",
     "    # -A '*.log*' grabs the Zeek/Bro logs and skips the large pcaps",
     "    subprocess.run(['wget','-q','-r','-np','-nH','--cut-dirs=1','-R','index.html*',",
     "                    '-A','*.log,*.log.gz,*.labeled',",
     "                    f'{BASE}/{c}/','-P','data'], check=False)",
     "!find data -name '*.log*' | head -30"),

code("# Point this at whichever directory actually contains conn.log",
     "import glob, os",
     "cands = [os.path.dirname(p) for p in glob.glob('data/**/conn.log*', recursive=True)]",
     "print('found conn.log in:', cands)",
     "",
     "from netsentinel_v2 import zeek_loader as zl",
     "if cands:",
     "    real = zl.load_dir(cands[0], min_windows_per_host=1)",
     "    print(zl.summarise(real))",
     "else:",
     "    print('No conn.log found. Either Internet is off, or this capture ships pcap only —',",
     "          'run `zeek -r <file>.pcap` on it first, or pick another capture.')"),

md("### Train the encoder on the real capture",
   "",
   "Same models, different data source — that's the whole point of the loader. Note there are no",
   "attack labels here and none are needed: the Inspector is an anomaly model that learns normal.",
   "What you get out is a **representation**; the per-host baselines still come from commissioning",
   "at deployment time."),
code("import numpy as np, torch",
     "from netsentinel_v2 import train as T",
     "",
     "if cands:",
     "    E, M = real['edges'], real['mask']",
     "    Co = T.compute_cohort(E, M)",
     "    flat = lambda X: X.reshape(-1, *X.shape[2:])",
     "    Ef, Mf, Cf = flat(E), flat(M), flat(Co)",
     "    Ef, mu, sd = T.standardise(Ef, Mf)",
     "    print('host-days:', Ef.shape[0])",
     "    insp = T.train_inspector(Ef, Mf, Cf, epochs=8, seed=0)",
     "    Z, err = T.inspector_forward(insp, Ef, Mf, Cf)",
     "    print('embedding', Z.shape, '| recon error mean %.4f p99 %.4f'",
     "          % (err.mean(), np.quantile(err, 0.99)))",
     "    torch.save(insp.state_dict(), 'inspector_real_pretrained.pt')",
     "    print('saved inspector_real_pretrained.pt — this is the transferable part')"),

md("## 6 · What to take away",
   "",
   "- `results.json` — router comparison, the number you quote",
   "- `shift_results.json` — how much of it survives a new network",
   "- `chart_escalation_budget.png` — the slide",
   "- `inspector_real_pretrained.pt` — encoder weights from real traffic",
   "",
   "**Do not quote** ≥95% recall (measured 37.5% at a 5% budget), and mark every attack-recall",
   "number indicative-only while the generator is still the attack source."),
]

nb = {"cells": cells,
      "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python",
                                  "name": "python3"},
                   "language_info": {"name": "python", "version": "3.11"},
                   "kaggle": {"accelerator": "none", "dataSources": [],
                              "isInternetEnabled": True, "language": "python",
                              "sourceType": "notebook"}},
      "nbformat": 4, "nbformat_minor": 5}

out = os.path.join(here, "netsentinel_v2_kaggle.ipynb")
json.dump(nb, open(out, "w", encoding="utf-8"), indent=1)
print("wrote", out, os.path.getsize(out) // 1024, "KB,", len(cells), "cells")
