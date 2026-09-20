# Datasets — what to download, what it's for, what it can't do

> Checked 2026-09-04; reachability re-checked after the Stratosphere host failed. Read the "what it can't do" column before planning around any of these.
> The short version: **no LOTS/cloud-C2 chain corpus exists.** A 2026 survey of **124** IDS
> datasets found none containing multi-stage or APT-style campaigns at all. Everything below is
> a partial substitute for a different part of the problem.

---

## Reachability first (added after Stratosphere failed)

`mcfp.felk.cvut.cz` is **unreachable from the college network** — both `Invoke-WebRequest`
and `curl` fail to connect, so it is a firewall or the host being down, not TLS. Everything below
is now ranked by *can you actually download it*, then by *is it any good*.

| Source | Reachable? | Real humans | Hostnames (SNI/DNS) | Multi-day hosts | Attack labels |
|---|---|---|---|---|---|
| **WRCCDC 2018** (GitHub) | **yes** | yes | **yes** | no | partial |
| **LANL cyber1** | yes (email form) | yes | **no** | **yes, 58 days** | **yes, real red team** |
| UWF-ZeekData22 | probably | yes | some | no (hours) | yes (MITRE) |
| Stratosphere Normal | **no** | yes | some | no | none |
| Your own capture | **yes** | yes | **yes** | **yes** | none |

### WRCCDC 2018 — try this first
Zeek logs from the Western Regional Collegiate Cyber Defense Competition: real blue teams
defending a real network while real red teams attack it. Republished as Zeek TSV in
`brimdata/zed-sample-data`, so it comes off GitHub, which campus firewalls almost never block.

- https://github.com/brimdata/zed-sample-data
- `powershell -ExecutionPolicy Bypass -File get_data.ps1`

The repo ships the same logs in six encodings; the script keeps the Zeek TSV and deletes the
rest, otherwise `train_real.py` reads the same traffic four times and thinks it has four
networks. **It includes ssl.log and dns.log, so the Service Category Resolver has hostnames to
work with** — which is exactly what Stratosphere would probably not have given you.

Limits: one competition, short span, so no multi-day per-host baselines. It is a real test of the
*resolver* and the *encoder*, not of the baselines.

### LANL cyber1 — the only real multi-day host data that exists
58 consecutive days, **17,684 real computers**, 12,425 users, 1.6 billion events, ~12 GB
compressed, CC0. Includes `flows.txt.gz` (time, duration, src computer, src port, dst computer,
dst port, protocol, packets, bytes) and — importantly — **`redteam.txt.gz`: real red-team
compromise events**. Not a generator. Not emulation. An actual red team on an actual enterprise.

- https://csr.lanl.gov/data/cyber1/  (email + intended-use form, then direct download)

**The catch: everything is de-identified to internal IDs** (`C1`, `C2`, `U7`). There are no
domain names anywhere, so the Service Category Resolver is completely blind. Half the
architecture cannot be tested on it.

**But the other half can, and better than anywhere else** — and there is a way to get categories
back. Group destination computers by *port and fan-in degree* rather than by domain: a host that
3,000 machines connect to on 445 is a file server; one that 12 connect to on 3389 is a jump box;
a leaf that talks only outbound is a workstation. That is **internal asset class**, which is
precisely the bridge ARCHITECTURE_V2 §9 proposes for the OT/data-diode positioning — where there
is no Telegram or GitHub either. So LANL is not a consolation prize: **it is a direct test of the
positioning you intend to lead with**, on real data, with real attack ground truth.

**Running it** (`netsentinel_v2/lanl_loader.py`, self-tested by `test_lanl_loader.py`):

```powershell
.\.venv\Scripts\python.exe train_real.py --lanl --data D:\Downloads `
    --max-hosts 500 --lanl-days 14 --epochs-teacher 12 --epochs-student 14 `
    --label-policy both --out lanl_results.json
```

The first run streams the whole flow file twice and caches both the fan-in profile
(`lanl_profile.json`) and the parsed tensors (`lanl_tensors_H*_D*.npz`); after that, re-runs and
`--label-policy` sweeps are nearly free.

Four things about this dataset will silently produce a wrong number if you don't know them:

1. **cyber1 does not normalise flow direction.** The dataset's own example row
   `1,0,C1065,389,C3799,N10451,6,10,5323` has the LDAP service port on the *source* side. The
   loader takes the service port as `min(numeric ports)` and attributes the flow to the endpoint
   holding the *ephemeral* port — the client. Keying on `dst_port`, or on `src_computer`, gets
   both the category and the host wrong on a large share of traffic.
2. **`egress_asymmetry` and `log_bytes_down` do not exist here.** cyber1 logs one byte count, not
   a directional pair. The loader writes exact zeros and reports it. The 2017 *Unified Host and
   Network* release has directional bytes and **no red-team labels** — labels or directionality,
   not both.
3. **`redteam.txt` rows are authentication events, not flows**, and which endpoint you mark
   changes the answer. `--label-policy dst` (mark the victim) is the intuitive choice and the
   wrong one for this system: we model a host's *outbound* behaviour, so the row that actually
   changes shape is the compromised **source**. Run all three policies before concluding anything
   from a low attack recall.
4. **Positives are extremely rare.** A few hundred attack windows against tens of thousands of
   benign ones. Quote the count next to the rate, always.

**The result, and the reason the loader has novelty features.** The first correct run (500 hosts,
13 days, 3 label policies) gave a global Inspector AUC of 0.713 against the red team — and a
**within-host AUC of 0.526 ± 0.308, which is chance.** Scoring each host against its own baseline
removed the signal entirely: the global figure was ranking *which* host was unusual (attacked rows
ran at 0.811 live-window density vs 0.530 for the rest), not *when* it was attacked. Volume and
timing cannot separate a credential-based hop over Kerberos/SMB/RDP from an administrator's
Tuesday, because they are the same traffic.

So slots 2 and 3 — dead on this dataset — now carry the signal that *does* describe lateral
movement:

| slot | generator name | on LANL |
|---|---|---|
| 2 | `log_bytes_down` | `new_peer_ratio` — distinct peers outside the host's commissioned profile |
| 3 | `egress_asymmetry` | `new_service_flag` — first use of a service class outside that profile |

The profile is learned over days `0 .. D//2 - 1` (exactly the commissioning split) and then
**frozen**. Freezing is not a detail: with an ever-growing prefix a lateral hop is novel for one
window and ordinary from the second onwards, which caps any window-level metric by construction.

`test_lanl_loader.py` proves the features work rather than assuming it. It builds a fixture where
the attack day has *identical* flow counts, bytes, durations and timing to every other day — only
the peers are new — and asserts that volume/timing scores chance on it while novelty does not.
Measured through the full pipeline: **within-host AUC 0.520 → 0.888.**

Always run the A/B, and report both:

```powershell
.\.venv\Scripts\python.exe train_real.py --lanl --data D:\Downloads --max-hosts 500 `
    --lanl-days 13 --label-policy both --seeds 3 --no-novelty --out lanl_base.json
.\.venv\Scripts\python.exe train_real.py --lanl --data D:\Downloads --max-hosts 500 `
    --lanl-days 13 --label-policy both --seeds 3 --out lanl_novelty.json
```

The number that decides it is **within-host AUC**, not the global one. Below 0.60 it is chance
whatever the global figure says.

### UWF-ZeekData22
Real Zeek logs labelled with MITRE ATT&CK tactics (recon/discovery), PCAP and parquet.
- https://datasets.uwf.edu/ , files at https://datasets.uwf.edu/data/

Limits: a few hours of Feb 10 2022, roughly 80/20 benign/attack, and only two tactics. Fine as a
second format test, not a source of normal.

---

## Tier 1 — get these first (real, free, no labelling work)

### Stratosphere Normal Captures — real benign, for ENCODER pretraining
23 captures of real human/host activity: university networks, home Linux notebooks, Windows
machines, xDSL. pcap, binetflow, **and Bro/Zeek logs**.

- Index: https://www.stratosphereips.org/datasets-normal
- Files: https://mcfp.felk.cvut.cz/publicDatasets/
- Useful individual captures:
  - `CTU-Normal-7` — P2P + web, Linux notebook — https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-7
  - `CTU-Normal-12` — Linux notebook, P2P + web — https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-12
  - `CTU-Normal-6-filtered` — Linux user, DNS-filtered for privacy — https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-6-filtered/
  - `CTU-Normal-10` — Windows host — https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-10
  - `CTU-Normal-13`, `CTU-Normal-20`…`-32` — HTTPS-focused captures

**What it can't do:** captures are short (hours) and single-host. Good for teaching the encoder
what real traffic *looks like*; **useless for validating multi-day per-host baselines.** Do not
try to fit (μ_h, Σ_h) from these.

### CTU-13 — real botnet + real background, you already have it
13 scenarios, real infected hosts mixed with real university background traffic. Already used by
your C2 BiLSTM+FFT model.

- https://www.stratosphereips.org/datasets-ctu13
- Files: https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/

**What it can't do:** botnet C2, not trusted-service abuse. No service-category structure.

### Your own team's machines — the only source of multi-day per-host normal
Zeek on 6 laptops for 2 weeks. `conn.log` + `ssl.log` + `dns.log`. Zero labelling; you are only
recording. Setup is a day; the two weeks pass while you build other things.

```bash
# per machine, one line of setup
zeek -i <iface> LogAscii::use_json=T Log::default_rotation_interval=1hr
```

**Start this now** precisely because it has wall-clock latency and nothing else does. It is the
only thing on this page that produces *stable hosts observed over days*, which is what the
Sentry's baseline actually needs.

---

## Tier 2 — for the sequence claim (real red-team, not your generator)

### DARPA OpTC — real enterprise ops + red-team, unlabelled
Large (~1 TB raw). Used by StageFinder (arXiv:2603.07560) for **self-supervised pretraining**,
then fine-tuned on labelled TC. That is the template to copy.

- https://github.com/FiveDirections/OpTC-data
- Analysis of its usefulness/pitfalls: https://ar5iv.labs.arxiv.org/html/2103.03080

### DARPA Transparent Computing (TC) — labelled red-team engagements
Multi-stage attack campaigns with ground truth. Host-provenance-heavy, but the network component
gives **real adversary sequences**, which is what kills the "your generator marked its own
homework" objection.

- https://github.com/darpa-i2o/Transparent-Computing

**What they can't do:** neither is LOTS. The services abused are not GitHub/Telegram/Drive. Use
them to validate that *sequence-based detection works on real adversaries*, then argue the
mechanism transfers to trusted-service categories.

---

## Tier 3 — background / comparison only

| Dataset | Link | Why it's here | Why it isn't enough |
|---|---|---|---|
| MAWI | http://mawi.wide.ad.jp/mawi/ | real, ongoing daily captures | backbone transit — no stable hosts, so no per-host baseline |
| CAIDA | https://www.caida.org/catalog/datasets/overview/ | real IXP captures | DDoS/backscatter only |
| LBNL | https://www.icir.org/enterprise-tracing/ | real *enterprise* traffic | 2004–05, pre-HTTPS-dominance |
| IoT-23 | https://www.stratosphereips.org/datasets-iot23 | labelled malicious + benign IoT, Zeek format | IoT malware, not LOTS |
| CIC-IDS2017 / CSE-CIC-IDS2018 | https://www.unb.ca/cic/datasets/ids-2017.html | the standard benchmark | **benign traffic is itself synthetic** (B-Profile) — does not solve our problem |
| UNSW-NB15 | https://research.unsw.edu.au/projects/unsw-nb15-dataset | your port-scan model's training set | synthetic background |

---

## Emulation — for the malicious half (when you get there)

Label **by construction**: the orchestrator logs (timestamp, host, stage, ATT&CK id); join to
Zeek by (host, time-window). Chain-level labels, not flow-level.

- **MITRE Caldera** — https://github.com/mitre/caldera
- **Atomic Red Team** — https://github.com/redcanaryco/atomic-red-team
- **Mythic C2** (custom profiles over third-party services) — https://github.com/its-a-feature/Mythic

Ground truth for *what to emulate* — real campaigns, use these as specs:
- Recorded Future, GitHub as malicious infrastructure — https://www.recordedfuture.com/research/flying-under-the-radar-abusing-github-malicious-infrastructure
- Cloudflare, Vercel-hosted RMM + Telegram C2 — https://www.cloudflare.com/cloudforce-one/research/report/vercel-hosted-rmm-abuse-campaign-evolves-with-telegram-c2-for-victim-filtering/
- LOTS Project (domain taxonomy for the Service Category Resolver) — https://lots-project.com/

---

## The order that matters

1. **Stratosphere Normal + CTU-13** → encoder pretraining. Free, today, half a day.
2. **Team laptops + Zeek** → start recording now; it's the only source of real per-host baselines.
3. **DARPA TC/OpTC** → sequence-hypothesis validation on real adversaries.
4. **Caldera/Mythic emulation** → the malicious half. Months. Future work; cite the 124-dataset
   gap as why building it is a contribution.

**Do not** train on CIC-IDS benign and call it real — its background traffic is generated, so it
reproduces the exact problem you are trying to escape.

---

## Sources
- *A survey of intrusion detection datasets for communication networks* (124 datasets) — https://link.springer.com/article/10.1007/s10791-026-10486-2
- *Expectations Versus Reality: Evaluating Intrusion Detection Systems in Practice* — https://arxiv.org/html/2403.17458v2
- *Benchmarking the benchmark — synthetic vs real-world NIDS datasets* — https://www.sciencedirect.com/science/article/pii/S2214212623002739
- StageFinder — https://arxiv.org/html/2603.07560v1

---

## Evaluated and rejected — do not re-open these

Checked 2026-09-05. Each was assessed against the only question that matters for Tier 2:
**does it contain egress to trusted SaaS, with resolvable hostnames, over multiple days per host?**

### Zenodo 19206234 — "Benign Network Traffic PCAP Dataset for Reproducibility"
https://zenodo.org/records/19206234 — 45 PCAPs, 3 profiles (Regular / Gamer / Administrator)
x 3 durations x 5 replications. **Rejected, twice over:**

1. **Longest capture is 60 minutes.** Per-host baselines need days, not one window. `train_real.py`
   would fall through to its "too few days, plumbing check only" path.
2. **Agent-generated, not human.** It is synthetic traffic produced by LLM-driven agents. We
   already have `synth.py`; swapping one generator for another does not answer CRITIQUE A5/B2, it
   just moves it, and we lose control of the DevOps hard negatives that make the experiment
   non-trivial.

### IoT-23 (Stratosphere)
https://www.stratosphereips.org/datasets-iot23 — 23 captures, 20 malicious / 3 benign, real IoT
devices, Zeek `conn.log.labeled`. **Rejected for Tier 2:**

1. **`conn.log.labeled` only** — no `ssl.log`, no `dns.log`. The Service Category Resolver has no
   hostnames, so every external destination becomes `Unknown_External`. (Pcaps are included, so
   the logs could be regenerated — but see 2, which makes that pointless.)
2. **The hosts are a smart lamp, an Echo and a doorlock.** They do not visit GitHub, Telegram or
   Drive, so there is no cross-service chain in this data to detect at all. The threat model is
   IoT botnet: horizontal port scan, DDoS, C&C to hardcoded IPs.
3. **Three benign captures.** Almost no "normal" to baseline.

**But IoT-23 IS the right dataset for one thing:** the Tier-1 **port-scan expert currently gets
zero detections** because it was trained on the wrong data. IoT-23 carries **213,852,924 labelled
`PartOfAHorizontalPortScan` flows** and 19,538,713 labelled DDoS flows — exactly what that model
needs for a retrain or an honest second-dataset validation, and it would put real evidence behind
the "agentless-first: IoT, OT, BYOD" positioning. Not a Tier-2 result. Park it until
re-calibration and chain injection are both landing.

### The pattern, stated once so it stops costing time
LANL had labels and no egress (section 5c). Stratosphere Normal has egress and no labels.
WRCCDC has egress and one day. IoT-23 has labels and no hostnames and no browsing hosts. This
one has neither labels nor duration nor real humans. **Nobody publishes multi-day egress traffic
with attack labels**, because doing so means publishing where an organisation's staff browse.
That is why the 12-day capture plus injected chains is not a fallback — it is the only route.
