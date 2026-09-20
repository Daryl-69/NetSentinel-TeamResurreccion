# After the 8th — to the 20 Sep submission

Twelve days. The capture is already running and finishes on the 17th, which fixes the shape of
everything else: three workstreams in parallel, one hard checkpoint on the 16th.

---

## Track A — rolling re-calibration  (owner: 1 dev, 9–12 Sep)

**Why this and not something else.** Three independent measurements now say the alert threshold
decays from the day it is set: 6.82% flag rate in world A's own later period, 6.26% cross-org,
2.56% ± 0.22 on real LANL traffic — all against a 1.0% target. ARCHITECTURE_V2 §4 has no knob for
it. This is the one piece of engineering your own evidence demands, it is small, and "our
measurements told us to build this, so we built it" is a strong line in a submission.

- [ ] Rolling window re-estimate of the Inspector threshold: hold the last N days of
      commissioning-equivalent scores, re-take the 99th percentile on a schedule.
- [ ] Guard it: never let the flag rate move more than X% per re-calibration, so one bad day
      cannot blind the system.
- [ ] Measure it — re-run `shift_test.py` and `train_real.py --lanl` with re-calibration on, and
      report flag rate vs the 1.0% target before and after. **If it does not pull the flag rate
      toward target, say so;** a feature that does not work is not a feature.
- [ ] Write it into ARCHITECTURE_V2 §4 as a real component, not a TODO.

## Track B — chain injection  (owner: 1–2 devs, 9–16 Sep)

**The only route to a detection number you can defend.** LANL is all-internal, so the
cross-service sequence hypothesis was never testable there (§5c). Your own capture has real
egress; you supply the labels.

- [ ] Script LOTS chains over the captured benign base: Recon_API &rarr; Code_Repo_Paste &rarr;
      Messaging_API &rarr; Cloud_Storage, at realistic beacon intervals.
- [ ] **Hard negatives are the whole experiment.** DevOps hosts legitimately walk the same
      category sequence with human timing — `synth.py` already models this. Without them the
      result is trivially good and worthless.
- [ ] Inject as Zeek-format rows so `zeek_loader.load_dir()` reads them with no code change.
- [ ] Evaluate with `train_real.py --seeds 3` and **report within-host AUC**, not global.

## Track C — the submission document  (owner: 1 dev, continuous)

- [ ] Fold §5c into the formal writeup. Lead with the cascade result; state the negative
      yourself, before a reviewer finds it.
- [ ] Correct the positioning: ARCHITECTURE_V2 §9's internal-asset-class reframe for OT is
      **not evidence-backed** — LANL is that setting and detection was chance there. Present it
      as a hypothesis with a stated test, not as validated.
- [ ] Prior art, stated plainly: Inspector = GraphIDS (arXiv:2509.16625); cascade, distillation
      and per-entity baselining are all prior art. The contribution is the cross-service
      category-sequence framing plus the chain dataset.
- [ ] Delete the stale result files so nobody quotes them: `lanl_results.json`,
      `lanl_src.json`, `lanl_dst.json`, `lanl_both.json`, `_superseded_kaggle.ipynb`.

---

## Daily, 30 seconds (someone owns this)

```powershell
cd D:\1_sih26#2\netsentinel-main\v2
.\install_capture_task.ps1 -Status
```

Files still appearing? Good. A capture nobody checked is a capture that died on day 2 — and you
will not find out until the 17th, when there is no time left to redo it.

Once, on **10 Sep**, also convert and sanity-check:
```bash
./zeekify.sh /mnt/d/capture /mnt/d/capture-zeek     # in WSL
```
```powershell
.\.venv\Scripts\python.exe train_real.py --data D:\capture-zeek --seeds 3
```
The number to look at is the **resolver hit rate** (WRCCDC gave 77.3%). If it is near zero,
there are no hostnames and the capture cannot test the hypothesis — you have a week to fix that,
but only if you look now.

---

## 16 Sep — the checkpoint, and the decision I would make for you

Ask one question: **is chain injection producing a within-host AUC you would defend under
questioning?**

- **Yes** &rarr; final run on the 18th with the full 12 days, `--seeds 3`, write it up.
- **No** &rarr; **stop Track B and ship without it.** The submission is then: the cascade
  efficiency result (real, measured, multi-seed, on real traffic), the honest negative with the
  confound check you built yourselves, and re-calibration as engineering that followed from your
  own evidence. That is a complete, defensible story.

A rushed detection number you cannot defend is worse than no detection number. You now have the
tooling to prove that to yourselves, which most teams at this stage do not.

---

## 17–20 Sep

- [ ] 17th: stop the capture (`install_capture_task.ps1 -Uninstall`), final `zeekify.sh`.
- [ ] 18th: final run, `--seeds 3`, on 12 days of your own traffic.
- [ ] 19th: `make_card.py` regenerated; every number in the document traced to a JSON file.
- [ ] 20th: submit.

## Explicitly NOT doing

- Hunting for more public datasets. `DATASETS.md` and §5c settle it — the labelled multi-day host
  data that exists cannot test this hypothesis. Don't spend a week rediscovering that.
- Fixing the port-scan model. Wrong dataset, not a code bug, no time.
- SHAP, blockchain anchoring, meta-classifier fusion, SIEM connectors. None of these change the
  answer to the question the submission has to answer.
