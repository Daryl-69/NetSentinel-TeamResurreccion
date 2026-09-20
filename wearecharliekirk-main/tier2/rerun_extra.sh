#!/bin/bash
cd "$(dirname "$0")"
# 1. EIGHT seeds on the router comparison. At 3 seeds the three routers are not
#    separable (A 0.735-0.885 across seeds, C wins one of them), yet the docs
#    read as a clean ranking. More seeds is the only honest way to settle it.
python3 run_experiment.py --seeds 8 --out results_8seed.json > /tmp/r_runexp8.log 2>&1
# 2. CONTROLLED stealth comparison: --easy varies stealth AND hard negatives
#    together, so it cannot say which one moved the result.
python3 sweep_threshold.py --seeds 3 --stealth 0.3 1.0 \
        --out sweep_threshold_midstealth.json > /tmp/r_sweepmid.log 2>&1
# 3. paired_synth again: median_paired_diff was written on one verdict branch
#    only, so the documented -0.007 had no source in the shipped code.
python3 paired_synth.py --hosts 700 --seeds 3 > /tmp/r_paired2.log 2>&1
# 4. escalate again, so escalate.json carries the machine_reference block.
python3 escalate.py > /tmp/r_escalate2.log 2>&1
echo DONE_EXTRA
