#!/bin/bash
# Remaining synthetic re-runs after the ROLE_PREPATH set->tuple fix.
# run_experiment/shift_test use DEFAULT flags: results.json recorded no config,
# and 37.1% at a 5% budget (the figure the docs quote) predates the
# --hard-negatives flag, so defaults are the closest honest match. Both scripts
# now write their config into the .json so this ambiguity cannot recur.
cd "$(dirname "$0")"
set -x
python3 sweep_threshold.py --seeds 3 --out sweep_threshold.json            > /tmp/r_sweephard.log 2>&1
python3 sweep_threshold.py --seeds 3 --easy --out sweep_threshold_easy.json > /tmp/r_sweepeasy.log 2>&1
python3 deploy_c.py                                                        > /tmp/r_deploy.log    2>&1
python3 ablation_order.py --out ablation_order.json                        > /tmp/r_abl.log       2>&1
python3 ablation_order.py --stealth-lo 0.9 --stealth-hi 1.0 \
        --out ablation_order_stealth.json                                  > /tmp/r_ablst.log     2>&1
python3 confound_test.py                                                   > /tmp/r_confound.log  2>&1
python3 paired_synth.py --hosts 700 --seeds 3                              > /tmp/r_paired.log    2>&1
python3 run_experiment.py                                                  > /tmp/r_runexp.log    2>&1
python3 shift_test.py                                                      > /tmp/r_shift.log     2>&1
echo DONE_ALL
