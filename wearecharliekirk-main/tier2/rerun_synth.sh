#!/bin/bash
# Re-run every SYNTHETIC experiment after the ROLE_PREPATH set->tuple fix.
# LANL and own-capture results are untouched: lanl_loader.py and zeek_loader.py
# import only _edge_row and WINDOWS_PER_DAY from synth, never ROLE_PREPATH.
cd "$(dirname "$0")"
set -x
python3 escalate.py                                                       > /tmp/r_escalate.log   2>&1
python3 ablation_order.py --hard-negatives --stealth-lo 0.9 --stealth-hi 1.0 \
        --out ablation_order_hard.json                                    > /tmp/r_ablhard.log    2>&1
python3 sweep_threshold.py --seeds 3 --out sweep_threshold.json           > /tmp/r_sweephard.log  2>&1
python3 sweep_threshold.py --seeds 3 --easy --out sweep_threshold_easy.json > /tmp/r_sweepeasy.log 2>&1
python3 deploy_c.py                                                       > /tmp/r_deploy.log     2>&1
python3 ablation_order.py --out ablation_order.json                       > /tmp/r_abl.log        2>&1
python3 ablation_order.py --stealth-lo 0.9 --stealth-hi 1.0 \
        --out ablation_order_stealth.json                                 > /tmp/r_ablst.log      2>&1
python3 confound_test.py                                                  > /tmp/r_confound.log   2>&1
python3 paired_synth.py --hosts 700 --seeds 3                             > /tmp/r_paired.log     2>&1
python3 run_experiment.py --hard-negatives                                > /tmp/r_runexp.log     2>&1
python3 shift_test.py                                                     > /tmp/r_shift.log      2>&1
echo DONE_ALL
