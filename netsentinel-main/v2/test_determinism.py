#!/usr/bin/env python3
"""
test_determinism.py -- the same seed must give the same numbers in a FRESH
process, whatever PYTHONHASHSEED is.

WHY THIS TEST EXISTS (found 17 Sep 2026).
`categories.ROLE_PREPATH` held sets of category names. `synth._benign_window`
iterates that collection and draws from the RNG inside the loop, so iteration
order fixed the order of RNG consumption. Python randomises string hashing per
process, so set order -- and therefore the whole synthetic corpus -- changed
every run. `synth.generate(seed=0)` was byte-different in every fresh process,
and two runs of `sweep_threshold.py` with identical arguments returned 12.0%
and 8.8% confirmation precision.

Nothing in the harness could see it: in-process reruns agreed (same hash seed),
every unit test passed, and the seed-to-seed error bars quietly absorbed a
source of variance no seed controlled.

So this test does the one thing that exposes it: run the generator in
subprocesses under DIFFERENT hash seeds and compare bytes. Any collection that
is iterated while drawing randomness -- a set, a dict keyed by something
unordered, a `glob` without `sorted` -- fails here.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PASS = FAILED = 0


def check(name, cond, detail=""):
    global PASS, FAILED
    if cond:
        PASS += 1
        print(f"  ok    {name}")
    else:
        FAILED += 1
        print(f"  FAIL  {name}   {detail}")


CHILD = r'''
import sys, hashlib
sys.path.insert(0, %r)
import numpy as np
from netsentinel_v2 import synth
from netsentinel_v2.categories import ROLE_PREPATH, ROLES, CATEGORIES
d = synth.generate(n_hosts=40, n_days=4, seed=0, hard_negatives=True)
print("EDGES", hashlib.md5(d["edges"].tobytes()).hexdigest())
print("MASK ", hashlib.md5(d["mask"].tobytes()).hexdigest())
print("ATK  ", hashlib.md5(d["is_attack_day"].tobytes()).hexdigest())
print("ROLES", ",".join(ROLES))
print("PREP ", ";".join(r + "=" + ",".join(ROLE_PREPATH[r]) for r in ROLES))
print("CATS ", ",".join(CATEGORIES))
''' % (HERE,)


def run_with(hash_seed):
    env = dict(os.environ, PYTHONHASHSEED=str(hash_seed))
    r = subprocess.run([sys.executable, "-c", CHILD], capture_output=True,
                       text=True, env=env, cwd=HERE, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f"child failed (hash seed {hash_seed}):\n{r.stderr[-1500:]}")
    out = {}
    for line in r.stdout.strip().split("\n"):
        k, _, v = line.partition(" ")
        out[k.strip()] = v.strip()
    return out


print("=" * 70)
print("  determinism across fresh processes and hash seeds")
print("=" * 70)

seeds = [0, 1, 12345, 99991]
runs = [run_with(s) for s in seeds]

for key in ("EDGES", "MASK", "ATK"):
    vals = {r[key] for r in runs}
    check(f"{key} identical under PYTHONHASHSEED {seeds}",
          len(vals) == 1,
          f"{len(vals)} distinct digests: {sorted(v[:12] for v in vals)}")

# The ordering primitives themselves must be stable, which is a sharper error
# message than "the edges differ" when someone reintroduces a set.
for key, label in (("ROLES", "ROLES order"),
                   ("PREP", "ROLE_PREPATH order"),
                   ("CATS", "CATEGORIES order")):
    vals = {r[key] for r in runs}
    check(f"{label} stable", len(vals) == 1, f"{sorted(vals)}")

# And a direct structural check: no value in ROLE_PREPATH may be a set.
sys.path.insert(0, HERE)
from netsentinel_v2.categories import ROLE_PREPATH        # noqa: E402
bad = [k for k, v in ROLE_PREPATH.items() if isinstance(v, (set, frozenset))]
check("no ROLE_PREPATH value is a set", not bad, f"sets at {bad}")

# Same seed twice in the SAME process was always true and is not the point --
# assert it anyway so a future regression cannot claim this file covered it.
from netsentinel_v2 import synth                          # noqa: E402
a = synth.generate(n_hosts=20, n_days=3, seed=7)["edges"]
b = synth.generate(n_hosts=20, n_days=3, seed=7)["edges"]
check("same seed, same process, identical",
      hashlib.md5(a.tobytes()).hexdigest() == hashlib.md5(b.tobytes()).hexdigest())

c = synth.generate(n_hosts=20, n_days=3, seed=8)["edges"]
check("different seed gives different data (the test is not vacuous)",
      hashlib.md5(a.tobytes()).hexdigest() != hashlib.md5(c.tobytes()).hexdigest())

# ---------------------------------------------------------------------------
# CHARACTERISATION TEST -- this pins a KNOWN LIMITATION, not a desired property.
#
# `generate` threads ONE RNG through the whole population in host order, and
# `_inject_lsa` draws a number of values that depends on `stealth`. So changing
# `stealth_range` shifts the stream for every host generated afterwards: at
# 60 hosts, moving stealth from (0.9,1.0) to (0.3,1.0) changes the BENIGN
# traffic of 34 of the 56 benign hosts.
#
# The consequence is a methodology one and it matters: varying a generator
# parameter and comparing the results is NOT an ablation on this generator. It
# resamples most of the population at the same time. Runs at different settings
# are separate samples, and differences between them cannot be attributed to
# the parameter.
#
# The fix is per-component streams --
#   ss = np.random.SeedSequence(seed); topo, benign, habit, inject = ss.spawn(4)
# -- so the attacker's draws cannot move anyone else's traffic. It is not done
# here because it changes every synthetic number again, three days before a
# deadline, and today's numbers are at least reproducible.
#
# When someone does fix it, THIS TEST FAILS. That is the point: it fails, they
# find this comment, and they update AUDIT.md G9 and the sweep caveats instead
# of quietly inheriting a caveat that no longer applies.
# ---------------------------------------------------------------------------
import numpy as np                                         # noqa: E402

_a = synth.generate(n_hosts=60, n_days=6, seed=0,
                    stealth_range=(0.9, 1.0), hard_negatives=True)
_b = synth.generate(n_hosts=60, n_days=6, seed=0,
                    stealth_range=(0.3, 1.0), hard_negatives=True)
_ben = _a["stealth"] <= 0
_labels_same = bool((_a["is_attack_day"] == _b["is_attack_day"]).all())
_benign_same = bool(np.isclose(_a["edges"][_ben], _b["edges"][_ben]).all())
check("attack-day labels do not depend on stealth", _labels_same)
check("KNOWN LIMITATION pinned: stealth also resamples benign traffic",
      not _benign_same,
      "benign traffic is now isolated -- GOOD. Remove this check, and update "
      "AUDIT.md G9 and the sweep caveats in the spec and brief.")

print()
print(f"  {PASS} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)
