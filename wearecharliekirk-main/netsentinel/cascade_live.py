"""Live Inspector-Sentry cascade for the Sentinel view (console/sentinel.html).

Runs tier2/cascade_stream.py with the Tier 2 Python (it needs PyTorch) and
keeps what it streams: the commissioning stages, then one record per hour
with every host's Sentry score, the hosts escalated to the Inspector and
the Inspector's verdicts. ``attack()`` tells the stream that a compromised
host starts its kill chain.
"""
from __future__ import annotations

import collections
import json
import os
import subprocess
import threading
import time
from typing import Optional

from netsentinel.tier2_bridge import TIER2, tier2_python


class CascadeLive:
    def __init__(self):
        self.lock = threading.Lock()
        self.proc: Optional[subprocess.Popen] = None
        self.status = "idle"            # idle | starting | running | error | stopped
        self.stage = None
        self.meta: dict = {}
        self.logs: collections.deque = collections.deque(maxlen=60)
        self.hours: collections.deque = collections.deque(maxlen=240)
        self.flags: collections.deque = collections.deque(maxlen=80)
        self.seq = 0
        self.error = None
        self.attack_since = None
        self.started = None

    # -------------------------------------------------------------- control
    def start(self, tick: float = 0.8) -> dict:
        with self.lock:
            if self.proc is not None and self.proc.poll() is None:
                return {"status": self.status}
            if not (TIER2 / "cascade_stream.py").exists():
                self.status, self.error = "error", "tier2/cascade_stream.py not found"
                return {"status": self.status, "error": self.error}
            self.status, self.stage, self.error = "starting", None, None
            self.meta, self.seq, self.attack_since = {}, 0, None
            self.logs.clear(); self.hours.clear(); self.flags.clear()
            self.started = time.time()
            env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
            try:
                self.proc = subprocess.Popen(
                    [tier2_python(), "-u", "cascade_stream.py", "--tick", str(tick)], cwd=str(TIER2),
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding="utf-8", errors="replace", bufsize=1, env=env)
            except Exception as e:
                self.status, self.error = "error", str(e)[:300]
                return {"status": self.status, "error": self.error}
        threading.Thread(target=self._read, daemon=True, name="cascade-live").start()
        return {"status": "starting", "python": tier2_python()}

    def _send(self, line: str) -> bool:
        p = self.proc
        if p is None or p.poll() is not None or p.stdin is None:
            return False
        try:
            p.stdin.write(line + "\n"); p.stdin.flush()
            return True
        except Exception:
            return False

    def attack(self) -> dict:
        if self.status != "running":
            return {"error": "the cascade is not running yet (%s)" % self.status}
        ok = self._send("attack")
        if ok:
            with self.lock:
                self.attack_since = time.time()
        t = self.meta.get("target") or {}
        return {"status": "sent" if ok else "failed", "host": t.get("name")}

    def reset(self) -> dict:
        ok = self._send("reset")
        with self.lock:
            self.attack_since = None
        return {"status": "sent" if ok else "failed"}

    def stop(self):
        self._send("quit")
        p = self.proc
        if p is not None:
            try:
                p.terminate()
            except Exception:
                pass
        self.status = "stopped"

    # -------------------------------------------------------------- reading
    def _read(self):
        p = self.proc
        tail = collections.deque(maxlen=8)
        for line in p.stdout:                                          # type: ignore[union-attr]
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                tail.append(line)
                continue
            with self.lock:
                t = d.get("type")
                if t == "stage":
                    self.stage = d.get("stage"); self.logs.append(d.get("text"))
                elif t == "log":
                    self.logs.append(d.get("text"))
                elif t == "ready":
                    self.meta = d; self.status = "running"; self.stage = "watching"
                elif t == "hour":
                    self.seq += 1
                    d["seq"] = self.seq
                    self.hours.append(d)
                    for v in d.get("verdicts", []):
                        if v.get("flagged"):
                            self.flags.append(dict(v, day=d["day"], clock=d["clock"], seq=self.seq,
                                                   target=v["host"] == d.get("target"),
                                                   attack_active=d.get("attack_active")))
        rc = p.wait()
        with self.lock:
            if self.status != "stopped":
                self.status = "error"
                txt = " ".join(tail)
                self.error = ("PyTorch is not available to %s" % tier2_python()) if "torch" in txt.lower() \
                    else ("the cascade stopped (exit %s) %s" % (rc, txt[-300:]))

    def state(self, since: int = 0) -> dict:
        with self.lock:
            hours = [h for h in self.hours if h["seq"] > since]
            return {"status": self.status, "stage": self.stage, "error": self.error,
                    "meta": self.meta, "logs": list(self.logs), "seq": self.seq,
                    "hours": hours, "flags": list(self.flags),
                    "attack_active": self.attack_since is not None, "python": tier2_python()}


CASCADE = CascadeLive()
