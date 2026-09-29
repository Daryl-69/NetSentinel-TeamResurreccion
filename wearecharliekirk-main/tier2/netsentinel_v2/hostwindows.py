"""Real traffic -> per-host hourly windows -> the Inspector's tensors.

This is the seam between captured traffic (a 20-day baseline capture, or the
sensor's live capture) and the Tier 2 models. Everything that decides what a
"window" is lives here, and both paths use it, so a window built from the
baseline pcaps and a window built from live traffic mean the same thing:

    connection record  (host, peer, hostname, start ts, duration, bytes up/down)
          |  resolve_category(hostname, peer)      -- zeek_loader's taxonomy
          v
    window  (host, LOCAL hour, category)           -- one hour, clock-aligned
          |  synth._edge_row(...)                  -- the same 10 features
          v
    CorpusStore (sqlite)                           -- baseline and live corpora
          |  build_samples(...)
          v
    host-day tensors  edges (N,24,C,F)  mask (N,24,C)  cohort (N,24,C,F)

Windows are keyed on the LOCAL hour of the network they were captured on
(tz offset stored per corpus), so hour-of-day means working hours on both a
baseline captured in India and a live sensor anywhere else.

No payload, no domain name and no timestamp finer than the hour is stored:
a corpus row is (host, hour, category, 10 statistics).
"""
from __future__ import annotations

import glob
import os
import re
import sqlite3
import time
from collections import defaultdict
from typing import Iterable, Iterator, NamedTuple, Optional

import numpy as np

from .categories import CAT_INDEX, CATEGORIES, N_CATEGORIES, N_EDGE_FEATURES
from .synth import _edge_row, WINDOWS_PER_DAY
from .zeek_loader import _PRIVATE, _num, read_zeek, resolve_category


class FlowRecord(NamedTuple):
    """One connection, seen from the monitored (local) host's side."""
    host: str            # local endpoint (the device being profiled)
    peer: str            # the other endpoint
    name: Optional[str]  # hostname for the peer (TLS SNI / DNS answer), if known
    ts: float            # connection start, epoch seconds
    dur: float           # seconds
    up: float            # bytes host -> peer (payload)
    down: float          # bytes peer -> host (payload)


def local_tz_offset() -> int:
    """This machine's UTC offset in seconds (e.g. +19800 for IST)."""
    return int(time.localtime().tm_gmtoff)


def parse_tz(s: Optional[str]) -> int:
    """'+05:30' / '-4' / '19800' -> seconds; None -> this machine's offset."""
    if s is None or s == "":
        return local_tz_offset()
    s = str(s).strip()
    # hours form: "+5", "-4", "05:30", "+05:30", "+0530"; anything else is seconds
    m = re.fullmatch(r"([+-]?)(\d{1,2})(?::(\d{2}))?", s) or re.fullmatch(r"([+-])(\d{2})(\d{2})", s)
    if m:
        sign = -1 if m.group(1) == "-" else 1
        return sign * (int(m.group(2)) * 3600 + int(m.group(3) or 0) * 60)
    return int(float(s))


def local_hour(ts: float, tz_offset: int) -> int:
    """Clock-aligned hour index in the capture site's local time.
    day = lhour // 24, hour of day = lhour % 24."""
    return int((ts + tz_offset) // 3600)


def is_local(ip: str, local_ips: frozenset | set = frozenset()) -> bool:
    return bool(ip) and (ip in local_ips or bool(_PRIVATE.match(ip)))


# --------------------------------------------------------------------------
# Aggregation: connection records -> hourly windows
# --------------------------------------------------------------------------
class _Acc:
    __slots__ = ("n", "up", "down", "starts", "dur", "peers")

    def __init__(self):
        self.n = 0
        self.up = 0.0
        self.down = 0.0
        self.starts: list = []
        self.dur = 0.0
        self.peers: set = set()


class WindowAggregator:
    """Accumulates connection records into (host, local hour, category) windows.

    Features are computed exactly as zeek_loader does for a Zeek conn.log:
    one timestamp per connection for the timing statistics, distinct peers
    over connections, mean duration, summed payload bytes.
    """

    def __init__(self, tz_offset: int):
        self.tz = int(tz_offset)
        self.acc: dict[tuple, _Acc] = {}
        self.records = 0

    def add(self, r: FlowRecord) -> None:
        cat = resolve_category(r.name, r.peer)
        key = (r.host, local_hour(r.ts, self.tz), CAT_INDEX[cat])
        a = self.acc.get(key)
        if a is None:
            a = self.acc[key] = _Acc()
        a.n += 1
        a.up += max(0.0, float(r.up))
        a.down += max(0.0, float(r.down))
        a.starts.append(float(r.ts))
        a.dur += max(0.0, float(r.dur))
        a.peers.add(r.peer)
        self.records += 1

    @staticmethod
    def _row(a: _Acc) -> np.ndarray:
        ts = np.sort(np.asarray(a.starts, dtype=np.float64))
        iats = np.diff(ts) if ts.size > 1 else np.array([0.0])
        return _edge_row(None, a.n, a.up, a.down, iats,
                         len(a.peers) / max(a.n, 1), a.dur / max(a.n, 1))

    def rows(self, keys: Optional[Iterable[tuple]] = None) -> list[tuple]:
        """[(host, lhour, cat, n, features)] for the given (or all) windows."""
        ks = self.acc.keys() if keys is None else [k for k in keys if k in self.acc]
        return [(k[0], k[1], k[2], self.acc[k].n, self._row(self.acc[k])) for k in ks]

    def rows_for_hour(self, lhour: int) -> list[tuple]:
        return self.rows([k for k in self.acc if k[1] == lhour])

    def pop_before(self, lhour: int) -> list[tuple]:
        """Close and remove every window whose hour is < lhour."""
        keys = [k for k in self.acc if k[1] < lhour]
        out = self.rows(keys)
        for k in keys:
            del self.acc[k]
        return out

    def pop_all(self) -> list[tuple]:
        out = self.rows()
        self.acc.clear()
        return out

    def hours(self) -> list[int]:
        return sorted({k[1] for k in self.acc})


# --------------------------------------------------------------------------
# Corpus store (sqlite): the 20-day baseline, and the live corpus
# --------------------------------------------------------------------------
_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS windows (
    host    TEXT    NOT NULL,
    lhour   INTEGER NOT NULL,
    cat     INTEGER NOT NULL,
    n       REAL    NOT NULL,
    f       BLOB    NOT NULL,
    flagged INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host, lhour, cat)
);
CREATE INDEX IF NOT EXISTS windows_lhour ON windows (lhour);
"""


class CorpusStore:
    """One corpus of hourly windows from ONE network (one tz, one address plan).

    flagged=1 marks windows the Inspector flagged; they are kept for audit but
    left out of training, so an intrusion that is in progress is not learned
    as the host's normal.
    """

    def __init__(self, path: str, tz_offset: Optional[int] = None, create: bool = True):
        if not create and not os.path.exists(path):
            raise FileNotFoundError(path)
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)
        self.path = path
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self.db.executescript(_SCHEMA)
        stored = self.meta_get("tz_offset")
        if stored is None:
            self.tz = local_tz_offset() if tz_offset is None else int(tz_offset)
            self.meta_set("tz_offset", str(self.tz))
            self.meta_set("created", str(int(time.time())))
        else:
            self.tz = int(stored)
            if tz_offset is not None and int(tz_offset) != self.tz:
                raise ValueError(f"{path} was built with tz offset {self.tz}s, not {tz_offset}s")

    # ---- meta
    def meta_get(self, k: str, default=None):
        row = self.db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return row[0] if row else default

    def meta_set(self, k: str, v) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)", (k, str(v)))
        self.db.commit()

    # ---- writes
    def put(self, rows: Iterable[tuple], flagged: Iterable[tuple] = ()) -> int:
        """Upsert windows. rows: (host, lhour, cat, n, features[10]).
        flagged: (host, lhour) pairs to mark."""
        fl = set(flagged)
        data = [(h, int(lh), int(c), float(n), np.asarray(f, np.float32).tobytes(),
                 1 if (h, int(lh)) in fl else 0) for h, lh, c, n, f in rows]
        if data:
            self.db.executemany(
                "INSERT OR REPLACE INTO windows (host, lhour, cat, n, f, flagged) "
                "VALUES (?, ?, ?, ?, ?, ?)", data)
            self.db.commit()
        return len(data)

    def mark_flagged(self, pairs: Iterable[tuple]) -> None:
        self.db.executemany("UPDATE windows SET flagged=1 WHERE host=? AND lhour=?",
                            [(h, int(lh)) for h, lh in pairs])
        self.db.commit()

    def rename_hosts(self, mapping: dict) -> None:
        for old, new in mapping.items():
            self.db.execute("UPDATE windows SET host=? WHERE host=?", (new, old))
        self.db.commit()

    # ---- reads
    def rows(self, lhour_from: Optional[int] = None, lhour_to: Optional[int] = None,
             include_flagged: bool = False, hosts: Optional[Iterable[str]] = None):
        q, args = "SELECT host, lhour, cat, n, f, flagged FROM windows WHERE 1=1", []
        if lhour_from is not None:
            q += " AND lhour >= ?"; args.append(int(lhour_from))
        if lhour_to is not None:
            q += " AND lhour < ?"; args.append(int(lhour_to))
        if not include_flagged:
            q += " AND flagged = 0"
        if hosts is not None:
            hs = list(hosts)
            if not hs:
                return []
            q += " AND host IN (%s)" % ",".join("?" * len(hs)); args += hs
        return [(h, lh, c, n, np.frombuffer(f, np.float32), fl)
                for h, lh, c, n, f, fl in self.db.execute(q, args)]

    def summary(self) -> dict:
        r = self.db.execute(
            "SELECT COUNT(*), COUNT(DISTINCT host), MIN(lhour), MAX(lhour), "
            "SUM(flagged) FROM windows").fetchone()
        n, hosts, lo, hi, flagged = r
        days = self.db.execute(
            "SELECT COUNT(*) FROM (SELECT DISTINCT host, lhour / 24 FROM windows)").fetchone()[0]
        cats = dict(self.db.execute("SELECT cat, COUNT(*) FROM windows GROUP BY cat").fetchall())
        return {
            "path": self.path, "windows": n or 0, "hosts": hosts or 0, "host_days": days or 0,
            "days_spanned": 0 if lo is None else hi // 24 - lo // 24 + 1,
            "first_day": None if lo is None else _day_str(lo // 24),
            "last_day": None if hi is None else _day_str(hi // 24),
            "flagged_windows": int(flagged or 0), "tz_offset": self.tz,
            "categories": {CATEGORIES[c]: int(k) for c, k in sorted(cats.items())},
        }

    def close(self):
        self.db.close()


def _day_str(lday: int) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(lday * 86400))


# --------------------------------------------------------------------------
# Rows -> host-day tensors
# --------------------------------------------------------------------------
def compute_cohort(E, M):
    """Same as train.compute_cohort (kept here so this module never imports
    torch -- the sensor uses it without PyTorch installed)."""
    s = (E * M[..., None]).sum(axis=0)
    n = M.sum(axis=0)[..., None]
    own = E * M[..., None]
    cnt = np.maximum(n - M[..., None], 1.0)
    return ((s[None] - own) / cnt).astype(np.float32)


def rows_to_grid(rows, host_prefix: str = ""):
    """Sparse rows of ONE corpus -> dense (H, D, 24, C, F) grid + cohort.

    Cohort (the Inspector's hop-2 context) is computed inside the corpus, i.e.
    among hosts of the same network on the same local day and hour, never
    across two different networks.
    """
    if not rows:
        z = np.zeros((0, WINDOWS_PER_DAY, N_CATEGORIES, N_EDGE_FEATURES), np.float32)
        return dict(edges=z, mask=z[..., 0], cohort=z, host_day=[])
    hosts = sorted({r[0] for r in rows})
    days = sorted({r[1] // WINDOWS_PER_DAY for r in rows})
    hi = {h: i for i, h in enumerate(hosts)}
    di = {d: i for i, d in enumerate(days)}
    H, D = len(hosts), len(days)
    E = np.zeros((H, D, WINDOWS_PER_DAY, N_CATEGORIES, N_EDGE_FEATURES), np.float32)
    M = np.zeros((H, D, WINDOWS_PER_DAY, N_CATEGORIES), np.float32)
    for r in rows:
        h, lh, c, f = r[0], r[1], r[2], r[4]
        d, w = divmod(lh, WINDOWS_PER_DAY)
        E[hi[h], di[d], w, c] = f
        M[hi[h], di[d], w, c] = 1.0
    Co = compute_cohort(E, M)
    live = M.sum(axis=(2, 3)) > 0                     # (H, D) host-days with traffic
    idx = np.argwhere(live)
    return dict(
        edges=E[idx[:, 0], idx[:, 1]], mask=M[idx[:, 0], idx[:, 1]],
        cohort=Co[idx[:, 0], idx[:, 1]],
        host_day=[(host_prefix + hosts[a], days[b]) for a, b in idx],
    )


def build_samples(stores_and_prefixes, max_days: Optional[int] = None,
                  before_lhour: Optional[dict] = None):
    """Training samples from several corpora (e.g. baseline + live).

    stores_and_prefixes: [(CorpusStore, "base:"), (CorpusStore, "live:")]
    max_days: keep only the most recent N days of each corpus (None = all).
    before_lhour: {prefix: lhour} -- exclude windows at/after this hour
                  (the live corpus's current, incomplete day).
    Flagged windows are always excluded.
    """
    parts = []
    for store, prefix in stores_and_prefixes:
        lo = None
        hi = (before_lhour or {}).get(prefix)
        if max_days:
            last = store.db.execute("SELECT MAX(lhour) FROM windows").fetchone()[0]
            if last is not None:
                lo = (last // WINDOWS_PER_DAY - max_days + 1) * WINDOWS_PER_DAY
        g = rows_to_grid(store.rows(lhour_from=lo, lhour_to=hi), prefix)
        if len(g["host_day"]):
            parts.append(g)
    if not parts:
        return None
    return dict(
        edges=np.concatenate([p["edges"] for p in parts]),
        mask=np.concatenate([p["mask"] for p in parts]),
        cohort=np.concatenate([p["cohort"] for p in parts]),
        host_day=sum((p["host_day"] for p in parts), []),
    )


# --------------------------------------------------------------------------
# Zeek logs -> connection records (the 20-day capture after zeekify.sh)
# --------------------------------------------------------------------------
def _logs(d: str, base: str) -> list[str]:
    """conn.log, conn.log.gz, and rotated conn.<date>.log(.gz) in one folder."""
    out = []
    for p in sorted(glob.glob(os.path.join(d, base + "*"))):
        n = os.path.basename(p)
        if n == base or n.startswith(base + ".") and ".log" in n:
            out.append(p)
    return out


def zeek_dirs(root: str) -> list[str]:
    """Every folder under root that holds a conn log (zeekify.sh writes one
    folder per hourly pcap), in name order = capture order."""
    found = []
    for d, _subs, files in os.walk(root):
        if any(f == "conn" or f.startswith("conn.") and ".log" in f for f in files):
            found.append(d)
    return sorted(found)


def records_from_zeek(root: str, local_ips: Iterable[str] = (),
                      progress=None) -> Iterator[FlowRecord]:
    """Yield connection records from a tree of Zeek logs.

    host = the local endpoint (RFC1918 / ULA / link-local, or one of
    local_ips -- pass your machines' global IPv6 addresses there, or they are
    treated as external). Connections with no local endpoint are skipped.
    """
    loc = frozenset(local_ips)
    ip_host: dict[str, str] = {}          # DNS answers carry forward across hours
    dirs = zeek_dirs(root)
    if not dirs:
        raise RuntimeError(f"no conn.log found under {root}")
    for i, d in enumerate(dirs):
        uid_host: dict[str, str] = {}
        for p in _logs(d, "ssl"):
            for rec in read_zeek(p):
                sn = rec.get("server_name")
                if sn and sn != "-":
                    uid_host[rec.get("uid", "")] = sn
        for p in _logs(d, "dns"):
            for rec in read_zeek(p):
                q, ans = rec.get("query"), rec.get("answers")
                if not q or q == "-" or not ans or ans == "-":
                    continue
                items = ans if isinstance(ans, list) else str(ans).split(",")
                for a in items:
                    a = str(a).strip()
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", a) or (":" in a and re.match(r"^[0-9a-fA-F:]+$", a)):
                        ip_host[a] = q
        for p in _logs(d, "conn"):
            for rec in read_zeek(p):
                ts = _num(rec.get("ts"))
                src, dst = rec.get("id.orig_h"), rec.get("id.resp_h")
                if ts <= 0 or not src or not dst:
                    continue
                up, down = _num(rec.get("orig_bytes")), _num(rec.get("resp_bytes"))
                dur = _num(rec.get("duration"))
                if is_local(src, loc):
                    name = uid_host.get(rec.get("uid", "")) or ip_host.get(dst)
                    yield FlowRecord(src, dst, name, ts, dur, up, down)
                elif is_local(dst, loc):
                    yield FlowRecord(dst, src, ip_host.get(src), ts, dur, down, up)
        if progress:
            progress(i + 1, len(dirs), d)


def ingest(records: Iterable[FlowRecord], store: CorpusStore, lag_hours: int = 6,
           progress_every: int = 200_000) -> dict:
    """Aggregate a (roughly time-ordered) record stream into a corpus.

    Windows are written once they are `lag_hours` older than the newest
    record seen, which keeps memory bounded on a multi-week capture.
    Records arriving for an already-written window are counted as late
    (they would need the raw record set to merge correctly).
    """
    agg = WindowAggregator(store.tz)
    written = late = 0
    newest = None
    closed_upto = None
    for i, r in enumerate(records, 1):
        lh = local_hour(r.ts, store.tz)
        if closed_upto is not None and lh < closed_upto:
            late += 1
            continue
        agg.add(r)
        newest = lh if newest is None else max(newest, lh)
        if i % 5000 == 0 and newest - lag_hours > (closed_upto or -1):
            closed_upto = newest - lag_hours
            written += store.put(agg.pop_before(closed_upto))
        if progress_every and i % progress_every == 0:
            print(f"    ... {i:,} connections", flush=True)
    written += store.put(agg.pop_all())
    return {"connections": agg.records, "windows_written": written, "late_connections": late}
