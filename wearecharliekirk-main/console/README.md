# NetSentinel Console

Operator console for the NetSentinel sensor. Plain HTML, CSS and JavaScript:
no build step, no npm packages, no CDN. It works on an air-gapped machine.

It is built around PS 26145: the Overview tab shows the six threat families,
the throughput and latency the sensor is sustaining, and the five constraints
with values read from the running sensor. The full mapping is in
[`../docs/PS26145_COMPLIANCE.md`](../docs/PS26145_COMPLIANCE.md).

## Run it

1. Start the sensor from the project folder:

   ```
   python run.py
   ```

2. Open **http://localhost:8000/console/** in Chrome or Edge.

   You can also open `console/index.html` straight from disk. If the sensor is
   not on `localhost:8000`, set its address under **Settings → Sensor URL**.

3. Give it traffic from the **Ingest** tab:
   - **Replay a capture**: upload a `.pcap` / `.pcapng`, or give a path on the sensor machine.
   - **Live capture**: listens on an interface (admin rights and Npcap on Windows).
   - **Simulator**: synthetic traffic, one scenario per PS 26145 family or all six mixed. The title bar says *Simulator (synthetic)* while it runs.
   - **Throughput benchmark**: replays a synthetic or real capture through extraction and every detector as fast as one process can, and records the machine it ran on. It runs inside the sensor's process, so stop the simulator or live capture first for a clean figure.

## Tabs

| Tab | What it shows |
|---|---|
| Overview | The six PS 26145 threat families with alert counts, the detectors behind each and the last alert (click a family to see its alerts); throughput over 10 s windows with sparklines and the last benchmark; latency p50/p95/p99 per event type and detector; the five constraints with live values; C2 watch list (highest combined scores so far); most common TLS fingerprints; recent high-severity alerts; the deliverables |
| Alerts | Live alert table over the WebSocket (time, severity, class and subtype, source, destination, port, detector, score, latency, ATT&CK, flow ID, receipt; the narrowest columns give way on small screens), alerts-over-time chart (click a bar to filter to it), and a detail pane with the alert record in schema v1, the evidence, the flow, ATT&CK mapping and integrity actions |
| Hosts | Every address seen in an alert: as source, as destination, classes, highest severity, first and last seen |
| Models | Every detector, model or rule: PS family, status, sha256 digest (parameter digest for rules), alerts, p50/p95 time, and each rule's parameters; the encrypted-traffic application mix; the PS 26145 figures (`docs/figures/`) and each model's own evaluation figures |
| Inspector–Sentry | Tier 2: how the cascade works, a **Run the cascade** button that runs `tier2/demo_scenario.py` (synthetic organisation, about 30 s, needs PyTorch) with its output streamed live and its results as tiles, the headline numbers re-derived from `tier2/*.json` on every load and checked against their documented values, its charts, and what it does not claim. Tier 2 is verified standalone and not wired into the live sensor. |
| Integrity | Ledger hash chain, published checkpoints, and buttons to seal the current window or publish a checkpoint |
| Ingest | Capture replay, live capture, simulator, throughput benchmark, and the extractor counters (TLS/QUIC hellos, probe records, DNS query types) |

In the detail pane, **Verify claims**, **Replay inference** and **Show receipt**
call the sensor's `/api/integrity/...` endpoints and show exactly what they
return. Every detector, including the rule detectors, now issues a receipt.
Claims that are not implemented come back as *Unverifiable* and are shown that
way.

The confidence column is labelled with what kind of number it is: a model
probability, an anomaly score, a weighted score or a rule score
(see [`../docs/ALERT_SCHEMA.md`](../docs/ALERT_SCHEMA.md)).

## Filter syntax

Plain words match class, subtype, addresses, domain, detector, Community ID,
JA3/JA4, SNI and ATT&CK. Tokens:

| Token | Example |
|---|---|
| `class:` | `class:dga` |
| `ps:` | `ps:a` (DDoS), `ps:bd` (C2 or encrypted sessions) |
| `sev:` / `sev>=` | `sev:critical`, `sev>=high` |
| `src:` `dst:` `ip:` | `ip:192.168.1.74` |
| `port:` | `port:443` |
| `mitre:` | `mitre:T1071` |
| `model:` / `det:` | `det:dns_behaviour`, `model:vae` |

## Keyboard

`/` filter · `j` `k` or arrows to move · `Esc` close · `p` pause · `g` group repeats

## Recording a demo

- **Settings → Screen recording** masks IP addresses and domain names on screen and in the raw JSON.
- **Save** writes the alerts in view to a session file. **Open…** loads one later without the sensor running (verification buttons need the live sensor).
- **Pause** freezes the table while alerts keep arriving; resume to catch up.

## Endpoints it uses

`/api/alerts`, `/api/stats`, `/api/models`, `/api/detectors`, `/api/metrics`,
`/api/ps26145`, `/api/schema/alert`, `/api/benchmark`, `/api/extractor/stats`,
`/api/tier2`, `/api/tier2/demo`, `/api/figures`,
`/api/pcap/...`, `/api/capture/...`, `/api/simulate/...`,
`/api/integrity/...`, and the `/ws` WebSocket (alerts, stats, and one
`metrics` message per second).

## Files

`index.html`, `console.css`, `console.js`. The sensor serves this folder at
`/console/` (see the static mount in `netsentinel/main.py`).
