# Capture defect found 2026-09-06 — read before the 20th

The first ~21 hours of capture are **not usable** by the Service Category
Resolver. Three independent defects, all in the capture configuration, none in
the model code. All three are fixable in about five minutes. Everyone running a
capture (Deep + both friends) must apply all three.

Evidence: `v2\capture_audit.py`, run over 16 hourly pcaps (2.07 M packets,
17.2 h span). Re-run it yourself — it is the proof, not this document.

```powershell
cd D:\1_sih26#2\netsentinel-main\v2
.\.venv\Scripts\python.exe -m pip install dpkt
.\.venv\Scripts\python.exe capture_audit.py --dir D:\capture
```

---

## Defect 1 — snaplen 160 destroys every TLS hostname

| measured | value |
|---|---|
| TLS ClientHellos captured | 4,539 |
| records truncated by the snaplen | 4,539 (**100%**) |
| SNI hostnames recovered | **0** |

Ethernet + IP + TCP is 54 bytes. At a 160-byte snaplen the TLS record gets ~106
bytes. A ClientHello spends roughly 112 bytes on version, random, session ID,
cipher suites and compression **before** it reaches the extensions block where
`server_name` lives. The hostname is never written to disk. It is not a parsing
bug and no amount of Zeek tuning recovers it.

Same cause truncated **6,007 of 25,168** DNS packets, which is why the fallback
naming path is also degraded.

**Fixed** in `capture_service.ps1` and `start_capture.ps1`: snaplen is now
**512**, exposed as `-SnapLen` so it can be raised without editing the file.
Expect roughly 2–3× the bytes/hour. The ring self-sizes from free space at every
start, so it will tell you in `capture.log` if 13 days no longer fits.

## Defect 2 — 61% of encrypted traffic is QUIC

| measured | value |
|---|---|
| UDP/443 (QUIC) packets | 659,522 |
| TCP/443 packets | 419,402 |
| QUIC share | **61%** |

QUIC carries its SNI inside an encrypted Initial packet. Raising the snaplen
does not help; Zeek must decrypt it, and only Zeek 6+ can. Nearly two thirds of
the browsing is invisible to the resolver by construction.

**Fix — turn QUIC off in the browsers on the capture machines.** Run PowerShell
**as Administrator**:

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "QuicAllowed" -Value 0 -Type DWord
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "QuicAllowed" -Value 0 -Type DWord
```

Then fully quit and reopen the browser. Verify at `chrome://net-internals/#quic`
— the sessions list should stay empty.

## Defect 3 — DNS-over-HTTPS hides the fallback naming path

| measured | value |
|---|---|
| cleartext DNS queries parsed | 19,210 |
| of those, queries **for a DoH resolver** | 10,526 (**55%**) |
| IP → hostname pairs learned | 210 |

`chrome.cloudflare-dns.com` was the single most-queried name in the capture.
Chrome is resolving inside HTTPS, so the cleartext DNS we can see is mostly
Windows telemetry and OS services — not browsing.

**Fix — same admin PowerShell:**

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DnsOverHttpsMode" -Value "off" -Type String
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DnsOverHttpsMode" -Value "off" -Type String
```

Firefox, if used: `about:config` → `network.trr.mode` = `5`.

---

## Restart the capture after applying all three

```powershell
cd D:\1_sih26#2\netsentinel-main\v2
Stop-Process -Name dumpcap -Force -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName "NetSentinelCapture"
Start-Sleep -Seconds 90
.\install_capture_task.ps1 -Status
```

Then **verify the fix took**, an hour later, on the first rotated file:

```powershell
.\.venv\Scripts\python.exe capture_audit.py --dir D:\capture
```

`SNI hostnames extracted` must be **non-zero** and the `Unknown_External` share
must fall well below the 73.8% it is at now. If it doesn't, stop and find out
why before letting another day accumulate.

---

## Is defects 2 and 3 "changing the traffic to suit the model"?

It is a fair question and a judge may ask it. The honest answer:

Blocking QUIC at the perimeter and forcing internal DNS resolution is what
enterprises with any egress monitoring already do — it is a prerequisite for
*every* passive NIDS, not a favour to ours. A site that permits QUIC and DoH to
arbitrary resolvers has no egress visibility at all, for any product. So the
captured environment after these changes is **closer** to a monitored
enterprise than before, not further from it.

What we must not do is claim the capture is a naïve consumer laptop. It is a
laptop configured the way a monitored network configures its endpoints. Say
that plainly if asked.

## Keep the broken day

Do not delete the 21 hours captured under snaplen 160. It is the evidence for
this document, it is a genuine negative result, and the audit table is worth
showing: *we instrumented our own capture, found it was silently useless on day
one, and fixed it with thirteen days to spare.* That story is worth more to a
panel than a capture that quietly happened to work.
