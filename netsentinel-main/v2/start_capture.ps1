# start_capture.ps1 -- begin the 12-day benign capture. Run as Administrator.
#
# WHY THIS EXISTS
#   LANL cannot test NetSentinel's actual claim: it has zero egress traffic, so
#   there are no trusted-SaaS destinations to sequence (ARCHITECTURE_V2 section
#   5c). The only data that can test it is traffic from machines that browse
#   the real internet -- ours. This is the critical path to the 20th and the
#   only task gated on wall-clock rather than effort, so it starts TODAY.
#
# WHAT IT DOES
#   Runs dumpcap (ships with Wireshark) in a ring buffer: one file per hour,
#   capped total disk. Headers only by default -- no payload is written, which
#   keeps the files small and keeps this defensible on a shared network.
#   Zeek then reads these files later; see zeekify.sh.
#
# PERMISSION -- read this before running
#   Capturing on a network you do not own can be a policy or legal problem.
#   Capture on YOUR OWN machines. If you want the college network, ask the
#   network admin first and get it in writing. Six laptops running this for
#   twelve days is plenty of data and needs nobody's permission but yours.
#
# USAGE
#   .\start_capture.ps1                 # list interfaces, then pick one
#   .\start_capture.ps1 -Interface 5
#   .\start_capture.ps1 -Interface 5 -OutDir D:\capture -MaxGB 40

[CmdletBinding()]
param(
    [string]$Interface = "",
    [string]$OutDir = "D:\capture",
    [int]$MaxGB = 40,
    [int]$HoursPerFile = 1,
    [switch]$FullPayload
)

$ErrorActionPreference = "Stop"

function Test-Npcap {
    # dumpcap without the Npcap driver lists NO interfaces and prints a wpcap
    # error, which reads like "the script found nothing" rather than "the
    # driver is missing". winget's silent Wireshark install does not run the
    # bundled Npcap sub-installer, so this is the normal first failure.
    param([string]$Dumpcap)
    $out = & $Dumpcap -D 2>&1 | Out-String
    if ($out -match "Npcap|wpcap|WinPcap" -or [string]::IsNullOrWhiteSpace($out)) {
        Write-Host ""
        Write-Host "Npcap is not installed -- dumpcap cannot see any interface."
        Write-Host ""
        Write-Host "Wireshark installed, but winget skips the Npcap driver that"
        Write-Host "actually does the capturing. Install it yourself:"
        Write-Host ""
        Write-Host "  1. If you have NOT rebooted since installing Wireshark,"
        Write-Host "     reboot first and re-run this script -- that alone may fix it."
        Write-Host "  2. Otherwise download Npcap from   https://npcap.com"
        Write-Host "     Run the installer, accept the defaults, then REBOOT."
        Write-Host ""
        Write-Host "Do not use 'winget install Insecure.Npcap' -- winget carries"
        Write-Host "Npcap 0.86 from 2019, which will not work on Windows 11."
        Write-Host ""
        Write-Host "Then: .\install_capture_task.ps1     (to list interfaces)"
        return $false
    }
    return $true
}

function Assert-InterfaceGiven {
    # Catches the literal placeholder being pasted in. PowerShell parses "<"
    # as a reserved operator, so "-Interface <n>" dies with an unhelpful
    # "The '<' operator is reserved for future use."
    param([string]$Value)
    if ($Value -match "^[<{\[]" -or $Value -eq "n" -or $Value -eq "number") {
        Write-Host "'-Interface $Value' is the placeholder, not a value."
        Write-Host "Run this script with no arguments to see the numbered list,"
        Write-Host "then pass that number, e.g.  -Interface 5"
        exit 1
    }
}


function Find-Dumpcap {
    $candidates = @(
        "C:\Program Files\Wireshark\dumpcap.exe",
        "C:\Program Files (x86)\Wireshark\dumpcap.exe"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    $cmd = Get-Command dumpcap.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

$dumpcap = Find-Dumpcap
if (-not $dumpcap) {
    Write-Host "dumpcap.exe not found."
    Write-Host ""
    Write-Host "Install Wireshark (it bundles dumpcap and the npcap driver):"
    Write-Host "    winget install WiresharkFoundation.Wireshark"
    Write-Host ""
    Write-Host "Tick 'Install Npcap' during setup, then re-run this script."
    exit 1
}
Write-Host "dumpcap: $dumpcap"

if (-not (Test-Npcap $dumpcap)) { exit 1 }

if (-not $Interface) {
    Write-Host ""
    Write-Host "Available interfaces:"
    & $dumpcap -D
    Write-Host ""
    Write-Host "Pick the number of the interface carrying your normal traffic"
    Write-Host "(usually Wi-Fi or Ethernet, NOT Loopback or a VM adapter), then:"
    Write-Host "    .\start_capture.ps1 -Interface <number>"
    exit 0
}

Assert-InterfaceGiven $Interface

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

# Free-space guard. Filling the system disk mid-capture loses the whole run.
$drive = (Get-Item $OutDir).PSDrive.Name
$free = [math]::Round((Get-PSDrive $drive).Free / 1GB, 1)
Write-Host "output : $OutDir  (${free} GB free on ${drive}:)"
if ($free -lt ($MaxGB + 5)) {
    Write-Host ""
    Write-Host "Only ${free} GB free but -MaxGB is $MaxGB. Lower -MaxGB or pick"
    Write-Host "another drive. Stopping rather than filling the disk."
    exit 1
}

# Ring buffer: files:0 = never stop rotating, so the capture survives 12 days
# and old files roll off once MaxGB is reached.
$secs = $HoursPerFile * 3600
$ringFiles = [int]([math]::Max(2, ($MaxGB * 1024) / 200))   # ~200 MB per file

$dcArgs = @(
    "-i", $Interface,
    "-w", (Join-Path $OutDir "ns.pcap"),
    "-b", "duration:$secs",
    "-b", "files:$ringFiles",
    "-b", "filesize:200000"
)
# Whole packets. Measured with v2\capture_probe.py on our own capture:
#   snaplen 160 -> 0 of 442 TLS ClientHellos named (50.8% of packets cut)
#   snaplen 512 -> 365 of 415 named (88.0%), but 0 of 805 QUIC Initials
#                  readable: RFC 9000 s14.1 pads client Initials to >=1200
#                  bytes, our measured median is 1,230, and QUIC is ~61% of
#                  encrypted traffic here. 512 can never name any of it.
#   snaplen 0   -> nothing truncated. Cost x1.84 bytes, ~1.01 GB/day,
#                  ~12.1 GB for 12 days against a 40 GB budget.
# The sensor keeps whole packets so it can read HANDSHAKES. The detector
# reads flow records and handshake metadata only -- it never consumes
# application payload. Those are two different statements and only the
# second one is about the model.
$dcArgs += @("-s", "0")

Write-Host ""
Write-Host "Starting capture."
Write-Host "  one file per $HoursPerFile h, ring of $ringFiles files, ~$MaxGB GB cap"
Write-Host "  whole packets (snaplen 0) -- required to read QUIC Initials"
Write-Host "  these files contain application payload. Keep them local and private."
Write-Host "  the DETECTOR still reads only flow records and handshake metadata."
Write-Host ""
Write-Host "Leave this window open. Ctrl+C stops it."
Write-Host "Target: 12 days, so it must still be running on the 17th."
Write-Host "Check on it daily -- a capture nobody looked at is a capture that died on day 2."
Write-Host ""

& $dumpcap @dcArgs
