# capture_service.ps1 -- the thing the scheduled task actually runs.
#
# You do NOT run this by hand. Run install_capture_task.ps1 once; Windows then
# runs this at every boot and keeps it alive. See CAPTURE_RUNBOOK.md.
#
# It does two jobs dumpcap cannot do for itself across reboots:
#   1. PRUNE. dumpcap's ring buffer only deletes files from its OWN run. After
#      a reboot it starts a fresh series and never touches yesterday's files,
#      so across 12 days and a dozen reboots the folder grows without limit and
#      eventually fills the disk -- which ends the capture silently. We delete
#      anything older than -KeepDays first.
#   2. LOG. Appends a line per start to capture.log so that on the 17th you can
#      prove the capture was actually up, and see every gap.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Interface,
    [string]$OutDir = "D:\capture",
    [int]$MaxGB = 40,
    [int]$KeepDays = 13,
    [int]$HoursPerFile = 1,
    # SNAPLEN. 0 means capture the whole packet. This value has been wrong
    # twice, so the reasoning is written down. All numbers below are measured
    # by v2\capture_probe.py on our own files, not estimated.
    #
    #   160 (5-10 Sep)  50.8% of packets truncated.  0 of 442 ClientHellos
    #                   yielded a hostname. Four days of capture that cannot
    #                   feed the category resolver at all.
    #   512 (10-11 Sep) 25.1% of packets truncated.  365 of 415 ClientHellos
    #                   yielded a hostname (88.0%) -- a real improvement, and
    #                   where we would have stopped if we had not measured the
    #                   other half of the traffic.
    #                   BUT: 0 of 805 QUIC Initial packets could be read,
    #                   because RFC 9000 s14.1 REQUIRES a client Initial to be
    #                   padded to at least 1200 bytes. Measured median UDP
    #                   payload in our capture: 1,230 bytes; 90.2% exceed 512.
    #                   QUIC is ~61% of our encrypted traffic. At 512 we can
    #                   never name any of it, no matter how good the parser is.
    #   0   (now)       No truncation. Measured cost: x1.84 bytes on disk,
    #                   about 1.01 GB/day, so 12 days is ~12.1 GB against a
    #                   40 GB budget with 67 GB free. Affordable.
    #
    # We capture whole packets so we can READ HANDSHAKES (TLS ClientHello and
    # QUIC Initial). The detector never looks at application payload -- see
    # netsentinel_v2\zeek_loader.py, which consumes only flow records and
    # handshake metadata. "Full capture" is a property of the sensor, not of
    # the model. Do not describe this capture as "headers only": at ANY
    # snaplen above the header length it contains application bytes, and that
    # earlier wording in this file was simply false.
    #
    # Because raw files now contain payload, treat D:\capture as sensitive:
    # keep it local, do not commit it, and prefer extracting Zeek metadata and
    # ageing the raw pcaps out rather than archiving them indefinitely.
    # Do not change this without re-running v2\capture_probe.py.
    [int]$SnapLen = 0
)

$ErrorActionPreference = "Continue"

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

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$log = Join-Path $OutDir "capture.log"

function Say($msg) {
    $line = "{0}  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
    Add-Content -Path $log -Value $line
    Write-Host $line
}

$dumpcap = Find-Dumpcap
if (-not $dumpcap) { Say "FATAL dumpcap.exe not found"; exit 1 }

# ---- prune ---------------------------------------------------------------
$cut = (Get-Date).AddDays(-$KeepDays)
$old = Get-ChildItem -Path $OutDir -Filter "ns_*.pcap*" -File -ErrorAction SilentlyContinue |
       Where-Object { $_.LastWriteTime -lt $cut }
if ($old) {
    $mb = [math]::Round(($old | Measure-Object Length -Sum).Sum / 1MB, 0)
    $old | Remove-Item -Force -ErrorAction SilentlyContinue
    Say ("pruned {0} file(s) older than {1} days ({2} MB)" -f $old.Count, $KeepDays, $mb)
}

$have = Get-ChildItem -Path $OutDir -Filter "ns_*.pcap*" -File -ErrorAction SilentlyContinue
$haveGB = if ($have) { [math]::Round(($have | Measure-Object Length -Sum).Sum / 1GB, 2) } else { 0 }
$drive = (Get-Item $OutDir).PSDrive.Name
$free = [math]::Round((Get-PSDrive $drive).Free / 1GB, 1)
Say ("start  iface={0} files={1} onDisk={2}GB free={3}GB" -f $Interface, $have.Count, $haveGB, $free)

if ($free -lt 5) {
    Say "FATAL less than 5 GB free -- refusing to start rather than fill the disk"
    exit 1
}

# ---- size the ring to the disk, not to the request -----------------------
# dumpcap rotates only once the ring reaches its file COUNT, so a ring sized
# larger than the free space fills the disk before it ever rotates -- on about
# day 9 of an unattended run, which is the worst possible time to find out.
# Recompute every start: free space changes, and a reboot re-enters here.
$reserve = 8
$budget = [math]::Floor($free - $reserve)
if ($budget -lt $MaxGB) {
    Say ("ring capped to {0} GB (asked {1}, only {2} GB free, {3} GB reserved)" -f `
         $budget, $MaxGB, $free, $reserve)
    $MaxGB = $budget
}
if ($MaxGB -lt 3) {
    Say "FATAL less than 3 GB usable after reserve -- free some space"
    exit 1
}

# ---- size the ring in TIME, not gigabytes --------------------------------
# dumpcap rotates on whichever comes first: the hour, or the size limit. At a
# laptop's real rate an hourly file is ~10-30 MB, nowhere near the 200 MB cap,
# so a ring sized "40 GB / 200 MB = 205 files" actually retains 205 HOURS --
# 8.5 days. The oldest files then start disappearing on day 9 of a 12-day
# capture and nobody notices until the 17th. What we need to retain is DAYS,
# so derive the file count from KeepDays and shrink the per-file cap to fit
# the disk budget instead.
$secs = $HoursPerFile * 3600
$ringFiles = [int][math]::Ceiling(($KeepDays * 24.0) / $HoursPerFile)
if ($ringFiles -lt 2) { $ringFiles = 2 }

$perFileMB = [int][math]::Floor(($MaxGB * 1024.0) / $ringFiles)
if ($perFileMB -gt 200) { $perFileMB = 200 }      # no point in bigger files
if ($perFileMB -lt 40) {
    # Not enough budget for the full window even at small files: keep the file
    # size sane and shorten the window, loudly, rather than silently thrashing.
    $perFileMB = 40
    $ringFiles = [int][math]::Max(2, [math]::Floor(($MaxGB * 1024.0) / $perFileMB))
    Say ("WARNING retention shortened to {0:N1} days -- only {1} GB of budget" -f `
         ($ringFiles * $HoursPerFile / 24.0), $MaxGB)
}
Say ("ring {0} files x {1}MB = {2:N1} days retained, {3:N1} GB worst case" -f `
     $ringFiles, $perFileMB, ($ringFiles * $HoursPerFile / 24.0), `
     ($ringFiles * $perFileMB / 1024.0))
$dcArgs = @(
    "-i", $Interface,
    "-w", (Join-Path $OutDir "ns.pcap"),
    "-b", "duration:$secs",
    "-b", "files:$ringFiles",
    "-b", ("filesize:" + ($perFileMB * 1000)),
    "-s", "$SnapLen"
)
if ($SnapLen -eq 0) {
    Say "snaplen 0 (whole packet) -- measured x1.84 bytes vs 512, ~1.01 GB/day"
    Say "  handshakes readable: TLS ClientHello AND QUIC Initial (>=1200 B, RFC 9000)"
    Say "  raw files now contain payload -- keep this directory local and private"
} else {
    Say ("snaplen {0} bytes -- WARNING: below 1200 no QUIC Initial can be read" -f $SnapLen)
}

& $dumpcap @dcArgs
$code = $LASTEXITCODE
Say ("dumpcap exited with code {0}" -f $code)
exit $code
