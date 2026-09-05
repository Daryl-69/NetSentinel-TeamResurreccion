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
    [int]$HoursPerFile = 1
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

# ---- run -----------------------------------------------------------------
$secs = $HoursPerFile * 3600
$ringFiles = [int]([math]::Max(2, ($MaxGB * 1024) / 200))
Say ("ring {0} files x 200MB = {1} GB" -f $ringFiles, $MaxGB)
$dcArgs = @(
    "-i", $Interface,
    "-w", (Join-Path $OutDir "ns.pcap"),
    "-b", "duration:$secs",
    "-b", "files:$ringFiles",
    "-b", "filesize:200000",
    "-s", "160"
)

& $dumpcap @dcArgs
$code = $LASTEXITCODE
Say ("dumpcap exited with code {0}" -f $code)
exit $code
