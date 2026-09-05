# install_capture_task.ps1 -- register the capture as a Windows scheduled task.
# Run ONCE, as Administrator. After this you never think about it again:
# it starts at boot, restarts if it dies, and survives you closing every window.
#
#   .\install_capture_task.ps1 -Interface 5
#   .\install_capture_task.ps1 -Interface 5 -OutDir D:\capture -MaxGB 40
#
# Check it:    .\install_capture_task.ps1 -Status
# Remove it:   .\install_capture_task.ps1 -Uninstall
#
# NOTE ON SLEEP: a scheduled task cannot capture traffic while the laptop is
# asleep, because the NIC is off. That is fine and expected -- the gaps are
# simply hours with no traffic, and the loader treats an empty window as empty
# rather than as anomalous. Do NOT leave the laptop awake for twelve days on
# our account. Just do not sit on the capture for a week and then wonder why
# you have four days of data: check capture.log.

[CmdletBinding()]
param(
    [string]$Interface = "",
    [string]$OutDir = "D:\capture",
    [int]$MaxGB = 40,
    [int]$KeepDays = 13,
    [switch]$Uninstall,
    [switch]$Status
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

$TaskName = "NetSentinelCapture"

$admin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Status) {
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $t) { Write-Host "Task '$TaskName' is NOT installed."; exit 0 }
    $i = Get-ScheduledTaskInfo -TaskName $TaskName
    Write-Host ("Task    : {0}" -f $t.State)
    Write-Host ("Last run: {0}  result {1}" -f $i.LastRunTime, $i.LastTaskResult)
    $dc = Get-Process dumpcap -ErrorAction SilentlyContinue
    Write-Host ("dumpcap : {0}" -f $(if ($dc) { "RUNNING (pid $($dc.Id))" } else { "not running" }))
    $log = Join-Path $OutDir "capture.log"
    if (Test-Path $log) {
        Write-Host ""
        Write-Host "last 8 lines of capture.log:"
        Get-Content $log -Tail 8 | ForEach-Object { Write-Host "  $_" }
    }
    $f = Get-ChildItem -Path $OutDir -Filter "ns_*.pcap*" -File -ErrorAction SilentlyContinue
    if ($f) {
        $gb = [math]::Round(($f | Measure-Object Length -Sum).Sum / 1GB, 2)
        $span = ((Get-Date) - ($f | Sort-Object LastWriteTime | Select-Object -First 1).LastWriteTime).TotalDays
        Write-Host ""
        Write-Host ("files   : {0}  ({1} GB, oldest {2:N1} days ago)" -f $f.Count, $gb, $span)
        Write-Host ("newest  : {0}" -f ($f | Sort-Object LastWriteTime | Select-Object -Last 1).LastWriteTime)
    } else {
        Write-Host ""
        Write-Host "files   : NONE -- the capture is not producing anything. Check capture.log."
    }
    exit 0
}

if (-not $admin) {
    Write-Host "Run this in an Administrator PowerShell (right-click > Run as administrator)."
    exit 1
}

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Get-Process dumpcap -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host "Removed task '$TaskName' and stopped dumpcap."
    exit 0
}

if ($Interface) { Assert-InterfaceGiven $Interface }

if (-not $Interface) {
    Write-Host "Which interface? Listing them:"
    Write-Host ""
    & "$PSScriptRoot\start_capture.ps1"
    exit 0
}

$svc = Join-Path $PSScriptRoot "capture_service.ps1"
if (-not (Test-Path $svc)) { Write-Host "capture_service.ps1 not found next to this script."; exit 1 }

# QUOTE the interface. A device NAME looks like \Device\NPF_{GUID} and those
# curly braces are script-block syntax to the child PowerShell if left bare.
# Names are strongly preferred over dumpcap's index: the index is positional,
# and Windows adds and removes "Local Area Connection*" pseudo-adapters, so
# the number that means Wi-Fi today can mean something else after a reboot --
# and the task would then quietly capture the wrong adapter for twelve days.
$argline = ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" ' +
            '-Interface "{1}" -OutDir "{2}" -MaxGB {3} -KeepDays {4}') -f `
           $svc, $Interface, $OutDir, $MaxGB, $KeepDays

if ($Interface -match '^\d+$') {
    Write-Host ""
    Write-Host "NOTE: you passed the index $Interface, not a device name."
    Write-Host "Indexes shift when Windows adds or drops pseudo-adapters, so"
    Write-Host "after a reboot this task may capture a different adapter."
    Write-Host "Prefer the full \Device\NPF_{...} name from the listing."
    Write-Host ""
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argline
$trigger = New-ScheduledTaskTrigger -AtStartup
# SYSTEM so it runs with no one logged in; Highest because packet capture needs it.
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount `
             -RunLevel Highest
# RestartCount/Interval is what makes this survive dumpcap dying; ExecutionTimeLimit 0
# stops Windows from killing a task that is meant to run for twelve days.
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries -StartWhenAvailable `
            -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
            -ExecutionTimeLimit (New-TimeSpan -Seconds 0)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 4

Write-Host "Installed and started '$TaskName'."
Write-Host ""
Write-Host "  interface : $Interface"
Write-Host "  output    : $OutDir   (prunes files older than $KeepDays days)"
Write-Host ""
Write-Host "It now starts at every boot and restarts itself if it dies."
Write-Host "You do NOT need to start or stop anything when you turn the laptop on or off."
Write-Host ""
Write-Host "Check on it any time with:"
Write-Host "    .\install_capture_task.ps1 -Status"
Write-Host ""
Write-Host "Stop it for good on the 17th with:"
Write-Host "    .\install_capture_task.ps1 -Uninstall"
