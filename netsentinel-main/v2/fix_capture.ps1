<#
  fix_capture.ps1 -- repair the capture and PROVE it is repaired.

  WHAT BROKE
  ----------
  The task was installed with "-Interface 5". A dumpcap interface INDEX is a
  position in an enumeration that reshuffles whenever Windows adds or drops an
  adapter (VPN, WSL, Hyper-V, USB tethering, Wi-Fi toggling). On 12 Sep at
  12:03 index 5 was the real NIC and captured 1.6 GB in 105 minutes. At the
  13:49 restart index 5 pointed elsewhere, and every file since has been 376
  bytes -- a pcap header with zero packets.

  The correct identifier is the \Device\NPF_{GUID} name, which is stable. This
  script uses it, and then verifies that packets are actually arriving rather
  than trusting that the service started.

  RUN IT:  right-click PowerShell -> Run as Administrator, then:
             cd D:\1_sih26#2\netsentinel-main\v2
             .\fix_capture.ps1
#>
param(
    # Confirmed from inside the working pcap itself: the IDB of
    # ns_00001_20260912120336.pcap records if_name = this GUID.
    [string]$Interface = "\Device\NPF_{5F8D1592-76DE-4F55-B801-2F1CF645F564}",
    [string]$OutDir    = "D:\capture",
    [int]$MaxGB        = 40,
    [int]$VerifySeconds = 90
)
$ErrorActionPreference = "Stop"

function Say($m) { Write-Host $m }

# --- must be elevated ------------------------------------------------------
$admin = ([Security.Principal.WindowsPrincipal] `
          [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Say "This must run elevated (it re-registers a SYSTEM scheduled task)."
    Say "Right-click PowerShell -> Run as Administrator, then re-run."
    exit 1
}

# --- 1. does the adapter still exist under that name? ----------------------
Say ""
Say "1/5  checking the adapter is present"
$dc = @("C:\Program Files\Wireshark\dumpcap.exe",
        "C:\Program Files (x86)\Wireshark\dumpcap.exe") |
      Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $dc) { Say "  FATAL dumpcap.exe not found"; exit 1 }

$listing = & $dc -D 2>&1 | Out-String
if ($listing -notmatch [regex]::Escape($Interface)) {
    Say "  The stored GUID is NOT in dumpcap's list. Interfaces present:"
    Say $listing
    Say "  Pick the Wi-Fi/Ethernet line, copy its full \Device\NPF_{...} name,"
    Say "  and re-run:  .\fix_capture.ps1 -Interface `"<that name>`""
    exit 1
}
Say "  found: $Interface"

# --- 2. what is on disk right now (the failure signature) ------------------
Say ""
Say "2/5  current state"
$before = Get-ChildItem "$OutDir\ns_*.pcap" -ErrorAction SilentlyContinue |
          Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($before) {
    Say ("  newest file: {0}  {1:N0} bytes  {2}" -f `
         $before.Name, $before.Length, $before.LastWriteTime)
    if ($before.Length -lt 10000) {
        Say "  ^ under 10 KB = zero packets captured. This is the fault."
    }
}

# --- 3. reinstall against the stable name ----------------------------------
Say ""
Say "3/5  reinstalling the task against the GUID"
& "$PSScriptRoot\install_capture_task.ps1" -Uninstall
Start-Sleep -Seconds 3
& "$PSScriptRoot\install_capture_task.ps1" -Interface $Interface `
      -OutDir $OutDir -MaxGB $MaxGB

# --- 4. sleep is what produced the 3-hour gaps -----------------------------
Say ""
Say "4/5  disabling sleep so the capture is continuous"
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
powercfg /h off 2>$null
Say "  standby and hibernate off on AC"

# --- 5. PROVE it. do not trust the log line --------------------------------
Say ""
Say "5/5  verifying packets are actually arriving ($VerifySeconds s)"
Say "     (the service logged a healthy start every day for four days while"
Say "      capturing nothing -- a start message is not evidence)"
Start-Sleep -Seconds $VerifySeconds

$after = Get-ChildItem "$OutDir\ns_*.pcap" -ErrorAction SilentlyContinue |
         Sort-Object LastWriteTime -Descending | Select-Object -First 1
Say ""
if (-not $after) {
    Say "  FAIL no capture file appeared."
} elseif ($after.Length -lt 10000) {
    Say ("  FAIL newest file {0} is only {1:N0} bytes -- still zero packets." -f `
         $after.Name, $after.Length)
    Say "       The adapter name is right but no traffic is on it."
    Say "       Are you on Wi-Fi while this GUID is the Ethernet port (or vice versa)?"
    Say "       Run:  & '$dc' -D    and pick the interface you are actually using."
} else {
    Say ("  OK   {0} is {1:N0} bytes and growing." -f $after.Name, $after.Length)
    Say ""
    Say "  CAPTURE IS LIVE. Next, after about an hour, confirm what it can see:"
    Say ("    .\.venv\Scripts\python.exe capture_probe.py {0}\{1}" -f $OutDir, $after.Name)
    Say "  (name the file explicitly -- --limit sorts alphabetically and the"
    Say "   ring restarted its numbering, so it would probe the wrong era)"
}
Say ""
