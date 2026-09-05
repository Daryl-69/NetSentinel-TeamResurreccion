# Fetch REAL, human-generated network traffic as Zeek logs.
#
#   powershell -ExecutionPolicy Bypass -File get_data.ps1
#   powershell -ExecutionPolicy Bypass -File get_data.ps1 -Source stratosphere
#
# Sources, in order of how likely they are to be reachable from a college
# network. The default is GitHub because campus firewalls almost never block
# it, and the Stratosphere host already failed for you.
#
#   github       brimdata/zed-sample-data - Zeek logs from the WRCCDC 2018
#                collegiate cyber-defence competition. REAL humans (blue teams
#                defending, red teams attacking) on a real network. Includes
#                ssl/dns logs, so the Service Category Resolver has hostnames
#                to work with. This is the one to try first.
#
#   stratosphere CTU Normal Captures. Real home/university hosts. Currently
#                unreachable from your network.
#
# ASCII only, no here-strings: PowerShell 5.1 reads .ps1 as ANSI without a BOM.

param(
    [ValidateSet("github", "stratosphere")]
    [string]$Source = "github"
)

$ErrorActionPreference = "Continue"
$ProgressPreference    = "SilentlyContinue"
Set-Location -Path $PSScriptRoot

try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.SecurityProtocolType]::Tls12 -bor `
        [Net.SecurityProtocolType]::Tls11 -bor `
        [Net.SecurityProtocolType]::Tls
} catch { }

function Human([long]$b) {
    if ($b -ge 1073741824) { return ("{0:N2} GB" -f ($b / 1073741824)) }
    if ($b -ge 1048576)    { return ("{0:N1} MB" -f ($b / 1048576)) }
    if ($b -ge 1024)       { return ("{0:N0} KB" -f ($b / 1024)) }
    return ("$b B")
}

function Report-Data {
    $conn = Get-ChildItem -Path "data" -Recurse -Filter "conn.log*" -ErrorAction SilentlyContinue
    $ssl  = Get-ChildItem -Path "data" -Recurse -Filter "ssl.log*"  -ErrorAction SilentlyContinue
    $dns  = Get-ChildItem -Path "data" -Recurse -Filter "dns.log*"  -ErrorAction SilentlyContinue
    Write-Host ""
    if (-not $conn) {
        Write-Host "No conn.log found under .\data - nothing usable was fetched." -ForegroundColor Yellow
        return $false
    }
    Write-Host "Usable Zeek logs:" -ForegroundColor Green
    foreach ($f in $conn) { Write-Host ("   conn  " + $f.FullName + "  " + (Human $f.Length)) }
    foreach ($f in $ssl)  { Write-Host ("   ssl   " + $f.FullName + "  " + (Human $f.Length)) }
    foreach ($f in $dns)  { Write-Host ("   dns   " + $f.FullName + "  " + (Human $f.Length)) }
    if (-not $ssl -and -not $dns) {
        Write-Host ""
        Write-Host "NOTE: no ssl.log or dns.log. Without SNI or DNS names the Service" -ForegroundColor Yellow
        Write-Host "Category Resolver has nothing to categorise and every destination" -ForegroundColor Yellow
        Write-Host "becomes Unknown_External. train_real.py will say so loudly." -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "Next:  .\.venv\Scripts\python.exe train_real.py --data data" -ForegroundColor Green
    return $true
}

# ---------------------------------------------------------------- github
if ($Source -eq "github") {
    $REPO = "https://github.com/brimdata/zed-sample-data"
    Write-Host ""
    Write-Host "Source: WRCCDC 2018 via brimdata/zed-sample-data" -ForegroundColor Cyan
    Write-Host "Real traffic from a collegiate cyber-defence competition, as Zeek logs."
    Write-Host "Roughly 100-200 MB. GitHub is rarely blocked on campus networks."
    Write-Host ""

    New-Item -ItemType Directory -Force -Path "data" | Out-Null
    $dest = "data\zed-sample-data"

    if (Test-Path $dest) {
        Write-Host "already present at $dest - skipping download"
    } elseif (Get-Command git -ErrorAction SilentlyContinue) {
        Write-Host "cloning with git (shallow)..."
        & git clone --depth 1 $REPO $dest
        if ($LASTEXITCODE -ne 0) { Write-Host "git clone failed" -ForegroundColor Yellow }
    } else {
        Write-Host "git not found; downloading the tarball instead..."
        $tgz = "data\zed-sample-data.tar.gz"
        $url = "https://codeload.github.com/brimdata/zed-sample-data/tar.gz/refs/heads/main"
        try {
            Invoke-WebRequest -Uri $url -OutFile $tgz -UseBasicParsing -TimeoutSec 900
        } catch {
            $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
            if ($curl) { & $curl.Source -sS -L --max-time 900 -o $tgz $url }
        }
        if (Test-Path $tgz) {
            Write-Host ("downloaded " + (Human (Get-Item $tgz).Length) + ", extracting...")
            if (Get-Command tar -ErrorAction SilentlyContinue) {
                & tar -xzf $tgz -C "data"
                Remove-Item $tgz -ErrorAction SilentlyContinue
            } else {
                Write-Host "tar.exe not found - extract $tgz by hand into .\data\" -ForegroundColor Yellow
            }
        } else {
            Write-Host "could not download the tarball" -ForegroundColor Red
        }
    }

    # The repo ships several encodings of the same logs. We want the plain
    # Zeek TSV ones; delete the rest so train_real.py does not read the same
    # traffic four times and think it has four networks.
    foreach ($d in @("zeek-ndjson", "sup", "bsup", "zeek-json")) {
        $p = Join-Path $dest $d
        if (Test-Path $p) {
            Write-Host ("  removing duplicate encoding: " + $d)
            Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not (Report-Data)) {
        Write-Host "Try:  powershell -ExecutionPolicy Bypass -File get_data.ps1 -Source stratosphere"
    }
    Read-Host "Press Enter to close"
    exit 0
}

# ---------------------------------------------------------------- stratosphere
Write-Host ""
Write-Host "Source: Stratosphere CTU Normal Captures" -ForegroundColor Cyan
Write-Host "This host was unreachable from your network last time. Trying anyway."
Write-Host ""
& powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "get_stratosphere.ps1")
