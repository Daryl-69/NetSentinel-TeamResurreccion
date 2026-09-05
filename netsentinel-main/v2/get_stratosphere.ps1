# Download the Stratosphere "Normal Captures" Zeek/Bro logs - logs ONLY.
#
#   powershell -ExecutionPolicy Bypass -File get_stratosphere.ps1
#
# It never downloads .pcap / .pcapng. Those are the bulk of the dataset (GB per
# capture) and are not needed: the model consumes Zeek logs. If a capture ships
# pcap only, the script says so and skips it. Convert those yourself later with
#     zeek -r <file>.pcap
#
# Everything lands in .\data\<capture>\ . Re-running skips files already there.
#
# NOTE: pure ASCII, no here-strings. PowerShell 5.1 reads .ps1 as ANSI when
# there is no BOM, so non-ASCII characters can corrupt parsing.

$ErrorActionPreference = "Continue"
$ProgressPreference    = "SilentlyContinue"   # ~10x faster downloads on PS 5.1
Set-Location -Path $PSScriptRoot

# PowerShell 5.1 still negotiates TLS 1.0 by default. Any modern server
# refuses that and .NET reports it as the useless "Unable to connect to the
# remote server". Opt in to 1.2 before the first request.
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.SecurityProtocolType]::Tls12 -bor `
        [Net.SecurityProtocolType]::Tls11 -bor `
        [Net.SecurityProtocolType]::Tls
} catch {
    Write-Host "could not set TLS 1.2 - continuing anyway" -ForegroundColor Yellow
}

# curl.exe ships with Windows 10 1803+ and does its own TLS. When
# Invoke-WebRequest cannot connect, curl usually still can.
$script:CURL = $null
$c = Get-Command curl.exe -ErrorAction SilentlyContinue
if ($c) { $script:CURL = $c.Source }

$BASE = "https://mcfp.felk.cvut.cz/publicDatasets"

# Captures documented as shipping Bro/Zeek logs (not just pcap).
$CAPTURES = @(
    "CTU-Normal-7",
    "CTU-Normal-12",
    "CTU-Normal-6-filtered",
    "CTU-Normal-10"
)

$WANT = @("*.log", "*.log.gz", "*.labeled", "*.log.labeled")
$MAXDEPTH = 3

$script:bytes = [long]0
$script:files = 0
$script:t0 = Get-Date

function Human([long]$b) {
    if ($b -ge 1073741824) { return ("{0:N2} GB" -f ($b / 1073741824)) }
    if ($b -ge 1048576)    { return ("{0:N1} MB" -f ($b / 1048576)) }
    if ($b -ge 1024)       { return ("{0:N0} KB" -f ($b / 1024)) }
    return ("$b B")
}

function Get-Links([string]$url) {
    $html = $null
    try {
        $html = (Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 60).Content
    } catch {
        $msg = $_.Exception.Message
        if ($script:CURL) {
            $html = & $script:CURL -s -L --max-time 60 $url 2>$null
        }
        if (-not $html) {
            Write-Host ("    ! cannot list " + $url + " : " + $msg) -ForegroundColor Yellow
            return @()
        }
    }
    $out = @()
    foreach ($m in [regex]::Matches($html, 'href="([^"?]+)"')) {
        $h = $m.Groups[1].Value
        if ($h -eq "../") { continue }
        if ($h.StartsWith("/")) { continue }
        if ($h.StartsWith("http")) { continue }
        $out += $h
    }
    return ($out | Select-Object -Unique)
}

function Fetch([string]$url, [string]$dest) {
    if (Test-Path $dest) {
        $script:bytes += (Get-Item $dest).Length
        $script:files += 1
        Write-Host ("    = " + (Split-Path $dest -Leaf) + "  (already here)")
        return
    }
    $dir = Split-Path $dest
    if ($dir) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    try {
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -TimeoutSec 900
    } catch {
        if ($script:CURL) { & $script:CURL -s -L --max-time 900 -o $dest $url 2>$null }
    }
    try {
        if (-not (Test-Path $dest)) { throw "no file written" }
        $len = (Get-Item $dest).Length
        $script:bytes += $len
        $script:files += 1
        $el = (Get-Date) - $script:t0
        Write-Host ("    + {0,-32} {1,9}   [total {2}, {3:mm\:ss} elapsed]" -f `
            (Split-Path $dest -Leaf), (Human $len), (Human $script:bytes), $el)
    } catch {
        Write-Host ("    ! failed " + $url + " : " + $_.Exception.Message) -ForegroundColor Yellow
        Remove-Item $dest -ErrorAction SilentlyContinue
    }
}

function Walk([string]$url, [string]$dest, [int]$depth) {
    if ($depth -gt $MAXDEPTH) { return }
    $links = Get-Links $url
    foreach ($l in $links) {
        if ($l.EndsWith("/")) {
            Walk ($url + $l) (Join-Path $dest $l.TrimEnd("/")) ($depth + 1)
        } else {
            foreach ($w in $WANT) {
                if ($l -like $w) { Fetch ($url + $l) (Join-Path $dest $l); break }
            }
        }
    }
}

Write-Host ""
Write-Host "Stratosphere Normal Captures - Zeek/Bro logs only (no pcap)" -ForegroundColor Cyan
Write-Host ("Source: " + $BASE)
Write-Host "This is a university server in Prague. Throughput varies a lot;"
Write-Host "expect anywhere from 2 to 20 minutes. Sizes print as they arrive."
Write-Host ""

Write-Host "checking connectivity..." -NoNewline
$probe = Get-Links ($BASE + "/")
if ($probe.Count -eq 0) {
    Write-Host ""
    Write-Host ""
    Write-Host "CANNOT REACH THE SERVER." -ForegroundColor Red
    Write-Host "Tried Invoke-WebRequest and curl.exe; both failed."
    Write-Host ""
    Write-Host "Most likely, in order:"
    Write-Host "  1. Your network blocks it (campus/college firewalls often block"
    Write-Host "     university file servers). Try a phone hotspot."
    Write-Host "  2. The server is down. Open this in a browser to check:"
    Write-Host ("     " + $BASE + "/")
    Write-Host "  3. A proxy is intercepting TLS."
    Write-Host ""
    Write-Host "If the browser CAN open it, download by hand into .\data\ and run:"
    Write-Host "     .\.venv\Scripts\python.exe train_real.py --data data"
    Write-Host ""
    Write-Host "Or skip this dataset entirely - capturing your own traffic is the"
    Write-Host "only source that gives multi-day per-host baselines anyway."
    Read-Host "Press Enter to close"
    exit 1
}
Write-Host " ok"
Write-Host ""

foreach ($c in $CAPTURES) {
    Write-Host ("--- " + $c) -ForegroundColor Cyan
    $before = $script:files
    Walk ($BASE + "/" + $c + "/") (Join-Path "data" $c) 1
    if ($script:files -eq $before) {
        Write-Host "    (no Zeek logs here - probably pcap-only; skipping)" -ForegroundColor Yellow
    }
}

$el = (Get-Date) - $script:t0
Write-Host ""
Write-Host ("Downloaded {0} file(s), {1}, in {2:mm\:ss}." -f $script:files, (Human $script:bytes), $el) -ForegroundColor Green

$conn = Get-ChildItem -Path "data" -Recurse -Filter "conn.log*" -ErrorAction SilentlyContinue
if ($conn) {
    Write-Host ""
    Write-Host "conn.log files found:" -ForegroundColor Green
    foreach ($f in $conn) {
        Write-Host ("   " + $f.FullName + "  " + (Human $f.Length))
    }
    Write-Host ""
    Write-Host "Next:  .\.venv\Scripts\python.exe train_real.py --data data" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "No conn.log anywhere in .\data - these captures ship pcap only." -ForegroundColor Yellow
    Write-Host "Options:"
    Write-Host "  1. Install Zeek and convert:  zeek -r <capture>.pcap"
    Write-Host "  2. Skip this dataset and capture your own traffic instead - it is"
    Write-Host "     the only source that gives multi-day per-host baselines."
}
Read-Host "Press Enter to close"
