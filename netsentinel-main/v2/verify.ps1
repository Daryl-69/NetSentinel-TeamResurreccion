# NetSentinel V2 - one-shot verification.
#
#   Right-click this file -> "Run with PowerShell"
#   ...or from a terminal in this folder:
#       powershell -ExecutionPolicy Bypass -File verify.ps1
#
# Everything stays in this folder: it creates .venv\ here and writes
# verify_log.txt here. Nothing is installed system-wide. To undo it
# completely, delete the .venv folder.
#
# NOTE: this file is deliberately pure ASCII and contains no here-strings.
# PowerShell 5.1 reads .ps1 as ANSI when there is no BOM, so a stray em-dash
# is enough to corrupt parsing.

$ErrorActionPreference = "Continue"
$ProgressPreference    = "SilentlyContinue"
Set-Location -Path $PSScriptRoot

$LOG = Join-Path $PSScriptRoot "verify_log.txt"
Set-Content -Path $LOG -Value "" -Encoding UTF8

function Say([string]$m) {
    Write-Host $m
    Add-Content -Path $LOG -Value $m -Encoding UTF8
}

function Run([string]$exe, [string[]]$argv, [string]$label) {
    Say ""
    Say ("=== " + $label + " ===")
    Say ("> " + $exe + " " + ($argv -join " "))
    # Tee-Object PASSES THROUGH, so without Out-Host the command's stdout
    # becomes part of this function's return value and $rc is an array,
    # which makes every `if ($rc -ne 0)` check meaningless.
    & $exe @argv 2>&1 | Tee-Object -FilePath $LOG -Append | Out-Host
    $code = $LASTEXITCODE
    Say ("[exit " + $code + "]")
    return $code
}

Say "NetSentinel V2 verification"
Say ("started  : " + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))
Say ("folder   : " + $PSScriptRoot)
Say ("os       : " + [System.Environment]::OSVersion.VersionString)
Say ("cpu cores: " + $env:NUMBER_OF_PROCESSORS)

# ------------------------------------------------------------- find python
$PY = $null
$PYARGS = @()
if (Get-Command "py" -ErrorAction SilentlyContinue) {
    & py -3 -V 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { $PY = "py"; $PYARGS = @("-3") }
}
if (-not $PY) {
    foreach ($cand in @("python", "python3")) {
        if (Get-Command $cand -ErrorAction SilentlyContinue) {
            & $cand -V 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { $PY = $cand; $PYARGS = @(); break }
        }
    }
}
if (-not $PY) {
    Say ""
    Say "FAILED: no Python found on PATH."
    Say "Install Python 3.10-3.12 from https://www.python.org/downloads/"
    Say "and TICK 'Add python.exe to PATH' in the installer, then re-run."
    Say "=== RESULT: BLOCKED (no python) ==="
    Read-Host "Press Enter to close"
    exit 1
}
Say ("python   : " + $PY + " " + ($PYARGS -join " "))

# ------------------------------------------------------------- venv
$VENV_PY = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $VENV_PY)) {
    Run $PY ($PYARGS + @("-m", "venv", ".venv")) "create virtualenv" | Out-Null
}
if (-not (Test-Path $VENV_PY)) {
    Say ""
    Say "FAILED: could not create .venv"
    Say "=== RESULT: BLOCKED (venv) ==="
    Read-Host "Press Enter to close"
    exit 1
}
Say ("venv     : " + $VENV_PY)

# ------------------------------------------------------------- deps
# CPU-only torch: about 200 MB instead of the ~2.5 GB CUDA build.
# This model never needs a GPU.
Run $VENV_PY @("-m", "pip", "install", "--quiet", "--upgrade", "pip") "upgrade pip" | Out-Null

$rc = Run $VENV_PY @("-m", "pip", "install", "--quiet",
                     "--index-url", "https://download.pytorch.org/whl/cpu",
                     "torch") "install torch (CPU build, ~200MB)"
if ($rc -ne 0) {
    Say "CPU-index install failed; retrying from the default index (bigger download)."
    Run $VENV_PY @("-m", "pip", "install", "--quiet", "torch") "install torch (fallback)" | Out-Null
}

Run $VENV_PY @("-m", "pip", "install", "--quiet",
               "numpy", "scipy", "scikit-learn", "matplotlib") "install numpy/scipy/sklearn/matplotlib" | Out-Null

Run $VENV_PY @("-c", "import torch,numpy,scipy,sklearn;print('torch',torch.__version__);print('numpy',numpy.__version__);print('sklearn',sklearn.__version__);print('cuda_available',torch.cuda.is_available())") "versions" | Out-Null

# ------------------------------------------------------------- smoke test
$rc = Run $VENV_PY @("run_experiment.py", "--seeds", "1", "--hosts", "60", "--days", "16",
                     "--epochs-teacher", "3", "--epochs-student", "3",
                     "--out", "smoke.json") "SMOKE TEST (about 30s)"
if ($rc -ne 0) {
    Say ""
    Say "=== RESULT: SMOKE TEST FAILED - see the traceback above ==="
    Read-Host "Press Enter to close"
    exit 1
}

# ------------------------------------------------------------- main run
Say ""
Say "Main run: 3 seeds x 300 hosts x 24 days."
Say "Expect roughly 2-6 minutes per seed. Leave it alone until it finishes."
Run $VENV_PY @("run_experiment.py", "--seeds", "3", "--hosts", "300", "--days", "24",
               "--epochs-teacher", "12", "--epochs-student", "14",
               "--out", "results.json") "MAIN EXPERIMENT" | Out-Null

Run $VENV_PY @("make_charts.py", "results.json") "charts" | Out-Null

# ------------------------------------------------------------- verdict
Run $VENV_PY @("check_results.py", "results.json") "COMPARISON AGAINST REFERENCE" | Out-Null

Say ""
Say ("finished : " + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))
Say ("log file : " + $LOG)
Write-Host ""
Write-Host "Done. Send verify_log.txt to Claude." -ForegroundColor Green
Read-Host "Press Enter to close"
