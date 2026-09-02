#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets up the LocalScan malware analysis sandbox on a fresh Windows VM.

.DESCRIPTION
    1.  Verifies Windows Defender is running
    2.  Installs Python 3 (via winget, then pip)
    3.  Creates C:\MalwareAnalysis directory layout
    4.  Copies all source files (including the defender_check package)
    5.  Installs pip dependencies
    6.  Configures Windows Defender for dual-mode operation:
          Sandbox mode    -- real-time protection ON (captures runtime alerts)
          Signature mode  -- dedicated tmp\ excluded so slice files are never
                            quarantined during binary search
    7.  Enables process-creation audit policy (Event ID 4688)
    8.  Installs Sysmon (optional, improves telemetry)
    9.  Opens firewall for port 5000
    10. Creates a launcher script (sets TMPDIR so Python uses the excluded dir)
    11. Creates a Scheduled Task that runs the server at login
    12. Adds a desktop shortcut
    13. Launches the server immediately

.NOTES
    Run from the folder containing app.py, monitor.py,
    requirements.txt, templates\ and defender_check\.

    Tested on Windows 10 / 11 (x64).
    For an isolated VirtualBox VM ONLY -- do NOT run on a production machine.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
function Write-Step([string]$msg) {
    Write-Host ""
    Write-Host "[+] $msg" -ForegroundColor Cyan
}
function Write-Ok([string]$msg) {
    Write-Host "    [OK] $msg" -ForegroundColor Green
}
function Write-Warn([string]$msg) {
    Write-Host "    [!!] $msg" -ForegroundColor Yellow
}
function Write-Err([string]$msg) {
    Write-Host "    [XX] $msg" -ForegroundColor Red
}

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallDir = "C:\MalwareAnalysis"
$VenvDir    = "$InstallDir\.venv"
$AppPython  = "$VenvDir\Scripts\python.exe"
$PythonExe  = $null

# ---------------------------------------------------------------------------
# 1. Verify Windows Defender is running
# ---------------------------------------------------------------------------
Write-Step "Verifying Windows Defender service"

$defSvc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
if (-not $defSvc -or $defSvc.Status -ne "Running") {
    Write-Err "Windows Defender (WinDefend) is not running."
    Write-Err "LocalScan requires Defender enabled. Enable it and re-run setup."
    exit 1
}
Write-Ok "WinDefend service is running"

# ---------------------------------------------------------------------------
# 2. Python
# ---------------------------------------------------------------------------
Write-Step "Checking for Python 3.10+"

$existing = Get-Command python -ErrorAction SilentlyContinue
if ($existing) {
    $ver = & python --version 2>&1
    if ($ver -match "3\.(\d+)" -and [int]$Matches[1] -ge 10) {
        $PythonExe = $existing.Source
        Write-Ok "Found $ver at $PythonExe"
    }
}

if (-not $PythonExe) {
    Write-Warn "Python 3.10+ not found. Attempting install via winget..."
    try {
        winget install --id Python.Python.3.11 --silent --accept-source-agreements --accept-package-agreements
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("Path","User")
        $PythonExe = (Get-Command python -ErrorAction Stop).Source
        Write-Ok "Python installed: $PythonExe"
    }
    catch {
        Write-Err "winget install failed: $_"
        Write-Host "    Please install Python 3.10+ from https://python.org then re-run." -ForegroundColor Yellow
        exit 1
    }
}

# ---------------------------------------------------------------------------
# 3. Create directory layout
# ---------------------------------------------------------------------------
Write-Step "Creating directory layout at $InstallDir"

foreach ($dir in @(
    $InstallDir,
    "$InstallDir\uploads",
    "$InstallDir\results",
    "$InstallDir\templates",
    "$InstallDir\logs",
    "$InstallDir\tmp",
    "$InstallDir\defender_check"
)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}
Write-Ok "Directories created (including tmp\ for signature analysis)"

# ---------------------------------------------------------------------------
# 4. Copy source files
# ---------------------------------------------------------------------------
Write-Step "Copying source files from $ScriptDir"

# Top-level Python files
foreach ($f in @("app.py", "monitor.py", "requirements.txt")) {
    $src = Join-Path $ScriptDir $f
    if (Test-Path $src) {
        Copy-Item $src $InstallDir -Force
        Write-Ok "Copied $f"
    }
    else {
        Write-Err "Missing required file: $f  (looked in $ScriptDir)"
        exit 1
    }
}

# templates\
$tplSrc = Join-Path $ScriptDir "templates"
if (Test-Path $tplSrc) {
    Copy-Item "$tplSrc\*" "$InstallDir\templates\" -Recurse -Force
    Write-Ok "Copied templates\"
}
else {
    Write-Err "templates\ folder not found in $ScriptDir"
    exit 1
}

# defender_check\ package
$dcSrc = Join-Path $ScriptDir "defender_check"
if (Test-Path $dcSrc) {
    Copy-Item "$dcSrc\*" "$InstallDir\defender_check\" -Recurse -Force
    Write-Ok "Copied defender_check\ package"
}
else {
    Write-Err "defender_check\ folder not found in $ScriptDir"
    exit 1
}

# ---------------------------------------------------------------------------
# 5. Private Python environment and dependencies
# ---------------------------------------------------------------------------
Write-Step "Creating private Python environment"

if (-not (Test-Path $AppPython)) {
    & $PythonExe -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Could not create the Python environment"
        exit 1
    }
}
Write-Ok "Application environment: $VenvDir"

Write-Step "Installing Python dependencies"

& $AppPython -m pip install --upgrade pip --quiet
& $AppPython -m pip install -r "$InstallDir\requirements.txt" --quiet

if ($LASTEXITCODE -ne 0) {
    Write-Err "pip install failed"
    exit 1
}
Write-Ok "Installed: flask, psutil, pefile, tqdm"

# ---------------------------------------------------------------------------
# 5. Windows Defender -- dual-mode configuration
#
# Sandbox mode needs real-time protection ON:
#   Defender firing against a live sample is the primary signal we are
#   measuring. Turning real-time off would silence the runtime alerts that
#   drive the risk score.
#
# Signature mode needs the tmp\ dir excluded:
#   DefenderCheck's binary search writes and reads hundreds of partial file
#   slices into a temp directory. With real-time protection scanning those
#   files, Defender can quarantine a slice the instant it is written -- before
#   MpCmdRun even gets to scan it -- causing false "no threat" results and
#   corrupting the binary search. Excluding just the tmp\ directory lets
#   real-time protection stay fully on everywhere else.
# ---------------------------------------------------------------------------
Write-Step "Configuring Windows Defender for dual-mode operation"

# -- Real-time protection: ON --
# Do not disable this. Sandbox mode depends on it.
Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
Write-Ok "Real-time protection            : ON  (required for sandbox mode)"

# -- Behavioral monitoring: ON --
# Catches in-memory and fileless techniques during sandbox execution.
Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
Write-Ok "Behavioral monitoring           : ON"

# -- Script scanning: ON --
# Catches PowerShell / VBScript / JS payloads executed by samples.
Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
Write-Ok "Script scanning                 : ON"

# -- Cloud protection / MAPS: OFF --
# Samples must never be uploaded to Microsoft.
Set-MpPreference -MAPSReporting           Disabled  -ErrorAction SilentlyContinue
Set-MpPreference -SubmitSamplesConsent    NeverSend -ErrorAction SilentlyContinue
Set-MpPreference -DisableBlockAtFirstSeen $true     -ErrorAction SilentlyContinue
Write-Ok "Cloud / MAPS / sample upload    : OFF (samples stay on this VM)"

# -- Network protection: OFF --
# We want to observe the complete network behaviour of samples, including
# connections to known-bad IPs that network protection would otherwise silently
# block. Isolation must be enforced at the hypervisor (host-only adapter),
# not by Defender.
Set-MpPreference -EnableNetworkProtection Disabled -ErrorAction SilentlyContinue
Write-Ok "Network protection              : OFF (observe full network behaviour)"

# -- Controlled folder access: OFF --
# CFA would block samples from writing files to protected paths, preventing
# observation of file-drop behaviour.
Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue
Write-Ok "Controlled folder access        : OFF (allows observation of file drops)"

# -- Path exclusions --
# uploads\  Samples must be scannable then executable without quarantine.
# results\  Patched binaries from signature analysis land here.
# tmp\      DefenderCheck's temp slice files. Excluding this dir is what
#           allows real-time protection to stay on everywhere else.
foreach ($p in @(
    "$InstallDir\uploads",
    "$InstallDir\results",
    "$InstallDir\tmp"
)) {
    Add-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue
    Write-Ok "Excluded from real-time scan    : $p"
}

Write-Warn "uploads\ and tmp\ are excluded from real-time scanning."
Write-Warn "Isolate this VM at the hypervisor level -- host-only or isolated NAT adapter."

# ---------------------------------------------------------------------------
# 7. Enable process-creation audit (Event ID 4688)
# ---------------------------------------------------------------------------
Write-Step "Enabling process creation audit policy (Event ID 4688)"

auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $regPath)) {
    New-Item $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

Write-Ok "Process creation (with command line) logging enabled"

# ---------------------------------------------------------------------------
# 8. Sysmon (optional)
# ---------------------------------------------------------------------------
Write-Step "Checking for Sysmon"

$sysmonExe = Get-Command sysmon64.exe -ErrorAction SilentlyContinue
if (-not $sysmonExe) {
    $sysmonExe = Get-Command sysmon.exe -ErrorAction SilentlyContinue
}

if ($sysmonExe) {
    Write-Ok "Sysmon already installed at $($sysmonExe.Source)"
}
else {
    Write-Warn "Sysmon not found. Attempting download from Sysinternals..."
    $sysmonZip = "$env:TEMP\Sysmon.zip"
    $sysmonDir = "$env:TEMP\Sysmon"
    try {
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
                          -OutFile $sysmonZip -UseBasicParsing -TimeoutSec 30
        Expand-Archive -Path $sysmonZip -DestinationPath $sysmonDir -Force

        $sysmonCfg = @"
<Sysmon schemaversion="4.90">
  <HashAlgorithms>md5,sha256</HashAlgorithms>
  <CheckRevocation/>
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Rule groupRelation="or"><Image condition="is not">System</Image></Rule>
      </ProcessCreate>
      <NetworkConnect onmatch="include">
        <Rule groupRelation="or"><Initiated condition="is">true</Initiated></Rule>
      </NetworkConnect>
      <DnsQuery onmatch="include">
        <Rule groupRelation="or"><QueryName condition="contains">.</QueryName></Rule>
      </DnsQuery>
      <FileCreate onmatch="include">
        <Rule groupRelation="or">
          <TargetFilename condition="end with">.exe</TargetFilename>
          <TargetFilename condition="end with">.dll</TargetFilename>
          <TargetFilename condition="end with">.bat</TargetFilename>
          <TargetFilename condition="end with">.ps1</TargetFilename>
        </Rule>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
"@
        $cfgPath = "$sysmonDir\localscan.xml"
        $sysmonCfg | Out-File -Encoding UTF8 -FilePath $cfgPath

        if (Test-Path "$sysmonDir\Sysmon64.exe") {
            $sysmonBin = "$sysmonDir\Sysmon64.exe"
        }
        else {
            $sysmonBin = "$sysmonDir\Sysmon.exe"
        }

        & $sysmonBin -accepteula -i $cfgPath 2>&1 | Out-Null
        Copy-Item $sysmonBin "C:\Windows\System32\" -Force
        Write-Ok "Sysmon installed and configured"
    }
    catch {
        Write-Warn "Sysmon auto-install failed: $_"
        Write-Warn "Download manually: https://docs.microsoft.com/sysinternals/downloads/sysmon"
        Write-Warn "The sandbox works without Sysmon -- you just get less telemetry."
    }
}

# ---------------------------------------------------------------------------
# 9. Local-only web access
# ---------------------------------------------------------------------------
Write-Step "Restricting the web interface to this VM"

# Older LocalScan releases opened this port. The current server binds to
# 127.0.0.1, so no inbound firewall rule is required.
$ruleName = "LocalScan-API"
$existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($existingRule) {
    Remove-NetFirewallRule -DisplayName $ruleName
}
Write-Ok "Web interface available only at http://localhost:5000"

# ---------------------------------------------------------------------------
# 10. Launcher script
#
# Sets TMPDIR / TMP / TEMP to $InstallDir\tmp before starting Python so that
# DefenderCheck's tempfile.mkdtemp() calls land in the Defender-excluded
# directory. Without this, slice files go to the system %TEMP% and real-time
# protection may quarantine them during signature analysis.
# ---------------------------------------------------------------------------
Write-Step "Creating launcher script"

$launcherPath = "$InstallDir\start_server.ps1"
$launcherContent = @"
# LocalScan server launcher -- generated by setup.ps1

# Route Python's temp files to the Defender-excluded directory so that
# signature analysis slice files are never touched by real-time protection.
`$env:TMPDIR = '$InstallDir\tmp'
`$env:TMP    = '$InstallDir\tmp'
`$env:TEMP   = '$InstallDir\tmp'

Set-Location '$InstallDir'
Start-Transcript -Path '$InstallDir\logs\server.log' -Append -NoClobber
Write-Host 'Starting LocalScan on http://localhost:5000 ...'
& '$AppPython' app.py
"@
$launcherContent | Out-File -Encoding ASCII -FilePath $launcherPath

Write-Ok "Launcher written to $launcherPath"
Write-Ok "  TMPDIR set to $InstallDir\tmp (Defender-excluded, used by signature analysis)"

# ---------------------------------------------------------------------------
# 11. Scheduled Task (at login, hidden window)
# ---------------------------------------------------------------------------
Write-Step "Creating Scheduled Task 'LocalScan-Server'"

$taskName = "LocalScan-Server"
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NonInteractive -WindowStyle Hidden -File `"$launcherPath`"" `
    -WorkingDirectory $InstallDir

$trigger = New-ScheduledTaskTrigger -AtLogOn

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 23) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $taskName `
                       -Action $action `
                       -Trigger $trigger `
                       -Settings $settings `
                       -RunLevel Highest `
                       -Force | Out-Null

Write-Ok "Scheduled Task created (runs at login, elevated)"

# ---------------------------------------------------------------------------
# 12. Desktop shortcut
# ---------------------------------------------------------------------------
Write-Step "Creating desktop shortcut"

$wsh      = New-Object -ComObject WScript.Shell
$shortcut = $wsh.CreateShortcut("$env:PUBLIC\Desktop\LocalScan.lnk")
$shortcut.TargetPath  = "http://localhost:5000"
$shortcut.Description = "LocalScan - Malware Analysis Sandbox + Signature Analyser"
$shortcut.Save()
Write-Ok "Shortcut created on Public Desktop"

# ---------------------------------------------------------------------------
# 13. Start server now
# ---------------------------------------------------------------------------
Write-Step "Launching server in a new window"

Start-Process powershell.exe `
    -ArgumentList "-NoExit -File `"$launcherPath`"" `
    -WorkingDirectory $InstallDir

Start-Sleep -Seconds 3
Write-Ok "Server should be starting at http://localhost:5000"

# ---------------------------------------------------------------------------
# Done -- print summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "==========================================================" -ForegroundColor Magenta
Write-Host "  LocalScan setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Web UI       : http://localhost:5000" -ForegroundColor White
Write-Host "  Install dir  : $InstallDir" -ForegroundColor White
Write-Host "  Logs         : $InstallDir\logs\server.log" -ForegroundColor White
Write-Host "  Uploads      : $InstallDir\uploads\" -ForegroundColor White
Write-Host "  Results      : $InstallDir\results\" -ForegroundColor White
Write-Host "  Temp (sig)   : $InstallDir\tmp\" -ForegroundColor White
Write-Host ""
Write-Host "  Defender settings applied:" -ForegroundColor Cyan
Write-Host "    Real-time protection    ON   (sandbox mode -- do not disable)" -ForegroundColor White
Write-Host "    Behavioral monitoring   ON" -ForegroundColor White
Write-Host "    Script scanning         ON" -ForegroundColor White
Write-Host "    Cloud / MAPS / upload   OFF  (samples stay on this VM)" -ForegroundColor White
Write-Host "    Network protection      OFF  (observe full network behaviour)" -ForegroundColor White
Write-Host "    Controlled folder access OFF (observe file drops)" -ForegroundColor White
Write-Host "    Excluded paths:" -ForegroundColor White
Write-Host "      uploads\  results\  tmp\" -ForegroundColor White
Write-Host ""
Write-Host "  REMINDER: Keep this VM isolated from production networks." -ForegroundColor Yellow
Write-Host "  Use a host-only or isolated NAT adapter -- not bridged." -ForegroundColor Yellow
Write-Host "  Take a snapshot now and restore after each analysis session." -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Magenta
