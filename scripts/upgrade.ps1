#Requires -Version 5.1
<#
.SYNOPSIS
    Multicast Ring Analyzer upgrade script for Windows.

.DESCRIPTION
    Pulls latest source, builds the Windows installer, backs up the existing
    installation and user data, then runs the new NSIS installer silently.

.PARAMETER FromDist
    Skip git pull and npm build — install from an existing dist\ folder.

.PARAMETER DryRun
    Show what would happen without making any changes.

.EXAMPLE
    .\scripts\upgrade.ps1
    .\scripts\upgrade.ps1 -FromDist
    .\scripts\upgrade.ps1 -DryRun
#>
param(
    [switch]$FromDist,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AppName   = "Multicast Ring Tester"
$AppId     = "multicast-ring-tester"
$RepoUrl   = "https://github.com/lavabeard/av-net-scout.git"
$Stamp     = Get-Date -Format "yyyyMMdd_HHmmss"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoDir   = Split-Path -Parent $ScriptDir

function Info  { param($m) Write-Host "[upgrade] $m" -ForegroundColor Green }
function Warn  { param($m) Write-Host "[upgrade] $m" -ForegroundColor Yellow }
function Error { param($m) Write-Host "[upgrade] $m" -ForegroundColor Red; exit 1 }
function Run   {
    param([string]$Cmd, [string[]]$Args)
    if ($DryRun) { Write-Host "[dry-run] $Cmd $Args" -ForegroundColor Cyan; return }
    & $Cmd @Args
    if ($LASTEXITCODE -ne 0) { Error "Command failed: $Cmd $Args" }
}

# ── locate user data ───────────────────────────────────────────────────────────
$UserData = Join-Path $env:APPDATA $AppName

# ── locate existing installation ──────────────────────────────────────────────
$InstallPath = ""
$DefaultInstall = "C:\Program Files\$AppName"
$DefaultInstall86 = "C:\Program Files (x86)\$AppName"
if     (Test-Path $DefaultInstall)   { $InstallPath = $DefaultInstall }
elseif (Test-Path $DefaultInstall86) { $InstallPath = $DefaultInstall86 }

# Also check registry uninstall key
$RegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
)
foreach ($rp in $RegPaths) {
    Get-ChildItem $rp -ErrorAction SilentlyContinue | ForEach-Object {
        $d = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($d.DisplayName -like "*$AppName*" -and $d.InstallLocation) {
            $InstallPath = $d.InstallLocation.TrimEnd('\')
        }
    }
}

Info "Platform  : Windows"
Info "User data : $UserData"
Info "Install   : $(if ($InstallPath) { $InstallPath } else { '<not found — fresh install>' })"
if ($DryRun) { Warn "Dry-run mode — no changes will be made" }
Write-Host ""

# ── step 1: pull latest source ─────────────────────────────────────────────────
if (-not $FromDist) {
    Info "Pulling latest source…"
    if (Test-Path (Join-Path $RepoDir ".git")) {
        Run "git" @("-C", $RepoDir, "pull", "--ff-only", "origin", "main")
    } else {
        $RepoDir = Join-Path $env:TEMP "mcast-build-$Stamp"
        Warn "Not inside a git repo — cloning to $RepoDir"
        Run "git" @("clone", $RepoUrl, $RepoDir)
    }
}

# ── step 2: build ──────────────────────────────────────────────────────────────
if (-not $FromDist) {
    Info "Installing Node dependencies…"
    Run "npm" @("--prefix", $RepoDir, "install")
    Info "Building for Windows…"
    Run "npm" @("--prefix", $RepoDir, "run", "dist:win")
}

$NewInstaller = Get-ChildItem (Join-Path $RepoDir "dist\*.exe") -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $NewInstaller) { Error "No .exe installer found in dist\ — build may have failed" }
Info "New build : $($NewInstaller.FullName)"

# ── step 3: back up existing installation ─────────────────────────────────────
$BackupBase = Join-Path $env:LOCALAPPDATA "$AppId-backups\$Stamp"

if ($InstallPath -and (Test-Path $InstallPath)) {
    Info "Backing up existing installation → $BackupBase\app\"
    if (-not $DryRun) {
        New-Item -ItemType Directory -Force -Path "$BackupBase\app" | Out-Null
        Copy-Item -Path $InstallPath -Destination "$BackupBase\app\" -Recurse -Force
    } else {
        Write-Host "[dry-run] Copy $InstallPath → $BackupBase\app\" -ForegroundColor Cyan
    }
}

if (Test-Path $UserData) {
    Info "Backing up user data → $BackupBase\userdata\"
    if (-not $DryRun) {
        New-Item -ItemType Directory -Force -Path "$BackupBase\userdata" | Out-Null
        Copy-Item -Path $UserData -Destination "$BackupBase\userdata\" -Recurse -Force
    } else {
        Write-Host "[dry-run] Copy $UserData → $BackupBase\userdata\" -ForegroundColor Cyan
    }
}

# ── step 4: uninstall old version ─────────────────────────────────────────────
if ($InstallPath) {
    $Uninstaller = Join-Path $InstallPath "Uninstall $AppName.exe"
    if (Test-Path $Uninstaller) {
        Info "Running silent uninstaller…"
        Run $Uninstaller @("/S")
        Start-Sleep -Seconds 3
    }
}

# ── step 5: install new version ───────────────────────────────────────────────
Info "Running new installer (silent)…"
# /S = silent NSIS install
Run $NewInstaller.FullName @("/S")

# ── done ───────────────────────────────────────────────────────────────────────
Write-Host ""
Info "Upgrade complete."
if (Test-Path $BackupBase) { Info "Backup saved to: $BackupBase" }
Info "Launch from Start Menu: $AppName"
