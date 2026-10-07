<#
.SYNOPSIS
  Registers the Sentinel collector as a Scheduled Task that starts at boot and restarts on failure.
  NOT TESTED on a real Windows host from this repository's build environment. Read it, and try it on a test machine first.

.DESCRIPTION
  Run from an elevated PowerShell. Use a dedicated low-privilege account (not SYSTEM, not an administrator) that can
  read the Snort log folder. The API key goes in a file only that account can read; this script locks the file down.

.EXAMPLE
  .\install-task.ps1 -Credential (Get-Credential .\sentinel-collector) -ApiKey 'snt_xxxxxxxx'
#>
param(
  [Parameter(Mandatory)][pscredential]$Credential,
  [Parameter(Mandatory)][string]$ApiKey,
  [string]$CollectorDir = (Resolve-Path "$PSScriptRoot\..").Path,
  [string]$ConfigPath   = 'C:\ProgramData\Sentinel\collector.toml',
  [string]$KeyPath      = 'C:\ProgramData\Sentinel\api_key.txt',
  [string]$Python       = (Get-Command python -ErrorAction Stop).Source,
  [string]$TaskName     = 'SentinelCollector'
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $ConfigPath)) { throw "Copy collector.example.toml to $ConfigPath and edit it first." }

# 1. Store the key where only the service account and administrators can read it.
New-Item -ItemType Directory -Force -Path (Split-Path $KeyPath) | Out-Null
Set-Content -Path $KeyPath -Value $ApiKey -NoNewline -Encoding ascii
icacls $KeyPath /inheritance:r /grant:r "$($Credential.UserName):(R)" "BUILTIN\Administrators:(F)" | Out-Null

# 2. The task: python -m sentinel_collector run --config ...
$action   = New-ScheduledTaskAction -Execute $Python -Argument "-m sentinel_collector run --config `"$ConfigPath`"" -WorkingDirectory $CollectorDir
$trigger  = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
            -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
  -User $Credential.UserName -Password $Credential.GetNetworkCredential().Password -RunLevel Limited -Force | Out-Null

Write-Host "Registered '$TaskName'. Verify the connection first:"
Write-Host "  $Python -m sentinel_collector check --config `"$ConfigPath`""
Write-Host "Then start it:  Start-ScheduledTask -TaskName $TaskName"
