<#
.SYNOPSIS
  Enforce (or roll back) the WinVerifyTrust "certificate padding" mitigation for CVE-2013-3900.

.DESCRIPTION
  Windows Server 2019 (and similar) may default to a compatibility mode for Authenticode
  signature padding. This script configures the DWORD registry value
  'EnableCertPaddingCheck' in **both** registry views so Windows uses strict validation.

  Paths affected:
    HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config
    HKLM\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Wintrust\Config   (on x64)

  Actions performed:
    1) Safety checks (Admin + 64-bit PowerShell recommended)
    2) Optional backup of current keys to .reg files
    3) Create missing keys
    4) Set EnableCertPaddingCheck = 1 (Enable) or 0 (Disable/rollback)
    5) Verify and report status

.PARAMETER Enable
  Sets EnableCertPaddingCheck to 1 in both registry views. (Default action)

.PARAMETER Disable
  Sets EnableCertPaddingCheck to 0 in both registry views (rollback).

.PARAMETER VerifyOnly
  Makes no changes; outputs current settings.

.PARAMETER BackupDir
  Directory to write .reg backups before changes (default: a 'backup' subfolder in the script directory).
  If keys don’t exist yet, no backup is produced for that key.

.PARAMETER NoBackup
  Skip creating .reg backups.

.EXAMPLE
  PS> .\Set-WinVerifyTrustPadding.ps1
  # Enables the mitigation (value = 1) and shows verification.

.EXAMPLE
  PS> .\Set-WinVerifyTrustPadding.ps1 -Disable -Confirm
  # Prompts, then rolls back to value = 0.

.EXAMPLE
  PS> .\Set-WinVerifyTrustPadding.ps1 -VerifyOnly
  # Only reports current state.

.NOTES
  Author  : Marquell Proctor
  Version : 1.0
  Created : 2024-09-19
  Tested  : Windows Server 2019 Datacenter (x64), PowerShell 5.1

.USAGE
  Run from an elevated (Administrator) PowerShell session. A reboot is recommended after enabling.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [switch]$Enable,
  [switch]$Disable,
  [switch]$VerifyOnly,
  [string]$BackupDir,
  [switch]$NoBackup
)

# ---------- Helper: Environment/Safety checks(MUST RUN AS ADMIN) ----------
function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($id)
  return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
  Write-Error "This script must be run as Administrator. Right-click PowerShell and 'Run as administrator'."
  exit 1
}

# Recommend 64-bit host to avoid registry redirection surprises
if (-not [Environment]::Is64BitProcess) {
  Write-Warning "You are running 32-bit PowerShell on a 64-bit OS. Use 64-bit PowerShell to avoid registry redirection."
}

# ---------- Targets ----------
$RegistryPaths = @(
  'HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Wintrust\Config'
)

# Determine action (default = Enable)
if (-not $VerifyOnly -and -not $Enable -and -not $Disable) { $Enable = $true }

# ---------- Helper: Backup ----------
function Backup-RegistryKey {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$OutFile
  )
  #
