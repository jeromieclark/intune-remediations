# Intune Detection - Ensure Firefox is up to date with background updates enabled
# This script will be deployed via Intune and should run on Powershell 5 in the SYSTEM context
# If Firefox is installed, check if it is up to date and has the necessary configuration for background updates
# If Firefox is not present, exit 0 (compliant)
# If Firefox is present but not up to date or missing configuration, exit 1 (remediation required)

$ErrorActionPreference = 'Stop'

$DebugEnabled = $true
if ($DebugEnabled) {
	$VerbosePreference = 'Continue'
} else {
	$VerbosePreference = 'SilentlyContinue'
}

function Write-DebugLog {
	param(
		[Parameter(Mandatory = $true)]
		[string]$Message
	)
	if ($DebugEnabled) {
		Write-Verbose $Message
	}
}

function Get-FirefoxInfo {
	Write-DebugLog "Checking for Firefox installation."
	$paths = @(
		"$Env:ProgramFiles\Mozilla Firefox\firefox.exe",
		"${Env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
	) | Where-Object { $_ -and (Test-Path $_) }

	$regUninstall = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
					"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

	$entries = foreach ($root in $regUninstall) {
		Get-ChildItem $root -ErrorAction SilentlyContinue |
		Where-Object {
			($_ | Get-ItemProperty -ErrorAction SilentlyContinue).DisplayName -like 'Mozilla Firefox*'
		} |
		ForEach-Object {
			$p = $_ | Get-ItemProperty -ErrorAction SilentlyContinue
			[pscustomobject]@{
				DisplayName     = $p.DisplayName
				DisplayVersion  = $p.DisplayVersion
				InstallLocation = $p.InstallLocation
				Path            = if ($p.InstallLocation) { Join-Path $p.InstallLocation 'firefox.exe' } else { $null }
			}
		}
	}

	if (-not $paths -and $entries) {
		$paths = $entries | Where-Object { $_.Path } | Select-Object -ExpandProperty Path
	}

	if (-not $paths) {
		Write-DebugLog "Firefox not found via file paths or registry."
		return $null
	}

	$exe = $paths | Select-Object -First 1
	$version = (Get-Item $exe).VersionInfo.FileVersion
	$channel = if ($exe -like "*ESR*") { "ESR" } else {
		if ($entries | Where-Object { $_.DisplayName -match 'ESR' }) { "ESR" } else { "Release" }
	}

	Write-DebugLog "Firefox found at '$exe' (Version: $version, Channel: $channel)."

	[pscustomobject]@{
		Path    = $exe
		Version = [version]$version
		Channel = $channel
	}
}

function Test-PolicyKeys {
	$polPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"
	if (-not (Test-Path $polPath)) {
		Write-DebugLog "Policy path not found: $polPath"
		return $false
	}
	$p = Get-ItemProperty $polPath -ErrorAction SilentlyContinue
	$ok = (($p.DisableAppUpdate -eq 0) -and ($p.AppAutoUpdate -eq 1) -and ($p.BackgroundAppUpdate -eq 1))
	Write-DebugLog "Policy settings - DisableAppUpdate=$($p.DisableAppUpdate) AppAutoUpdate=$($p.AppAutoUpdate) BackgroundAppUpdate=$($p.BackgroundAppUpdate) (OK=$ok)"
	return $ok
}

function Test-MaintenanceService {
	try {
		$svc = Get-Service -Name 'MozillaMaintenance' -ErrorAction Stop
		Write-DebugLog "Maintenance service status: $($svc.Status)"
		return ($svc.Status -eq 'Running' -or $svc.Status -eq 'Stopped')
	} catch { return $false }
}

function Test-BackgroundUpdateTask {
	try {
		$task = Get-ScheduledTask -TaskPath '\Mozilla\' -TaskName 'Firefox Background Update' -ErrorAction Stop
		Write-DebugLog "Background update task state: $($task.State)"
		return ($task.State -ne 'Disabled')
	} catch { return $false }
}

function Get-WingetPath {
	$searchRoots = @()
	if ($env:LOCALAPPDATA) {
		$searchRoots += (Join-Path -Path $env:LOCALAPPDATA -ChildPath "Microsoft\WindowsApps")
	}
	if ($env:ProgramFiles) {
		$searchRoots += (Join-Path -Path $env:ProgramFiles -ChildPath "WindowsApps")
	}

	foreach ($root in $searchRoots) {
		if (-not (Test-Path -Path $root)) {
			continue
		}

		$appDirs = Get-ChildItem -Path $root -Directory -Filter "Microsoft.DesktopAppInstaller_*" -ErrorAction SilentlyContinue | Sort-Object Name -Descending
		foreach ($dir in $appDirs) {
			$candidate = Join-Path -Path $dir.FullName -ChildPath "winget.exe"
			if (Test-Path -Path $candidate) {
				return $candidate
			}
		}

		$fallback = Get-ChildItem -Path $root -Filter "winget.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
		if ($fallback) {
			return $fallback.FullName
		}
	}

	return $null
}

function Get-LatestVersionViaWinget {
	param(
		[Parameter(Mandatory = $true)]
		[string]$Channel
	)

	$id = if ($Channel -eq 'ESR') { 'Mozilla.Firefox.ESR' } else { 'Mozilla.Firefox' }
	$wingetPath = Get-WingetPath
	if (-not $wingetPath) {
		Write-DebugLog "winget not available; cannot query latest version."
		return $null
	}

	$info = & $wingetPath show --id $id -e 2>$null
	if (-not $info) {
		Write-DebugLog "winget show returned no data for id '$id'."
		return $null
	}

	$line = ($info | Select-String -Pattern 'Version:\s*(.+)$').Matches.Value
	if ($line) {
		$v = $line -replace 'Version:\s*',''
		Write-DebugLog "Latest $id version from winget: $v"
		return [version]$v
	}

	Write-DebugLog "Unable to parse version from winget output for id '$id'."
	return $null
}

try {
	Write-DebugLog "Starting Firefox detection."
	$fx = Get-FirefoxInfo
	if (-not $fx) {
		Write-DebugLog "Firefox not installed. Marking compliant."
		exit 0
	}

	$policiesOK = Test-PolicyKeys
	$svcOK      = Test-MaintenanceService
	$taskOK     = Test-BackgroundUpdateTask

	$latest = Get-LatestVersionViaWinget -Channel $fx.Channel
	if ($latest) {
		Write-DebugLog "Installed version: $($fx.Version). Latest version: $latest."
	} else {
		Write-DebugLog "Latest version could not be determined via winget."
	}

	$needsUpgrade = $false
	if ($latest -and ($fx.Version -lt $latest)) { $needsUpgrade = $true }
	Write-DebugLog "Upgrade required: $needsUpgrade. Policies OK: $policiesOK. Service OK: $svcOK. Task OK: $taskOK."

	if ($needsUpgrade -or (-not $policiesOK) -or (-not $svcOK) -or (-not $taskOK)) {
		Write-DebugLog "Non-compliant state detected."
		exit 1
	}

	Write-DebugLog "Compliant state detected."
	exit 0
} catch {
	Write-Output "Detection failed: $($_.Exception.Message)"
	exit 1
}