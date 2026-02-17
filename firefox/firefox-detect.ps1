# Intune Detection - Ensure Firefox is up to date with background updates enabled
# This script will be deployed via Intune and should run on Powershell 5 in the SYSTEM context
# If Firefox is installed, check if it is up to date and has the necessary configuration for background updates
# If Firefox is not present, exit 0 (compliant)
# If Firefox is present but not up to date or missing configuration, exit 1 (remediation required)

$ErrorActionPreference = 'Stop'

function Get-FirefoxInfo {
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

	if (-not $paths) { return $null }

	$exe = $paths | Select-Object -First 1
	$version = (Get-Item $exe).VersionInfo.FileVersion
	$channel = if ($exe -like "*ESR*") { "ESR" } else {
		if ($entries | Where-Object { $_.DisplayName -match 'ESR' }) { "ESR" } else { "Release" }
	}

	[pscustomobject]@{
		Path    = $exe
		Version = [version]$version
		Channel = $channel
	}
}

function Test-PolicyKeys {
	$polPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"
	if (-not (Test-Path $polPath)) { return $false }
	$p = Get-ItemProperty $polPath -ErrorAction SilentlyContinue
	return (($p.DisableAppUpdate -eq 0) -and ($p.AppAutoUpdate -eq 1) -and ($p.BackgroundAppUpdate -eq 1))
}

function Test-MaintenanceService {
	try {
		$svc = Get-Service -Name 'MozillaMaintenance' -ErrorAction Stop
		return ($svc.Status -eq 'Running' -or $svc.Status -eq 'Stopped')
	} catch { return $false }
}

function Test-BackgroundUpdateTask {
	try {
		$task = Get-ScheduledTask -TaskPath '\Mozilla\' -TaskName 'Firefox Background Update' -ErrorAction Stop
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
	if (-not $wingetPath) { return $null }

	$info = & $wingetPath show --id $id -e 2>$null
	if (-not $info) { return $null }

	$line = ($info | Select-String -Pattern 'Version:\s*(.+)$').Matches.Value
	if ($line) {
		$v = $line -replace 'Version:\s*',''
		return [version]$v
	}

	return $null
}

try {
	$fx = Get-FirefoxInfo
	if (-not $fx) {
		exit 0
	}

	$policiesOK = Test-PolicyKeys
	$svcOK      = Test-MaintenanceService
	$taskOK     = Test-BackgroundUpdateTask

	$latest = Get-LatestVersionViaWinget -Channel $fx.Channel

	$needsUpgrade = $false
	if ($latest -and ($fx.Version -lt $latest)) { $needsUpgrade = $true }

	if ($needsUpgrade -or (-not $policiesOK) -or (-not $svcOK) -or (-not $taskOK)) {
		exit 1
	}

	exit 0
} catch {
	Write-Output "Detection failed: $($_.Exception.Message)"
	exit 1
}