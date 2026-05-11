# Intune detection script for unsanctioned Greenshot installations
# This script runs in PowerShell 5 under the SYSTEM context.
# Exit 1 when Greenshot is detected (remediation required), otherwise exit 0.

$ErrorActionPreference = 'Stop'

function Get-GreenshotInstallIndicators {
	$results = New-Object System.Collections.Generic.List[object]

	$machineUninstallRoots = @(
		'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
		'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
	)

	foreach ($root in $machineUninstallRoots) {
		if (-not (Test-Path -Path $root)) { continue }

		Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
			$props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
			if (-not $props -or -not $props.DisplayName) { return }

			if ($props.DisplayName -match 'Greenshot') {
				$results.Add([pscustomobject]@{
					Scope          = 'Machine'
					Source         = 'Registry'
					DisplayName    = [string]$props.DisplayName
					RegistryPath   = [string]$_.PSPath
					UninstallString = [string]$props.UninstallString
				})
			}
		}
	}

	$machineFilePaths = @(
		'C:\Program Files\Greenshot\Greenshot.exe',
		'C:\Program Files (x86)\Greenshot\Greenshot.exe'
	)

	foreach ($path in $machineFilePaths) {
		if (Test-Path -Path $path) {
			$results.Add([pscustomobject]@{
				Scope          = 'Machine'
				Source         = 'File'
				DisplayName    = 'Greenshot'
				RegistryPath   = $null
				UninstallString = $null
				Path           = $path
			})
		}
	}

	$userProfiles = Get-ChildItem -Path 'C:\Users' -Directory -ErrorAction SilentlyContinue |
		Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }

	foreach ($profile in $userProfiles) {
		$userFileCandidates = @(
			(Join-Path -Path $profile.FullName -ChildPath 'AppData\Local\Greenshot\Greenshot.exe'),
			(Join-Path -Path $profile.FullName -ChildPath 'AppData\Local\Programs\Greenshot\Greenshot.exe'),
			(Join-Path -Path $profile.FullName -ChildPath 'AppData\Roaming\Greenshot\Greenshot.exe')
		)

		foreach ($candidate in $userFileCandidates) {
			if (Test-Path -Path $candidate) {
				$results.Add([pscustomobject]@{
					Scope          = 'User'
					Source         = 'File'
					DisplayName    = 'Greenshot'
					RegistryPath   = $null
					UninstallString = $null
					Path           = $candidate
					ProfilePath    = $profile.FullName
				})
			}
		}
	}

	$hkuSids = Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
		Where-Object { $_.PSChildName -match '^S-1-5-21-.+' }

	foreach ($sid in $hkuSids) {
		$root = "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall"
		if (-not (Test-Path -Path $root)) { continue }

		Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
			$props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
			if (-not $props -or -not $props.DisplayName) { return }

			if ($props.DisplayName -match 'Greenshot') {
				$results.Add([pscustomobject]@{
					Scope          = 'User'
					Source         = 'Registry'
					DisplayName    = [string]$props.DisplayName
					RegistryPath   = [string]$_.PSPath
					UninstallString = [string]$props.UninstallString
					Sid            = [string]$sid.PSChildName
				})
			}
		}
	}

	$deduped = $results |
		Sort-Object Scope, Source, RegistryPath, Path, DisplayName -Unique

	return $deduped
}

try {
	$found = Get-GreenshotInstallIndicators

	if (-not $found -or $found.Count -eq 0) {
		Write-Output 'No Greenshot installation indicators detected.'
		exit 0
	}

	Write-Output "Greenshot detected. Found $($found.Count) indicator(s):"
	$found | ForEach-Object {
		$pathInfo = if ($_.RegistryPath) { $_.RegistryPath } elseif ($_.Path) { $_.Path } else { 'Unknown location' }
		Write-Output "- [$($_.Scope)] $($_.Source): $($_.DisplayName) at $pathInfo"
	}

	exit 1
} catch {
	Write-Output "Detection failed: $($_.Exception.Message)"
	exit 1
}
