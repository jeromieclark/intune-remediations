# Intune detection script for old versions of Docker Desktop for Windows
# This script will be deployed via Intune and should run on Powershell 5 in the SYSTEM context
# If Docker Desktop for Windows is installed and the version is older than 4.60.1 update it
# If Docker Desktop for Windows is not present or the version is 4.60.1 or newer, exit 0 (compliant)
# If the update fails, exit 1 (remediation required)

$ErrorActionPreference = 'Stop'

$minimumVersion = [version]'4.60.1'

function Convert-VersionTextToVersion {
	param(
		[Parameter(Mandatory = $true)]
		[string]$VersionText
	)

	$match = [regex]::Match($VersionText, '(\d+\.\d+(?:\.\d+)?)')
	if (-not $match.Success) {
		return $null
	}

	try {
		return [version]$match.Groups[1].Value
	} catch {
		return $null
	}
}

function Get-DockerDesktopRegistryVersions {
	$found = New-Object System.Collections.Generic.List[object]

	$uninstallRoots = @(
		'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
		'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
	)

	foreach ($root in $uninstallRoots) {
		if (-not (Test-Path -Path $root)) {
			continue
		}

		Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
			$props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
			if (-not $props) {
				return
			}

			if ($props.DisplayName -like 'Docker Desktop*') {
				$version = $null
				if ($props.DisplayVersion) {
					$version = Convert-VersionTextToVersion -VersionText $props.DisplayVersion
				}

				$found.Add([pscustomobject]@{
					Source  = 'Registry'
					Path    = $props.InstallLocation
					Version = $version
				})
			}
		}
	}

	return $found
}

function Get-DockerDesktopFileVersions {
	$found = New-Object System.Collections.Generic.List[object]

	$commonRoots = @(
		$env:ProgramFiles,
		${env:ProgramFiles(x86)}
	) | Where-Object { $_ }

	foreach ($root in $commonRoots) {
		$exePath = Join-Path -Path $root -ChildPath 'Docker\Docker\Docker Desktop.exe'
		if (-not (Test-Path -Path $exePath)) {
			continue
		}

		$fileVersion = (Get-Item -Path $exePath -ErrorAction SilentlyContinue).VersionInfo.FileVersion
		if (-not $fileVersion) {
			$found.Add([pscustomobject]@{
				Source  = 'File'
				Path    = $exePath
				Version = $null
			})
			continue
		}

		$version = Convert-VersionTextToVersion -VersionText $fileVersion
		$found.Add([pscustomobject]@{
			Source  = 'File'
			Path    = $exePath
			Version = $version
		})
	}

	return $found
}

function Get-WingetPath {
	$searchRoots = @()
	if ($env:LOCALAPPDATA) {
		$searchRoots += (Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\WindowsApps')
	}
	if ($env:ProgramFiles) {
		$searchRoots += (Join-Path -Path $env:ProgramFiles -ChildPath 'WindowsApps')
	}

	foreach ($root in $searchRoots) {
		if (-not (Test-Path -Path $root)) {
			continue
		}

		$appDirs = Get-ChildItem -Path $root -Directory -Filter 'Microsoft.DesktopAppInstaller_*' -ErrorAction SilentlyContinue | Sort-Object Name -Descending
		foreach ($dir in $appDirs) {
			$candidate = Join-Path -Path $dir.FullName -ChildPath 'winget.exe'
			if (Test-Path -Path $candidate) {
				return $candidate
			}
		}

		$fallback = Get-ChildItem -Path $root -Filter 'winget.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
		if ($fallback) {
			return $fallback.FullName
		}
	}

	return $null
}

function Invoke-WingetUpgrade {
	param(
		[Parameter(Mandatory = $true)]
		[string]$WingetPath,
		[Parameter(Mandatory = $true)]
		[string]$PackageId
	)

	$upgradeArgs = @(
		'upgrade',
		'--id', $PackageId,
		'--exact',
		'--silent',
		'--scope', 'machine',
		'--disable-interactivity',
		'--accept-package-agreements',
		'--accept-source-agreements'
	)

	$output = & $WingetPath @upgradeArgs 2>&1
	$exitCode = $LASTEXITCODE

	return [pscustomobject]@{
		ExitCode = $exitCode
		Output   = $output
	}
}

function Test-WingetUpgradeSuccess {
	param(
		[Parameter(Mandatory = $true)]
		$Result
	)

	$text = ($Result.Output | Out-String).ToLowerInvariant()
	if ($text -match 'no available upgrade found' -or $text -match 'no newer package versions are available' -or $text -match 'no applicable update') {
		return $true
	}

	$successCodes = @(0, 3010, 1641)
	if ($successCodes -contains $Result.ExitCode) {
		return $true
	}

	if ($Result.ExitCode -eq 1 -and ($text -match 'no installed package found' -or $text -match 'successfully installed' -or $text -match 'already installed')) {
		return $true
	}

	return $false
}

try {
	$records = @()
	$records += Get-DockerDesktopRegistryVersions
	$records += Get-DockerDesktopFileVersions

	if (-not $records -or $records.Count -eq 0) {
		exit 0
	}

	$versions = $records | Where-Object { $_.Version }
	if (-not $versions -or $versions.Count -eq 0) {
		Write-Output 'Remediation failed: unable to determine Docker Desktop version.'
		exit 1
	}

	$needsRemediation = $false
	foreach ($ver in $versions) {
		if ($ver.Version -lt $minimumVersion) {
			$needsRemediation = $true
			break
		}
	}

	if (-not $needsRemediation) {
		exit 0
	}

	$wingetPath = Get-WingetPath
	if (-not $wingetPath) {
		Write-Output 'Remediation failed: winget.exe was not found.'
		exit 1
	}

	$result = Invoke-WingetUpgrade -WingetPath $wingetPath -PackageId 'Docker.DockerDesktop'
	if (-not (Test-WingetUpgradeSuccess -Result $result)) {
		$tail = $result.Output | Select-Object -Last 8
		Write-Output "Remediation failed: winget exit code $($result.ExitCode)."
		if ($tail) {
			Write-Output ($tail -join "`n")
		}
		exit 1
	}

	exit 0
} catch {
	Write-Output "Remediation failed: $($_.Exception.Message)"
	exit 1
}