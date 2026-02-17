# Intune detection script for old versions of Docker Desktop for Windows
# This script will be deployed via Intune and should run on Powershell 5 in the SYSTEM context
# If Docker Desktop for Windows is installed and the version is older than 4.60.1 (exit 1 - remediation required)
# If Docker Desktop for Windows is not present or the version is 4.60.1 or newer, exit 0 (compliant)

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

try {
	$records = @()
	$records += Get-DockerDesktopRegistryVersions
	$records += Get-DockerDesktopFileVersions

	if (-not $records -or $records.Count -eq 0) {
		Write-Output 'Docker Desktop not detected.'
		exit 0
	}

	$versions = $records | Where-Object { $_.Version }
	if (-not $versions -or $versions.Count -eq 0) {
		Write-Output 'Docker Desktop detected but version could not be determined.'
		exit 1
	}

	$vulnerable = $versions | Where-Object { $_.Version -lt $minimumVersion }
	if ($vulnerable) {
		Write-Output "Docker Desktop versions below $minimumVersion detected:"
		$vulnerable | Sort-Object Version | ForEach-Object {
			Write-Output "- Version $($_.Version) from $($_.Source) at $($_.Path)"
		}
		exit 1
	}

	Write-Output "Docker Desktop is $minimumVersion or newer."
	exit 0
} catch {
	Write-Output "Detection failed: $($_.Exception.Message)"
	exit 1
}

