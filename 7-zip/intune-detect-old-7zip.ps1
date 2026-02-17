# Intune detection script for old versions of 7-zip
# This script will be deployed via Intune and should run on Powershell 5 in the SYSTEM context
# If 7-zip is installed and the version is older than 26.00, exit 1 (remediation required)
# If 7-zip is not present or the version is 26.00 or newer, exit 0 (compliant)

$ErrorActionPreference = 'Stop'

$minimumVersion = [version]'26.0'

function Get-7ZipCandidates {
	$candidates = New-Object System.Collections.Generic.List[string]

	$commonRoots = @(
		$env:ProgramFiles,
		${env:ProgramFiles(x86)}
	) | Where-Object { $_ }

	foreach ($root in $commonRoots) {
		$exePath = Join-Path -Path $root -ChildPath '7-Zip\7z.exe'
		if (Test-Path -Path $exePath) { $candidates.Add($exePath) }
	}

	$regUninstall = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
					"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

	foreach ($root in $regUninstall) {
		Get-ChildItem $root -ErrorAction SilentlyContinue |
		Where-Object {
			($_ | Get-ItemProperty -ErrorAction SilentlyContinue).DisplayName -like '7-Zip*'
		} |
		ForEach-Object {
			$p = $_ | Get-ItemProperty -ErrorAction SilentlyContinue
			if ($p.InstallLocation) {
				$exePath = Join-Path -Path $p.InstallLocation -ChildPath '7z.exe'
				if (Test-Path -Path $exePath) { $candidates.Add($exePath) }
			}
		}
	}

	return $candidates | Sort-Object -Unique
}

function Get-7ZipVersionFromExe {
	param(
		[Parameter(Mandatory = $true)]
		[string]$ExePath
	)

	try {
		$fileVersion = (Get-Item -Path $ExePath).VersionInfo.FileVersion
		if (-not $fileVersion) { return $null }

		$match = [regex]::Match($fileVersion, '(\d+\.\d+(?:\.\d+)?)')
		if (-not $match.Success) { return $null }

		return [version]$match.Groups[1].Value
	} catch {
		return $null
	}
}

try {
	$paths = Get-7ZipCandidates
	if (-not $paths -or $paths.Count -eq 0) {
		exit 0
	}

	$versions = @()
	foreach ($path in $paths) {
		$ver = Get-7ZipVersionFromExe -ExePath $path
		if ($ver) { $versions += $ver }
	}

	if ($versions.Count -eq 0) {
		exit 1
	}

	foreach ($ver in $versions) {
		if ($ver -lt $minimumVersion) {
			exit 1
		}
	}

	exit 0
} catch {
	Write-Output "Detection failed: $($_.Exception.Message)"
	exit 1
}

