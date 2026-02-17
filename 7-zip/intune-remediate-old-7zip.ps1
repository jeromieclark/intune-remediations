# Intune remediation script for old versions of 7-zip
# This script will be deployed via Intune and should run on Powershell 5 in the SYSTEM context
# If 7-zip is installed and the version is older than 26.00, update it to the latest version using winget and exit 0
# If 7-zip is not present or the version is 26.00 or newer, exit 0 (compliant)
# If the upgrade fails, exit 1 (remediation failed)

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

function Invoke-WingetUpgrade {
	param(
		[Parameter(Mandatory = $true)]
		[string]$WingetPath,
		[Parameter(Mandatory = $true)]
		[string]$PackageId
	)

	$upgradeArgs = @(
		"upgrade",
		"--id", $PackageId,
		"--exact",
		"--silent",
		"--scope", "machine",
		"--disable-interactivity",
		"--accept-package-agreements",
		"--accept-source-agreements"
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
		Write-Output "Remediation failed: unable to determine 7-Zip version."
		exit 1
	}

	$needsRemediation = $false
	foreach ($ver in $versions) {
		if ($ver -lt $minimumVersion) {
			$needsRemediation = $true
			break
		}
	}

	if (-not $needsRemediation) {
		exit 0
	}

	$wingetPath = Get-WingetPath
	if (-not $wingetPath) {
		Write-Output "Remediation failed: winget.exe was not found."
		exit 1
	}

	$result = Invoke-WingetUpgrade -WingetPath $wingetPath -PackageId '7zip.7zip'
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