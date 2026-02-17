# Intune remediation script for old versions of Git for Windows
# This script will be deployed via Intune and should run on Powershell 5 in the SYSTEM context
# If using winget, remember to correctly resolve the path for execution in the SYSTEM context
# If Git for Windows is installed and the version is older than 2.53.0, exit 1 (remediation required)
# If Git for Windows is not present or the version is 2.53.0 or newer, exit 0 (compliant)

$ErrorActionPreference = 'Stop'

$minimumVersion = [version]'2.53.0'

function Get-GitCandidates {
	$candidates = New-Object System.Collections.Generic.List[string]

	$commonRoots = @(
		$env:ProgramFiles,
		${env:ProgramFiles(x86)}
	) | Where-Object { $_ }

	foreach ($root in $commonRoots) {
		$cmdPath = Join-Path -Path $root -ChildPath 'Git\cmd\git.exe'
		$binPath = Join-Path -Path $root -ChildPath 'Git\bin\git.exe'
		if (Test-Path -Path $cmdPath) { $candidates.Add($cmdPath) }
		if (Test-Path -Path $binPath) { $candidates.Add($binPath) }
	}

	$regUninstall = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
					"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

	foreach ($root in $regUninstall) {
		Get-ChildItem $root -ErrorAction SilentlyContinue |
		Where-Object {
			($_ | Get-ItemProperty -ErrorAction SilentlyContinue).DisplayName -like 'Git*'
		} |
		ForEach-Object {
			$p = $_ | Get-ItemProperty -ErrorAction SilentlyContinue
			if ($p.InstallLocation) {
				$cmdPath = Join-Path -Path $p.InstallLocation -ChildPath 'cmd\git.exe'
				$binPath = Join-Path -Path $p.InstallLocation -ChildPath 'bin\git.exe'
				if (Test-Path -Path $cmdPath) { $candidates.Add($cmdPath) }
				if (Test-Path -Path $binPath) { $candidates.Add($binPath) }
			}
		}
	}

	return $candidates | Sort-Object -Unique
}

function Get-GitVersionFromExe {
	param(
		[Parameter(Mandatory = $true)]
		[string]$GitPath
	)

	try {
		$output = & $GitPath --version 2>$null
		if (-not $output) { return $null }

		$match = [regex]::Match($output, '(\d+\.\d+\.\d+)')
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
	$paths = Get-GitCandidates
	if (-not $paths -or $paths.Count -eq 0) {
		exit 0
	}

	$versions = @()
	foreach ($path in $paths) {
		$ver = Get-GitVersionFromExe -GitPath $path
		if ($ver) { $versions += $ver }
	}

	if ($versions.Count -eq 0) {
		Write-Output "Remediation failed: unable to determine Git version."
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

	$result = Invoke-WingetUpgrade -WingetPath $wingetPath -PackageId 'Git.Git'
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

