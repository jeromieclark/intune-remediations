# Intune Remediation - Update Dell Command | Update to Latest Version
# This script will be deployed via Intune and should run on Powershell 5 in the SYSTEM context
# If Dell Command | Update is installed, update to the latest available version
# If Dell Command | Update is not present or the upgrade completes successfully, exit 0
# If the upgrade fails, exit 1

$ErrorActionPreference = 'Stop'

$dcuWingetPackageIds = @(
	'Dell.CommandUpdate.Universal',
	'Dell.CommandUpdate'
)

function ConvertTo-Version {
	param(
		[Parameter(Mandatory = $true)]
		[string]$Text
	)

	$match = [regex]::Match($Text, '(\d+\.\d+(?:\.\d+){0,2})')
	if (-not $match.Success) {
		return $null
	}

	try {
		return [version]$match.Groups[1].Value
	} catch {
		return $null
	}
}

function Get-DellCommandUpdateInfo {
	$found = @()

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

			if ($props.DisplayName -like 'Dell Command*Update*') {
				$ver = $null
				if ($props.DisplayVersion) {
					$ver = ConvertTo-Version -Text $props.DisplayVersion
				}

				$exePath = $null
				if ($props.InstallLocation) {
					$candidate = Join-Path -Path $props.InstallLocation -ChildPath 'dcu-cli.exe'
					if (Test-Path -Path $candidate) {
						$exePath = $candidate
					}
				}

				if (-not $exePath) {
					$possiblePaths = @(
						"$env:ProgramFiles\Dell\CommandUpdate\dcu-cli.exe",
						"${env:ProgramFiles(x86)}\Dell\CommandUpdate\dcu-cli.exe"
					) | Where-Object { $_ }

					foreach ($path in $possiblePaths) {
						if (Test-Path -Path $path) {
							$exePath = $path
							break
						}
					}
				}

				if (-not $ver -and $exePath -and (Test-Path -Path $exePath)) {
					$fileVersion = (Get-Item -Path $exePath -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
					if (-not $fileVersion) {
						$fileVersion = (Get-Item -Path $exePath -ErrorAction SilentlyContinue).VersionInfo.FileVersion
					}
					if ($fileVersion) {
						$ver = ConvertTo-Version -Text $fileVersion
					}
				}

				$found += [pscustomobject]@{
					Path    = $exePath
					Version = $ver
				}
			}
		}
	}

	if (-not $found -or $found.Count -eq 0) {
		$possiblePaths = @(
			"$env:ProgramFiles\Dell\CommandUpdate\dcu-cli.exe",
			"${env:ProgramFiles(x86)}\Dell\CommandUpdate\dcu-cli.exe"
		) | Where-Object { $_ -and (Test-Path -Path $_) }

		foreach ($path in $possiblePaths | Select-Object -Unique) {
			$fileVersion = (Get-Item -Path $path -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
			if (-not $fileVersion) {
				$fileVersion = (Get-Item -Path $path -ErrorAction SilentlyContinue).VersionInfo.FileVersion
			}
			$ver = $null
			if ($fileVersion) {
				$ver = ConvertTo-Version -Text $fileVersion
			}

			$found += [pscustomobject]@{
				Path    = $path
				Version = $ver
			}
		}
	}

	if (-not $found -or $found.Count -eq 0) {
		return $null
	}

	$withVersion = $found | Where-Object { $_.Version }
	if ($withVersion) {
		return ($withVersion | Sort-Object Version -Descending | Select-Object -First 1)
	}

	return ($found | Select-Object -First 1)
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

function Get-LatestDellCommandUpdateVersionViaWinget {
	param(
		[Parameter(Mandatory = $true)]
		[string]$WingetPath
	)

	$versions = @()
	foreach ($packageId in $dcuWingetPackageIds) {
		$info = & $WingetPath show --id $packageId -e 2>$null
		if (-not $info) {
			continue
		}

		$line = ($info | Select-String -Pattern 'Version:\s*(.+)$').Matches.Value | Select-Object -First 1
		if (-not $line) {
			continue
		}

		$versionText = $line -replace 'Version:\s*', ''
		$ver = ConvertTo-Version -Text $versionText
		if ($ver) {
			$versions += $ver
		}
	}

	if (-not $versions -or $versions.Count -eq 0) {
		return $null
	}

	return ($versions | Sort-Object -Descending | Select-Object -First 1)
}

function Get-InstalledWingetDellPackageIds {
	param(
		[Parameter(Mandatory = $true)]
		[string]$WingetPath,
		[Parameter(Mandatory = $true)]
		[string[]]$PackageIds
	)

	$installed = @()
	foreach ($packageId in $PackageIds) {
		$listResult = & $WingetPath list --id $packageId -e --accept-source-agreements 2>$null
		if (-not $listResult) {
			continue
		}

		$text = ($listResult | Out-String).ToLowerInvariant()
		if ($text -match 'no installed package found matching input criteria') {
			continue
		}

		if ($text -match [regex]::Escape($packageId.ToLowerInvariant())) {
			$installed += $packageId
		}
	}

	return $installed
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

	if ($Result.ExitCode -eq 1 -and ($text -match 'successfully installed' -or $text -match 'already installed')) {
		return $true
	}

	return $false
}

try {
	$dcu = Get-DellCommandUpdateInfo
	if (-not $dcu) {
		Write-Output 'Dell Command | Update not found.'
		exit 0
	}

	Write-Output "Detected Dell Command | Update path: $($dcu.Path)"
	if ($dcu.Version) {
		Write-Output "Detected Dell Command | Update version: $($dcu.Version)"
	} else {
		Write-Output 'Remediation failed: unable to determine installed Dell Command | Update version.'
		exit 1
	}

	$wingetPath = Get-WingetPath
	if (-not $wingetPath) {
		Write-Output 'Remediation failed: winget.exe was not found.'
		exit 1
	}

	Write-Output "Using winget at: $wingetPath"

	$latest = Get-LatestDellCommandUpdateVersionViaWinget -WingetPath $wingetPath
	if ($latest) {
		Write-Output "Latest Dell Command | Update version (winget): $latest"
	} else {
		Write-Output 'Unable to resolve latest Dell Command | Update version via winget.'
	}

	if ($latest -and ($dcu.Version -ge $latest)) {
		Write-Output 'Dell Command | Update is already current.'
		exit 0
	}

	$targetIds = @()
	$installedIds = Get-InstalledWingetDellPackageIds -WingetPath $wingetPath -PackageIds $dcuWingetPackageIds
	if ($installedIds -and $installedIds.Count -gt 0) {
		$targetIds += $installedIds
	}
	foreach ($id in $dcuWingetPackageIds) {
		if ($targetIds -notcontains $id) {
			$targetIds += $id
		}
	}

	$upgradeSucceeded = $false
	$lastResult = $null
	$lastPackageId = $null

	foreach ($packageId in $targetIds) {
		Write-Output "Running winget upgrade for $packageId..."
		$result = Invoke-WingetUpgrade -WingetPath $wingetPath -PackageId $packageId
		$lastResult = $result
		$lastPackageId = $packageId

		if (Test-WingetUpgradeSuccess -Result $result) {
			$upgradeSucceeded = $true
			break
		}

		$text = ($result.Output | Out-String).ToLowerInvariant()
		if ($text -notmatch 'no installed package found matching input criteria') {
			break
		}
	}

	if (-not $upgradeSucceeded) {
		$tail = $lastResult.Output | Select-Object -Last 8
		Write-Output "Remediation failed for package id ${lastPackageId}: winget exit code $($lastResult.ExitCode)."
		if ($tail) {
			Write-Output ($tail -join "`n")
		}
		exit 1
	}

	Write-Output 'Dell Command | Update remediation completed successfully.'
	exit 0
} catch {
	Write-Output "Remediation failed: $($_.Exception.Message)"
	exit 1
}
