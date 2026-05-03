# Intune Detection - Ensure Dell Command | Update is up to date
# This script will be deployed via Intune and should run on Powershell 5 in the SYSTEM context
# If Dell Command | Update is installed, compare installed version with the latest available version via winget
# If Dell Command | Update is not present, exit 0 (compliant)
# If Dell Command | Update is present but out of date or version lookup fails, exit 1 (remediation required)

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
		[string]$WingetPath,
		[Parameter(Mandatory = $true)]
		[string[]]$PackageIds
	)

	$versions = @()
	foreach ($packageId in $PackageIds) {
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
		Write-Output 'Detection failed: unable to determine installed Dell Command | Update version.'
		exit 1
	}

	$wingetPath = Get-WingetPath
	if (-not $wingetPath) {
		Write-Output 'Detection failed: winget.exe was not found.'
		exit 1
	}

	$latest = Get-LatestDellCommandUpdateVersionViaWinget -WingetPath $wingetPath -PackageIds $dcuWingetPackageIds
	if (-not $latest) {
		Write-Output 'Detection failed: unable to resolve latest Dell Command | Update version.'
		exit 1
	}

	Write-Output "Latest Dell Command | Update version (winget): $latest"

	if ($dcu.Version -lt $latest) {
		Write-Output 'Dell Command | Update is out of date.'
		exit 1
	}

	Write-Output 'Dell Command | Update is up to date.'
	exit 0
} catch {
	Write-Output "Detection failed: $($_.Exception.Message)"
	exit 1
}
