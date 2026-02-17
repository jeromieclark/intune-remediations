# Intune Remediation Script for vulnerable OpenSSL versions
# This script will be deployed via Microsoft Intune to check if vulnerable versions of OpenSSL are installed on the device.
# It should run successfully in Powershell 5 as the SYSTEM user on Windows 10 and Windows 11 devices.
# This script checks if any vulnerable versions of OpenSSL are installed.
# If vulnerable versions of OpenSSL are found, it will attempt to replace them with the latest secure version corresponding to that branch (e.g. 3.5.4 for 3.5.x, 3.4.8 for 3.4.x, etc.)
# If the remediation is successful, return exit code 0. If it fails, return exit code 1.

$ErrorActionPreference = "Stop"

function Convert-OpenSslSuffixToNumber {
	param(
		[Parameter(Mandatory = $false)]
		[string]$Suffix
	)

	if ([string]::IsNullOrWhiteSpace($Suffix)) {
		return 0
	}

	$value = 0
	foreach ($ch in $Suffix.ToLower().ToCharArray()) {
		if ($ch -lt 'a' -or $ch -gt 'z') {
			return 0
		}

		$value = ($value * 26) + ([int][char]$ch - 96)
	}

	return $value
}

function Parse-OpenSslVersion {
	param(
		[Parameter(Mandatory = $true)]
		[string]$VersionText
	)

	if ($VersionText -match "OpenSSL\s+([0-9]+\.[0-9]+\.[0-9]+)([a-z]{0,2})?") {
		$numeric = $Matches[1]
		$suffix = $Matches[2]

		$parts = $numeric.Split(".")
		if ($parts.Count -ne 3) {
			return $null
		}

		return [PSCustomObject]@{
			Major  = [int]$parts[0]
			Minor  = [int]$parts[1]
			Patch  = [int]$parts[2]
			Suffix = $suffix
		}
	}

	return $null
}

function Compare-OpenSslVersion {
	param(
		[Parameter(Mandatory = $true)]
		$Left,
		[Parameter(Mandatory = $true)]
		$Right
	)

	foreach ($prop in @("Major", "Minor", "Patch")) {
		if ($Left.$prop -lt $Right.$prop) { return -1 }
		if ($Left.$prop -gt $Right.$prop) { return 1 }
	}

	$leftSuffix = Convert-OpenSslSuffixToNumber -Suffix $Left.Suffix
	$rightSuffix = Convert-OpenSslSuffixToNumber -Suffix $Right.Suffix

	if ($leftSuffix -lt $rightSuffix) { return -1 }
	if ($leftSuffix -gt $rightSuffix) { return 1 }
	return 0
}

function Test-OpenSslVulnerable {
	param(
		[Parameter(Mandatory = $true)]
		$Version
	)

	$thresholds = @(
		@{ Major = 3; Minor = 5; Patch = 4; Suffix = "" },
		@{ Major = 3; Minor = 4; Patch = 3; Suffix = "" },
		@{ Major = 3; Minor = 3; Patch = 5; Suffix = "" },
		@{ Major = 3; Minor = 2; Patch = 6; Suffix = "" },
		@{ Major = 3; Minor = 0; Patch = 18; Suffix = "" },
		@{ Major = 1; Minor = 1; Patch = 1; Suffix = "zd" },
		@{ Major = 1; Minor = 0; Patch = 2; Suffix = "zm" }
	)

	foreach ($threshold in $thresholds) {
		if ($Version.Major -eq $threshold.Major -and $Version.Minor -eq $threshold.Minor) {
			$thresholdVersion = [PSCustomObject]@{
				Major = $threshold.Major
				Minor = $threshold.Minor
				Patch = $threshold.Patch
				Suffix = $threshold.Suffix
			}

			if ((Compare-OpenSslVersion -Left $Version -Right $thresholdVersion) -lt 0) {
				return $true
			}

			return $false
		}
	}

	return $false
}

function Get-OpenSslCandidatesFromRegistry {
	$paths = @(
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
		"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
	)

	$candidates = New-Object System.Collections.Generic.List[string]

	foreach ($path in $paths) {
		$keys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
		foreach ($key in $keys) {
			$props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
			if (-not $props) { continue }

			if ($props.DisplayName -and $props.DisplayName -match "OpenSSL") {
				$installLocation = $props.InstallLocation
				if ($installLocation -and (Test-Path -Path $installLocation)) {
					$binPath = Join-Path -Path $installLocation -ChildPath "bin\openssl.exe"
					if (Test-Path -Path $binPath) {
						$candidates.Add($binPath)
					}
				}

				if ($props.DisplayIcon -and $props.DisplayIcon -match "openssl\.exe") {
					$iconPath = $props.DisplayIcon.Trim('"')
					if (Test-Path -Path $iconPath) {
						$candidates.Add($iconPath)
					}
				}
			}
		}
	}

	return $candidates
}

function Get-OpenSslCandidates {
	$candidates = New-Object System.Collections.Generic.List[string]

	$commonPaths = @(
		"$env:ProgramFiles\OpenSSL-Win64\bin\openssl.exe",
		"$env:ProgramFiles\OpenSSL-Win32\bin\openssl.exe",
		"$env:ProgramFiles (x86)\OpenSSL-Win32\bin\openssl.exe",
		"$env:ProgramFiles\Git\usr\bin\openssl.exe",
		"$env:ProgramFiles\Git\mingw64\bin\openssl.exe",
		"$env:ProgramFiles (x86)\Git\usr\bin\openssl.exe",
		"$env:ProgramData\chocolatey\bin\openssl.exe",
		"$env:SystemRoot\System32\OpenSSL\bin\openssl.exe",
		"$env:SystemRoot\SysWOW64\OpenSSL\bin\openssl.exe"
	)

	foreach ($path in $commonPaths) {
		if (Test-Path -Path $path) {
			$candidates.Add($path)
		}
	}

	foreach ($path in (Get-OpenSslCandidatesFromRegistry)) {
		if ($path -and (Test-Path -Path $path)) {
			$candidates.Add($path)
		}
	}

	$pathHits = Get-Command -Name "openssl.exe" -ErrorAction SilentlyContinue
	foreach ($hit in $pathHits) {
		if ($hit.Path -and (Test-Path -Path $hit.Path)) {
			$candidates.Add($hit.Path)
		}
	}

	return $candidates | Sort-Object -Unique
}

function Get-OpenSslVersionFromPath {
	param(
		[Parameter(Mandatory = $true)]
		[string]$OpenSslPath
	)

	try {
		$output = & $OpenSslPath version 2>$null
		if (-not $output) {
			return $null
		}

		return Parse-OpenSslVersion -VersionText $output
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

function Get-TargetVersion {
	param(
		[Parameter(Mandatory = $true)]
		$Version
	)

	if ($Version.Major -eq 1) {
		return $null
	}

	if ($Version.Major -eq 3 -and $Version.Minor -eq 6) { return "3.6.1" }
	if ($Version.Major -eq 3 -and $Version.Minor -eq 5) { return "3.5.5" }
	if ($Version.Major -eq 3 -and $Version.Minor -eq 4) { return "3.4.4" }
	if ($Version.Major -eq 3 -and $Version.Minor -eq 3) { return "3.3.6" }
	if ($Version.Major -eq 3 -and $Version.Minor -eq 2) { return "3.3.6" }
	if ($Version.Major -eq 3 -and $Version.Minor -eq 0) { return "3.0.19" }

	return $null
}

function Test-IsShiningLightPath {
	param(
		[Parameter(Mandatory = $true)]
		[string]$OpenSslPath
	)

	return ($OpenSslPath -match "OpenSSL-Win(32|64)")
}

function Test-IsFireDaemonPath {
	param(
		[Parameter(Mandatory = $true)]
		[string]$OpenSslPath
	)

	return ($OpenSslPath -match "FireDaemon OpenSSL")
}

function Invoke-WingetInstall {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WingetPath,
        [Parameter(Mandatory = $true)]
        [string]$PackageId,
        [Parameter(Mandatory = $true)]
        [string]$TargetVersion,
        [Parameter(Mandatory = $false)]
        [bool]$UseExactVersion = $true,
        [Parameter(Mandatory = $false)]
        [string]$OverrideArgs = $null
    )

    $baseArgs = @("--id", $PackageId, "--exact", "--silent", "--scope", "machine", "--accept-package-agreements", "--accept-source-agreements")

    if ($UseExactVersion) {
        $installArgs = @("install") + $baseArgs + @("--version", $TargetVersion)
        if ($OverrideArgs) { $installArgs += @("--override", $OverrideArgs) }
        & $WingetPath @installArgs
        return $LASTEXITCODE
    }

    $upgradeArgs = @("upgrade") + $baseArgs
    if ($OverrideArgs) { $upgradeArgs += @("--override", $OverrideArgs) }
    & $WingetPath @upgradeArgs
    return $LASTEXITCODE
}

try {
	$paths = Get-OpenSslCandidates
	$vulnerable = @()

	foreach ($path in $paths) {
		$version = Get-OpenSslVersionFromPath -OpenSslPath $path
		if (-not $version) {
			continue
		}

		if (Test-OpenSslVulnerable -Version $version) {
			$vulnerable += [PSCustomObject]@{
				Path = $path
				Version = $version
			}
		}
	}

	if ($vulnerable.Count -eq 0) {
		Write-Output "No vulnerable OpenSSL versions detected."
		exit 0
	}

	$wingetPath = Get-WingetPath
	if (-not $wingetPath) {
		Write-Output "Remediation failed: winget.exe was not found."
		exit 1
	}

	$failures = @()

	foreach ($item in $vulnerable) {
		$version = $item.Version
		$targetVersion = Get-TargetVersion -Version $version
		$versionText = "$($version.Major).$($version.Minor).$($version.Patch)$($version.Suffix)"

		if (-not $targetVersion) {
			$failures += "$($item.Path) => $versionText (unsupported branch)"
			continue
		}

		$packageId = $null
		$useExactVersion = $true
		$overrideArgs = $null
		if (Test-IsShiningLightPath -OpenSslPath $item.Path) {
			$packageId = "ShiningLight.OpenSSL"
		} elseif (Test-IsFireDaemonPath -OpenSslPath $item.Path) {
			$packageId = "FireDaemon.OpenSSL"
			$useExactVersion = $false
			$overrideArgs = "/exenoui /exelog fdopenssl3.log /qn /norestart REBOOT=ReallySuppress APPDIR=`"C:\Program Files\FireDaemon OpenSSL 3`" ADJUSTSYSTEMPATHENV=yes"
		}

		if (-not $packageId) {
			$failures += "$($item.Path) => $versionText (no winget mapping)"
			continue
		}

		$exitCode = Invoke-WingetInstall -WingetPath $wingetPath -PackageId $packageId -TargetVersion $targetVersion -UseExactVersion $useExactVersion -OverrideArgs $overrideArgs
		if ($exitCode -ne 0) {
			$failures += "$($item.Path) => $versionText (winget failed, exit $exitCode)"
		}
	}

	$remaining = @()
	foreach ($path in (Get-OpenSslCandidates)) {
		$version = Get-OpenSslVersionFromPath -OpenSslPath $path
		if (-not $version) {
			continue
		}

		if (Test-OpenSslVulnerable -Version $version) {
			$remaining += "$path => $($version.Major).$($version.Minor).$($version.Patch)$($version.Suffix)"
		}
	}

	if ($remaining.Count -gt 0 -or $failures.Count -gt 0) {
		Write-Output "Remediation incomplete."
		if ($failures.Count -gt 0) {
			Write-Output "Failures:"
			$failures | ForEach-Object { Write-Output $_ }
		}
		if ($remaining.Count -gt 0) {
			Write-Output "Remaining vulnerable OpenSSL binaries:"
			$remaining | ForEach-Object { Write-Output $_ }
		}
		exit 1
	}

	Write-Output "Remediation successful."
	exit 0
} catch {
	Write-Output "Remediation failed: $($_.Exception.Message)"
	exit 1
}

