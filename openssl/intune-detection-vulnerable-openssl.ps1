# Intune Detection Script for vulnerable OpenSSL versions
# This script will be deployed via Microsoft Intune to check if vulnerable versions of OpenSSL are installed on the device.
# It should run successfully in Powershell 5 as the SYSTEM user on Windows 10 and Windows 11 devices.
# This script checks if any vulnerable versions of OpenSSL are installed.
# If no vulnerable versions of OpenSSL are found, return exit code 0    

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
        @{ Major = 3; Minor = 6; Patch = 1; Suffix = "" },
        @{ Major = 3; Minor = 5; Patch = 5; Suffix = "" },
		@{ Major = 3; Minor = 4; Patch = 4; Suffix = "" },
		@{ Major = 3; Minor = 3; Patch = 6; Suffix = "" },
		@{ Major = 3; Minor = 0; Patch = 19; Suffix = "" }
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

try {
	$paths = Get-OpenSslCandidates
	$vulnerableFindings = @()

	foreach ($path in $paths) {
		$version = Get-OpenSslVersionFromPath -OpenSslPath $path
		if (-not $version) {
			continue
		}

		if (Test-OpenSslVulnerable -Version $version) {
			$vulnerableFindings += "${path} => $($version.Major).$($version.Minor).$($version.Patch)$($version.Suffix)"
		}
	}

	if ($vulnerableFindings.Count -gt 0) {
		Write-Output "Vulnerable OpenSSL detected:"
		$vulnerableFindings | ForEach-Object { Write-Output $_ }
		exit 1
	}

	Write-Output "No vulnerable OpenSSL versions detected."
	exit 0
} catch {
	Write-Output "Detection failed: $($_.Exception.Message)"
	exit 1
}

