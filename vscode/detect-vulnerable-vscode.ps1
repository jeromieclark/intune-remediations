# Intune Detection Script to Detect Vulnerable Versions of Visual Studio Code
# This script will be deployed via Microsoft Intune to check if vulnerable versions of Visual Studio Code are installed on the device.
# It should run successfully in Powershell 5 as the SYSTEM user on Windows 10 and Windows 11 devices.
# This script checks if any vulnerable versions of Visual Studio Code (versions < 1.109.3) are installed.
# If no vulnerable versions of Visual Studio Code are found, return exit code 0

$ErrorActionPreference = "Stop"

$minimumSafeVersion = [version]"1.109.3"

function Get-InstalledVscodeVersions {
	$found = @()

	$uninstallRoots = @(
		"HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
		"HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
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

			if ($props.DisplayName -like "Microsoft Visual Studio Code*") {
				$versionText = $props.DisplayVersion
				if ($versionText) {
					try {
						$found += [pscustomobject]@{
							Source  = "Registry"
							Path    = $props.InstallLocation
							Version = [version]$versionText
						}
					} catch {
						Write-Output "Skipping unparseable VS Code version from registry: $versionText"
					}
				}
			}
		}
	}

	$codeExePaths = @(
		"C:\Program Files\Microsoft VS Code\Code.exe",
		"C:\Program Files (x86)\Microsoft VS Code\Code.exe"
	)

	Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
		$userCode = Join-Path -Path $_.FullName -ChildPath "AppData\Local\Programs\Microsoft VS Code\Code.exe"
		$codeExePaths += $userCode
	}

	foreach ($path in $codeExePaths | Select-Object -Unique) {
		if (-not (Test-Path -Path $path)) {
			continue
		}

		$fileVersion = (Get-Item -Path $path -ErrorAction SilentlyContinue).VersionInfo.FileVersion
		if (-not $fileVersion) {
			continue
		}

		try {
			$found += [pscustomobject]@{
				Source  = "File"
				Path    = $path
				Version = [version]$fileVersion
			}
		} catch {
			Write-Output "Skipping unparseable VS Code version from file: $fileVersion"
		}
	}

	return $found
}

try {
	$installed = Get-InstalledVscodeVersions

	if (-not $installed -or $installed.Count -eq 0) {
		Write-Output "No Visual Studio Code installations detected."
		exit 0
	}

	$vulnerable = $installed | Where-Object { $_.Version -lt $minimumSafeVersion }

	if ($vulnerable) {
		Write-Output "Vulnerable Visual Studio Code versions detected (below $minimumSafeVersion):"
		$vulnerable | Sort-Object Version | ForEach-Object {
			Write-Output "- Version $($_.Version) from $($_.Source) at $($_.Path)"
		}
		exit 1
	}

	Write-Output "All detected Visual Studio Code versions are $minimumSafeVersion or newer."
	exit 0
} catch {
	Write-Output "Detection script failed: $($_.Exception.Message)"
	exit 1
}
