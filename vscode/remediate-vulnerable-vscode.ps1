# Intune Remediation Script — stage VS Code update for next reboot
# Purpose: detect Visual Studio Code installations older than 1.109.3 and stage a silent installer to remediate on next reboot.
# Scope: runs as SYSTEM (PowerShell 5) on Windows 10 / Windows 11 when deployed via Microsoft Intune.
# Behavior:
#  - Detects VS Code from machine installs and common per-user install locations.
#  - If any installed version is < 1.109.3, downloads the official VS Code installer to
#    C:\ProgramData\VSCodeRemediation\VSCodeSetup.exe and creates an HKLM RunOnce entry to run:
#      "<installer-path>" /VERYSILENT /NORESTART /MERGETASKS=!runcode
#    The installer will execute at next reboot (reboot required to complete remediation).
#  - If no vulnerable versions are found the script exits with code 0.
# Exit codes:
#  0 = No vulnerable installs found OR remediation staged successfully
#  1 = Vulnerable installs found but staging/remediation failed, or script error

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

function Get-VscodeInstallRoot {
	param(
		[Parameter(Mandatory = $true)]
		[string]$path
	)

	if (-not $path) {
		return $null
	}

	if (Test-Path -Path $path -PathType Container) {
		return $path
	}

	if (Test-Path -Path $path -PathType Leaf) {
		return (Split-Path -Path $path -Parent)
	}

	return $null
}

function Get-VscodeInstallerUrl {
	$arch = $env:PROCESSOR_ARCHITECTURE
	switch ($arch) {
		"ARM64" { return "https://update.code.visualstudio.com/latest/win32-arm64/stable" }
		"AMD64" { return "https://update.code.visualstudio.com/latest/win32-x64/stable" }
		default { return "https://update.code.visualstudio.com/latest/win32/stable" }
	}
}

function Install-VscodeSilently {
	$arch = $env:PROCESSOR_ARCHITECTURE
	$stagingDir = Join-Path -Path $env:ProgramData -ChildPath "VSCodeRemediation"
	if (-not (Test-Path -Path $stagingDir)) {
		New-Item -Path $stagingDir -ItemType Directory -Force | Out-Null
	}

	$installerPath = Join-Path -Path $stagingDir -ChildPath "VSCodeSetup.exe"

	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	try {
		Invoke-WebRequest -Uri (Get-VscodeInstallerUrl) -OutFile $installerPath -UseBasicParsing -ErrorAction Stop
	} catch {
		Write-Output "Failed to download VS Code installer: $($_.Exception.Message)"
		return $false
	}

	# Schedule installer to run at next reboot via HKLM RunOnce
	$runOnceKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
	$entryName = 'VSCodeUpdate_' + (Get-Date -Format 'yyyyMMddHHmmss')
	$command = "`"$installerPath`" /VERYSILENT /NORESTART /MERGETASKS=!runcode"

	try {
		New-ItemProperty -Path $runOnceKey -Name $entryName -Value $command -PropertyType String -Force | Out-Null
	} catch {
		Write-Output "Failed to create RunOnce entry: $($_.Exception.Message)"
		return $false
	}

	Write-Output "Installer downloaded to $installerPath and scheduled in RunOnce as '$entryName'."
	return $true
}

try {
	$installed = Get-InstalledVscodeVersions

	if (-not $installed -or $installed.Count -eq 0) {
		Write-Output "No Visual Studio Code installations detected."
		exit 0
	}

	$vulnerable = $installed | Where-Object { $_.Version -lt $minimumSafeVersion }

	if (-not $vulnerable) {
		Write-Output "All detected Visual Studio Code versions are $minimumSafeVersion or newer."
		exit 0
	}

	Write-Output "Vulnerable Visual Studio Code versions detected (below $minimumSafeVersion). Staging installer to RunOnce for next reboot."

	if (Install-VscodeSilently) {
		Write-Output "Installer staged successfully; it will run on next reboot. Reboot is required to complete remediation."
		exit 0
	}

	Write-Output "Failed to stage installer for RunOnce."
	exit 1
} catch {
	Write-Output "Remediation script failed: $($_.Exception.Message)"
	exit 1
}



