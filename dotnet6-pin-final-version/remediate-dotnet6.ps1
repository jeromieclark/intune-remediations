# Intune Remediation Script for .NET 6 versions < 6.0.36
# 
# This script will be deployed via Microsoft Intune to check if .NET 6 is installed on the device and if the version is less than 6.0.36.
# It should run successfully in Powershell 5 as the SYSTEM user on Windows 10 and Windows 11 devices.
#
# This script will replace any installed .NET 6 runtime version less than 6.0.36 with the latest .NET 6 runtime version (6.0.36 or later).
# If .NET 6 is not installed, or .NET 6 is version 6.0.36 or later, the script will exit without making any changes.

param()

$ErrorActionPreference = 'Stop'

# Required minimum version for .NET 6 runtime
$requiredVersion = [Version] '6.0.36'

function Get-DotNet6InstalledVersions {
	[CmdletBinding()]
	param()

	$versions = @()

	# Check file system first (same as detect script)
	$roots = @(
		"$env:ProgramFiles\dotnet\shared\Microsoft.NETCore.App",
		"${env:ProgramFiles(x86)}\dotnet\shared\Microsoft.NETCore.App"
	) | Where-Object { $_ -and (Test-Path $_) }

	foreach ($root in $roots) {
		Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue |
			ForEach-Object {
				if ($_.Name -like '6.0.*') {
					$v = $null
					if ([Version]::TryParse($_.Name, [ref]$v)) {
						$versions += $v
					}
				}
			}
	}

	# Fallback to registry check
	$regPaths = @(
		'HKLM:\SOFTWARE\dotnet\Setup\Installed\Microsoft.NETCore.App',
		'HKLM:\SOFTWARE\WOW6432Node\dotnet\Setup\Installed\Microsoft.NETCore.App'
	)

	foreach ($path in $regPaths) {
		if (Test-Path -Path $path) {
			$subKeys = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
			foreach ($subKey in $subKeys) {
				$leafKeys = Get-ChildItem -Path $subKey.PSPath -ErrorAction SilentlyContinue
				if (-not $leafKeys -or $leafKeys.Count -eq 0) {
					$leafKeys = @($subKey)
				}

				foreach ($leaf in $leafKeys) {
					$props = Get-ItemProperty -Path $leaf.PSPath -ErrorAction SilentlyContinue
					if ($null -ne $props.Version -and ($props.Version -match '^6\.0\.')) {
						try {
							$v = [Version] $props.Version
							$versions += $v
						} catch {
							# Ignore unparsable versions
						}
					}
				}
			}
		}
	}

	$versions | Sort-Object -Unique
}

function Get-HighestDotNet6Version {
	[CmdletBinding()]
	param()

	$versions = Get-DotNet6InstalledVersions
	if (-not $versions -or $versions.Count -eq 0) {
		return $null
	}

	$versions | Sort-Object -Descending | Select-Object -First 1
}

function Get-DotNet6RuntimeDownloadUrl {
	[CmdletBinding()]
	param()

	$arch = if ([Environment]::Is64BitOperatingSystem) {
		if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
	} else {
		'x86'
	}

	switch ($arch) {
		'x86' { 'https://aka.ms/dotnet/6.0/dotnet-runtime-win-x86.exe' }
		'arm64' { 'https://aka.ms/dotnet/6.0/dotnet-runtime-win-arm64.exe' }
		default { 'https://aka.ms/dotnet/6.0/dotnet-runtime-win-x64.exe' }
	}
}

function Install-DotNet6Runtime {
	[CmdletBinding()]
	param()

	try {
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
	} catch {
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	}

	$downloadUrl = Get-DotNet6RuntimeDownloadUrl
	$tempDir = Join-Path -Path $env:TEMP -ChildPath 'dotnet6-remediation'
	$installerPath = Join-Path -Path $tempDir -ChildPath 'dotnet-runtime-6.0-latest.exe'

	New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

	Write-Output ("Downloading .NET 6 runtime from {0}" -f $downloadUrl)
	Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath -UseBasicParsing

	Write-Output 'Installing .NET 6 runtime...'
	$proc = Start-Process -FilePath $installerPath -ArgumentList '/install', '/quiet', '/norestart' -Wait -PassThru

	# 0 = success, 3010 = success + reboot required
	if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
		throw "Installer exited with code $($proc.ExitCode)."
	}

	try {
		Remove-Item -Path $installerPath -Force -ErrorAction SilentlyContinue
		Remove-Item -Path $tempDir -Force -ErrorAction SilentlyContinue
	} catch {
		# Ignore cleanup failures
	}
}

try {
	$highest = Get-HighestDotNet6Version

	if ($null -eq $highest) {
		Write-Output 'No .NET 6 runtime found. No remediation required.'
		exit 0
	}

	if ($highest -ge $requiredVersion) {
		Write-Output (".NET 6 runtime is {0} (>= {1}). No remediation required." -f $highest, $requiredVersion)
		exit 0
	}

	Write-Output (".NET 6 runtime is {0} (< {1}). Remediation required." -f $highest, $requiredVersion)
	Install-DotNet6Runtime

	$postInstall = Get-HighestDotNet6Version
	if ($null -eq $postInstall -or $postInstall -lt $requiredVersion) {
		Write-Output 'Remediation completed but required version not detected.'
		exit 1
	}

	Write-Output ("Remediation succeeded. .NET 6 runtime is now {0}." -f $postInstall)
	exit 0
} catch {
	Write-Output ("Remediation failed: {0}" -f $_.Exception.Message)
	exit 1
}
