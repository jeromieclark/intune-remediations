$ErrorActionPreference = 'Stop'

$DesiredVersion = [Version]'8.9.2'
$AppName = 'Notepad++'
$InstallerUrl = 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9.2/npp.8.9.2.Installer.x64.exe'
$InstallerFile = Join-Path -Path $env:TEMP -ChildPath 'npp-installer.exe'

function Get-InstalledNppVersion {
	$uninstallPaths = @(
		'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
		'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
	)

	foreach ($path in $uninstallPaths) {
		$apps = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
		foreach ($app in $apps) {
			$props = Get-ItemProperty -Path $app.PSPath -ErrorAction SilentlyContinue
			if ($null -ne $props.DisplayName -and $props.DisplayName -like "$AppName*") {
				if ([string]::IsNullOrWhiteSpace($props.DisplayVersion)) {
					continue
				}

				try {
					return [Version]$props.DisplayVersion
				} catch {
					continue
				}
			}
		}
	}

	return $null
}

function Ensure-Tls12 {
	$tls12 = [System.Net.SecurityProtocolType]::Tls12
	if (-not ([System.Net.ServicePointManager]::SecurityProtocol.HasFlag($tls12))) {
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor $tls12
	}
}

$installedVersion = Get-InstalledNppVersion

if ($null -ne $installedVersion -and $installedVersion -ge $DesiredVersion) {
	Write-Output "$AppName is already at version $installedVersion."
	exit 0
}

Ensure-Tls12

Write-Output "Downloading $AppName $DesiredVersion from $InstallerUrl"
Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerFile -UseBasicParsing

Write-Output "Installing $AppName $DesiredVersion"
$process = Start-Process -FilePath $InstallerFile -ArgumentList '/S' -Wait -PassThru

if ($process.ExitCode -ne 0) {
	throw "$AppName installer exited with code $($process.ExitCode)"
}

$installedVersion = Get-InstalledNppVersion
if ($null -eq $installedVersion -or $installedVersion -lt $DesiredVersion) {
	throw "$AppName did not update to $DesiredVersion. Detected version: $installedVersion"
}

Write-Output "$AppName updated successfully to $installedVersion."
exit 0
