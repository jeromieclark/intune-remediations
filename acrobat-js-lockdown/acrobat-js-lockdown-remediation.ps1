# Remediates the Adobe Acrobat JavaScript lockdown setting.
# This script sets the registry key for disabling JavaScript in Adobe Acrobat DC to
# the desired value (1) as a DWORD in the 64-bit HKLM registry view.
# If the remediation is successful, it outputs "Remediation complete" and exits with code 0.
# If the remediation fails, it outputs an error message and exits with code 1.

$Path = "SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown"
$Name = "bDisableJavaScript"
$Value = 1

if (-not [Environment]::Is64BitOperatingSystem) {
    Write-Output "Remediation failed: unsupported 32-bit operating system"
    exit 1
}

$baseKey = $null
$policyKey = $null

try {
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64
    )

    $policyKey = $baseKey.CreateSubKey($Path)
    if ($null -eq $policyKey) {
        throw "Failed to open or create registry path: HKLM:\$Path"
    }

    $policyKey.SetValue(
        $Name,
        [int]$Value,
        [Microsoft.Win32.RegistryValueKind]::DWord
    )

    Write-Output "Remediation complete"
    exit 0
} catch {
    Write-Output "Remediation failed: $($_.Exception.Message)"
    exit 1
} finally {
    if ($null -ne $policyKey) {
        $policyKey.Close()
    }

    if ($null -ne $baseKey) {
        $baseKey.Close()
    }
}
