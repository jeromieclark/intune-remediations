# PowerShell 5.1 detection for "minimum .NET 6.0.36" (unsupported baseline).

$ErrorActionPreference = 'Stop'
$min = [Version]'6.0.36'
$nonCompliant = $false

$roots = @(
  "$env:ProgramFiles\dotnet\shared\Microsoft.NETCore.App",
  "$env:ProgramFiles(x86)\dotnet\shared\Microsoft.NETCore.App"
) | Where-Object { $_ -and (Test-Path $_) }

foreach ($root in $roots) {
    Get-ChildItem -Path $root -ErrorAction SilentlyContinue |
      ForEach-Object {
          if ($_.Name -like '6.0.*') {
              $v = $null
              if ([Version]::TryParse($_.Name, [ref]$v)) {
                  if ($v -lt $min) { $nonCompliant = $true }
                  if ($v -ge $min) { Write-Output ".NET $($v.ToString()) meets baseline $min" }
              }
          }
      }
}

if ($nonCompliant) {
    Write-Output "Outdated .NET 6 detected — remediation required"
    exit 1
} else {
    Write-Output "No outdated .NET 6 found (or .NET 6 absent)"
    exit 0
}