param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$ErrorActionPreference = "Stop"

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "Version must use SemVer core format: X.Y.Z"
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$cargoTomlPath = Join-Path $repoRoot "Cargo.toml"

if (-not (Test-Path $cargoTomlPath)) {
    throw "Cargo.toml was not found at $cargoTomlPath"
}

$cargoToml = Get-Content $cargoTomlPath -Raw
$updated = [regex]::Replace(
    $cargoToml,
    '(?m)^version\s*=\s*"[^"]+"$',
    ('version = "{0}"' -f $Version),
    1
)

if ($updated -eq $cargoToml) {
    throw "Could not update the version field in Cargo.toml"
}

Set-Content -Path $cargoTomlPath -Value $updated -Encoding utf8

Write-Host "Updated Cargo.toml to version $Version"
Write-Host "Next steps:"
Write-Host "  git add Cargo.toml"
Write-Host ('  git commit -m "release: v{0}"' -f $Version)
Write-Host ('  git tag v{0}' -f $Version)
Write-Host "  git push && git push --tags"
