param(
    [switch]$BuildMsi,
    [string]$UpdateRepo
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$cargoTomlPath = Join-Path $repoRoot "Cargo.toml"
$versionLine = Select-String -Path $cargoTomlPath -Pattern '^version\s*=\s*"([^"]+)"$' | Select-Object -First 1

if (-not $versionLine) {
    throw "Could not determine the package version from Cargo.toml."
}

$appVersion = $versionLine.Matches[0].Groups[1].Value
$effectiveUpdateRepo = if ($UpdateRepo) { $UpdateRepo } else { $env:PILLOWLOCK_UPDATE_REPO }
$cargoExe = Join-Path $repoRoot ".local-rust\\toolchain\\bin\\cargo.exe"
$rustcExe = Join-Path $repoRoot ".local-rust\\toolchain\\bin\\rustc.exe"
$rustdocExe = Join-Path $repoRoot ".local-rust\\toolchain\\bin\\rustdoc.exe"

if (-not (Test-Path $cargoExe)) {
    $cargoCommand = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $cargoCommand) {
        throw "cargo.exe was not found. Install Rust or restore the local toolchain under .local-rust\\toolchain."
    }

    $cargoExe = $cargoCommand.Source
    $toolchainBin = Split-Path -Parent $cargoExe
    $rustcExe = Join-Path $toolchainBin "rustc.exe"
    $rustdocExe = Join-Path $toolchainBin "rustdoc.exe"
}

$vswhereExe = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\\Installer\\vswhere.exe"
if (-not (Test-Path $vswhereExe)) {
    throw "vswhere.exe was not found. Install Visual Studio Build Tools or Visual Studio."
}

$vsInstallPath = & $vswhereExe -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsInstallPath) {
    throw "Could not find a Visual Studio installation with the C++ build tools."
}

$vsDevCmd = Join-Path $vsInstallPath "Common7\\Tools\\VsDevCmd.bat"
if (-not (Test-Path $vsDevCmd)) {
    throw "VsDevCmd.bat was not found at $vsDevCmd."
}

$buildCmd = @(
    ('"{0}" -arch=x64 >nul' -f $vsDevCmd),
    ('set PATH={0};%PATH%' -f (Split-Path -Parent $cargoExe)),
    ('set RUSTC={0}' -f $rustcExe),
    ('set RUSTDOC={0}' -f $rustdocExe),
    $(if ($effectiveUpdateRepo) { 'set PILLOWLOCK_UPDATE_REPO={0}' -f $effectiveUpdateRepo }),
    ('"{0}" build --release' -f $cargoExe)
) -join " && "

& cmd.exe /c $buildCmd
if ($LASTEXITCODE -ne 0) {
    throw "Release build failed."
}

$exePath = Join-Path $repoRoot "target\\release\\pillowlock.exe"
if (-not (Test-Path $exePath)) {
    throw "Release executable was not produced at $exePath."
}

Write-Host "Built EXE:" $exePath

if (-not $BuildMsi) {
    return
}

$wixExe = Join-Path $repoRoot ".tools\\wix.exe"
if (-not (Test-Path $wixExe)) {
    throw "WiX CLI was not found. Install it with: dotnet tool install --tool-path .tools wix"
}

$distDir = Join-Path $repoRoot "dist"
New-Item -ItemType Directory -Force -Path $distDir | Out-Null

$wxsPath = Join-Path $repoRoot "packaging\\PillowLock.wxs"
$msiPath = Join-Path $distDir ("PillowLock-{0}-x64.msi" -f $appVersion)

& $wixExe build `
    $wxsPath `
    -arch x64 `
    -d "AppVersion=$appVersion" `
    -d "RepoRoot=$repoRoot" `
    -d "BuildOutputDir=$(Join-Path $repoRoot 'target\\release')" `
    -o $msiPath

if ($LASTEXITCODE -ne 0) {
    throw "MSI build failed."
}

Write-Host "Built MSI:" $msiPath
