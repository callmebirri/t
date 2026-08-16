param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
$vsPath = ""
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
}
if (-not $vsPath) {
    throw "Visual Studio 2022 with MSBuild was not found."
}

$cmake = Join-Path $vsPath "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
$msbuild = Join-Path $vsPath "MSBuild\Current\Bin\MSBuild.exe"

if (-not (Test-Path $cmake)) {
    $cmake = "cmake"
}
if (-not (Test-Path $msbuild)) {
    $msbuild = "msbuild"
}

$tpBuild = Join-Path $root "build\third_party"
New-Item -ItemType Directory -Force -Path $tpBuild | Out-Null

$deps = @(
    @{ Name = "minhook"; Source = "third_party\minhook"; Extra = @() },
    @{ Name = "zlib"; Source = "third_party\zlib"; Extra = @("-DBUILD_SHARED_LIBS=OFF") },
    @{ Name = "brotli"; Source = "third_party\brotli"; Extra = @("-DBUILD_SHARED_LIBS=OFF") }
)

foreach ($dep in $deps) {
    $src = Join-Path $root $dep.Source
    $dst = Join-Path $tpBuild $dep.Name
    $args = @("-S", $src, "-B", $dst, "-A", $Platform, "-T", "v143", "-DCMAKE_CONFIGURATION_TYPES=$Configuration")
    $args += $dep.Extra
    & $cmake @args
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed for $($dep.Name)" }
    & $cmake --build $dst --config $Configuration
    if ($LASTEXITCODE -ne 0) { throw "CMake build failed for $($dep.Name)" }
}

$sln = Join-Path $root "BirriMonitor.sln"
& $msbuild $sln /p:Configuration=$Configuration /p:Platform=$Platform /m
if ($LASTEXITCODE -ne 0) { throw "MSBuild failed" }

Write-Host "Build OK: $Platform $Configuration"
