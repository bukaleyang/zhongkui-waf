# Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
# Copyright (c) 2024 bukale bukale2022@163.com
#
# 下载并校验 lego（Windows）。在 zhongkui-waf 根目录执行：
#   powershell -ExecutionPolicy Bypass -File .\install-lego.ps1
# 可选参数：
#   -InstallPath E:\path\to\zhongkui-waf
#   -Force

param(
    [string]$InstallPath = $PSScriptRoot,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Version = "5.5.2"
$Hashes = @{
    "amd64" = "fc544130a2716329cad73a47b674e3aeea019c4753c3963d259bd45d946bbd34"
    "arm64" = "0eec94ec6834db18d537646a2c2a72fa9dc1e503f65e59ab574caae358a31982"
    "386"   = "22cfb8c782cd38974acc64e71c5a1ff466bcc719c07d42d01cf9623a72f6f24d"
}

$Arch = "386"
if ([Environment]::Is64BitOperatingSystem) {
    if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or $env:PROCESSOR_ARCHITEW6432 -eq "ARM64") {
        $Arch = "arm64"
    } else {
        $Arch = "amd64"
    }
}

if (-not $InstallPath) {
    $InstallPath = (Get-Location).Path
}
if (-not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null
}
$InstallPath = (Resolve-Path $InstallPath).Path

$BinDir = Join-Path $InstallPath "bin"
$LegoPath = Join-Path $BinDir "lego.exe"

if ((Test-Path $LegoPath) -and -not $Force) {
    $InstalledVersion = ""
    try {
        $InstalledVersion = (& $LegoPath --version 2>&1 | Out-String)
    } catch {
        $InstalledVersion = ""
    }
    if ($InstalledVersion -match [regex]::Escape($Version)) {
        Write-Host "lego already installed: $LegoPath"
        Write-Host $InstalledVersion.Trim()
        exit 0
    }
    Write-Host "existing lego version does not match v$Version, reinstalling: $LegoPath"
}

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

$Archive = "lego_v${Version}_windows_${Arch}.zip"
$Url = "https://github.com/go-acme/lego/releases/download/v${Version}/${Archive}"
$TempZip = Join-Path $env:TEMP ("zhongkui-" + [Guid]::NewGuid().ToString("N") + "-" + $Archive)
$TempDir = Join-Path $env:TEMP ("zhongkui-lego-" + [Guid]::NewGuid().ToString("N"))

try {
    Write-Host "downloading $Url"
    Invoke-WebRequest -Uri $Url -OutFile $TempZip -UseBasicParsing

    $ActualHash = (Get-FileHash -Path $TempZip -Algorithm SHA256).Hash.ToLowerInvariant()
    $ExpectedHash = $Hashes[$Arch]
    if (-not $ExpectedHash) {
        throw "unsupported architecture: $Arch"
    }
    if ($ActualHash -ne $ExpectedHash) {
        throw "lego checksum verification failed: expected $ExpectedHash, got $ActualHash"
    }

    Expand-Archive -Path $TempZip -DestinationPath $TempDir -Force
    $Extracted = Join-Path $TempDir "lego.exe"
    if (-not (Test-Path $Extracted)) {
        throw "lego.exe not found in archive"
    }

    Copy-Item -Path $Extracted -Destination $LegoPath -Force
    & $LegoPath --version
    if ($LASTEXITCODE -ne 0) {
        throw "lego failed to start after installation: $LegoPath"
    }

    New-Item -ItemType Directory -Force -Path (Join-Path $InstallPath "data\acme\webroot\.well-known\acme-challenge") | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $InstallPath "data\acme\logs") | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $InstallPath "admin\ssl-certs") | Out-Null

    Write-Host "lego v$Version installed and verified: $LegoPath"
}
finally {
    Remove-Item -Path $TempZip -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
