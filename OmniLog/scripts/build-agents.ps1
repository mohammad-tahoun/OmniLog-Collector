# Force-Fields Agent Cross-Compilation Script (PowerShell)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$AgentDir = Join-Path $RootDir "agent"
$BinDir = Join-Path $RootDir "bin"

if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   COMPILING FORCE-FIELDS AGENT (WINDOWS & LINUX AMD64)   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

Set-Location $AgentDir

Write-Host "[+] Compiling Windows AMD64 binary..." -ForegroundColor Yellow
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go build -ldflags="-s -w" -o (Join-Path $BinDir "forcefields-agent-windows-amd64.exe") ./cmd/agent
Write-Host "[✓] Built: $BinDir\forcefields-agent-windows-amd64.exe" -ForegroundColor Green

Write-Host "[+] Compiling Linux AMD64 binary..." -ForegroundColor Yellow
$env:GOOS = "linux"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go build -ldflags="-s -w" -o (Join-Path $BinDir "forcefields-agent-linux-amd64") ./cmd/agent
Write-Host "[✓] Built: $BinDir\forcefields-agent-linux-amd64" -ForegroundColor Green

Write-Host "==========================================================" -ForegroundColor Cyan
Get-ChildItem -Path $BinDir
Write-Host "==========================================================" -ForegroundColor Cyan
