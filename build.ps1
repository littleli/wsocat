param(
    [ValidateSet("amd64", "arm64", "386")]
    [string]$Architecture = "amd64"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutputDirectory = Join-Path $RepoRoot "dist"
$OutputFile = Join-Path $OutputDirectory "wsocat.exe"
$PreviousGoos = $env:GOOS
$PreviousGoarch = $env:GOARCH
$PreviousCgoEnabled = $env:CGO_ENABLED
$BuildExitCode = 0

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

Push-Location $RepoRoot
try {
    $env:GOOS = "windows"
    $env:GOARCH = $Architecture
    $env:CGO_ENABLED = "0"

    go build -trimpath -ldflags "-s -w" -o $OutputFile ./cmd/wsocat
    $BuildExitCode = $LASTEXITCODE
}
finally {
    Pop-Location
    $env:GOOS = $PreviousGoos
    $env:GOARCH = $PreviousGoarch
    $env:CGO_ENABLED = $PreviousCgoEnabled
}

if ($BuildExitCode -ne 0) {
    exit $BuildExitCode
}

Write-Output "Built $OutputFile"
