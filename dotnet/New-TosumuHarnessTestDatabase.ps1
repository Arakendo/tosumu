[CmdletBinding()]
param(
    [string]$Path = (Join-Path $PSScriptRoot '_scratch\harness-demo.tsm'),
    [ValidateSet('Tiny', 'Branchy', 'Wide')]
    [string]$Dataset = 'Branchy',
    [int]$RecordCount,
    [ValidateSet('debug', 'release')]
    [string]$Profile = 'debug',
    [switch]$SkipBuild,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function Resolve-OutputPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputPath
    )

    if ([System.IO.Path]::IsPathRooted($InputPath)) {
        $resolved = [System.IO.Path]::GetFullPath($InputPath)
    }
    else {
        $resolved = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $InputPath))
    }

    if ([string]::IsNullOrWhiteSpace([System.IO.Path]::GetExtension($resolved))) {
        return "$resolved.tsm"
    }

    return $resolved
}

function Get-DefaultRecordCount {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SelectedDataset
    )

    switch ($SelectedDataset) {
        'Tiny' { return 16 }
        'Branchy' { return 128 }
        'Wide' { return 256 }
        default { throw "Unsupported dataset: $SelectedDataset" }
    }
}

function Get-ValueWidth {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SelectedDataset
    )

    switch ($SelectedDataset) {
        'Tiny' { return 32 }
        'Branchy' { return 96 }
        'Wide' { return 160 }
        default { throw "Unsupported dataset: $SelectedDataset" }
    }
}

function Ensure-TosumuCli {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,
        [Parameter(Mandatory = $true)]
        [string]$BuildProfile,
        [Parameter(Mandatory = $true)]
        [bool]$ShouldBuild
    )

    $cliPath = Join-Path $Root ("target\{0}\tosumu.exe" -f $BuildProfile)
    if ((Test-Path $cliPath) -and -not $ShouldBuild) {
        return $cliPath
    }

    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if ($null -eq $cargo) {
        throw 'cargo is required to build the tosumu CLI for this helper script.'
    }

    if ($ShouldBuild -or -not (Test-Path $cliPath)) {
        Write-Host "Building tosumu CLI ($BuildProfile)..."
        $arguments = @('build', '-p', 'tosumu-cli')
        if ($BuildProfile -eq 'release') {
            $arguments += '--release'
        }

        & $cargo.Source @arguments
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build failed with exit code $LASTEXITCODE"
        }
    }

    if (-not (Test-Path $cliPath)) {
        throw "Expected CLI binary was not produced: $cliPath"
    }

    return $cliPath
}

function Invoke-Tosumu {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CliPath,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & $CliPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "tosumu failed with exit code ${LASTEXITCODE}: $($Arguments -join ' ')"
    }
}

function New-SeedRow {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Index,
        [Parameter(Mandatory = $true)]
        [int]$ValueWidth
    )

    $group = [int][math]::Floor($Index / 16)
    $bucket = [char](65 + ($Index % 26))
    $key = 'demo/{0:D3}/{1}/key-{2:D4}' -f $group, $bucket, $Index

    $prefix = 'value-{0:D4}-' -f $Index
    $suffixLength = [Math]::Max(0, $ValueWidth - $prefix.Length)
    $suffix = 'x' * $suffixLength
    $value = "$prefix$suffix"

    return @{
        Key = $key
        Value = $value
    }
}

$resolvedPath = Resolve-OutputPath -InputPath $Path
$parentDirectory = Split-Path -Parent $resolvedPath
if (-not [string]::IsNullOrWhiteSpace($parentDirectory) -and -not (Test-Path $parentDirectory)) {
    New-Item -ItemType Directory -Path $parentDirectory -Force | Out-Null
}

if (Test-Path $resolvedPath) {
    if (-not $Force) {
        throw "Database already exists: $resolvedPath`nUse -Force to overwrite it."
    }

    Remove-Item -Force $resolvedPath
}

$effectiveRecordCount = if ($PSBoundParameters.ContainsKey('RecordCount')) {
    $RecordCount
}
else {
    Get-DefaultRecordCount -SelectedDataset $Dataset
}

if ($effectiveRecordCount -lt 1) {
    throw 'RecordCount must be at least 1.'
}

$valueWidth = Get-ValueWidth -SelectedDataset $Dataset
$cliExe = Ensure-TosumuCli -Root $repoRoot -BuildProfile $Profile -ShouldBuild:(-not $SkipBuild)

Write-Host "Creating auth-only harness test database: $resolvedPath"
Invoke-Tosumu -CliPath $cliExe -Arguments @('init', $resolvedPath)

Write-Host "Seeding $effectiveRecordCount records ($Dataset dataset)..."
for ($index = 0; $index -lt $effectiveRecordCount; $index++) {
    $row = New-SeedRow -Index $index -ValueWidth $valueWidth
    Invoke-Tosumu -CliPath $cliExe -Arguments @('put', $resolvedPath, $row.Key, $row.Value)
}

Write-Host ''
Write-Host 'Harness test database created.'
Write-Host ("Path: {0}" -f $resolvedPath)
Write-Host ("Dataset: {0}" -f $Dataset)
Write-Host ("Records: {0}" -f $effectiveRecordCount)
Write-Host ''
Write-Host 'Open this file in Tosumu.WpfHarness to inspect it.'
Write-Host 'Note: this helper intentionally creates an auth-only database so it stays non-interactive.'