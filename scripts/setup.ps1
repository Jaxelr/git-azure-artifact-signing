[CmdletBinding()]
param(
    [Parameter()]
    [string] $MetadataPath = 'C:\tools\AcsUnitTest\metadata.scus.json',

    [Parameter()]
    [string] $Principal
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = (& git rev-parse --show-toplevel 2>$null)
if (-not $repositoryRoot) {
    throw 'Run this script from inside the Git repository.'
}

$gitDirectory = (& git rev-parse --path-format=absolute --git-dir)
$outputDirectory = Join-Path $gitDirectory 'artifact-signing'
$signerPath = Join-Path $outputDirectory 'git-acs-sign.exe'
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

Push-Location $repositoryRoot
try {
    & go build -o $signerPath '.\cmd\git-acs-sign'
    if ($LASTEXITCODE -ne 0) {
        throw "go build failed with exit code $LASTEXITCODE."
    }

    $setupArguments = @(
        'setup',
        '--metadata', (Resolve-Path -LiteralPath $MetadataPath).Path,
        '--program', $signerPath
    )
    if ($Principal) {
        $setupArguments += @('--principal', $Principal)
    }

    & $signerPath @setupArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Artifact Signing setup failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
