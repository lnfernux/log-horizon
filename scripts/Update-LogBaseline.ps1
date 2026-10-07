[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ArchivePath,

    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$ExpectedVersion,

    [string]$ModuleRoot = (Split-Path -Parent $PSScriptRoot)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Only files the module reads at runtime are vendored; anything else in the release is ignored.
$bundledFiles = @(
    'auxiliary-plan-tables.json',
    'basic-plan-tables.json',
    'custom-classifications-example.json',
    'field-frequency-stats.json',
    'high-value-fields.json',
    'implicit-consumers.json',
    'log-classifications.json',
    'shared-table-sources.json'
)
$supportedSchemaMajor = 1
$markerName = 'baseline-version.json'

$resolvedArchive = (Resolve-Path -LiteralPath $ArchivePath).Path
$moduleDataPath = Join-Path $ModuleRoot 'Data'
$moduleVersion = [version](Import-PowerShellDataFile -LiteralPath (Join-Path $ModuleRoot 'LogHorizon.psd1')).ModuleVersion
$temporaryPath = Join-Path ([System.IO.Path]::GetTempPath()) "log-baseline-$([guid]::NewGuid())"
$extractPath = Join-Path $temporaryPath 'archive'
$backupPath = Join-Path $temporaryPath 'backup'
$copyStarted = $false

try {
    Expand-Archive -LiteralPath $resolvedArchive -DestinationPath $extractPath
    $baselineDataPath = Join-Path $extractPath 'data'
    $baselineManifestPath = Join-Path $baselineDataPath 'manifest.json'
    if (-not (Test-Path -LiteralPath $baselineManifestPath -PathType Leaf)) {
        throw 'The baseline archive does not contain data/manifest.json.'
    }

    $baselineManifest = Get-Content -LiteralPath $baselineManifestPath -Raw | ConvertFrom-Json
    $dataVersion = [string]$baselineManifest.dataVersion
    if ($dataVersion -notmatch '^\d+\.\d+\.\d+$') {
        throw "Baseline dataVersion '$dataVersion' is not a release version."
    }
    if ($ExpectedVersion -and $dataVersion -ne $ExpectedVersion) {
        throw "Baseline manifest version $dataVersion does not match the expected release version $ExpectedVersion."
    }

    $schemaVersion = [version]$baselineManifest.schemaVersion
    if ($schemaVersion.Major -ne $supportedSchemaMajor) {
        throw "Baseline schema $schemaVersion is not supported. Log Horizon reads schema $supportedSchemaMajor.x."
    }

    $sourceRevision = [string]$baselineManifest.source.revision
    if ($sourceRevision -notmatch '^[a-f0-9]{40}$') {
        throw "Baseline source revision '$sourceRevision' is not a commit SHA."
    }

    $minimumVersion = [version]$baselineManifest.source.minimumLogHorizonVersion
    if ($moduleVersion -lt $minimumVersion) {
        throw "Baseline $dataVersion requires Log Horizon $minimumVersion or newer."
    }

    $fileHashes = [ordered]@{}
    foreach ($fileName in $bundledFiles) {
        $expectedHash = $baselineManifest.files.PSObject.Properties[$fileName]
        if (-not $expectedHash) {
            throw "The baseline manifest does not list $fileName."
        }

        $sourceFile = Join-Path $baselineDataPath $fileName
        if (-not (Test-Path -LiteralPath $sourceFile -PathType Leaf)) {
            throw "The baseline archive is missing $fileName."
        }

        $actualHash = (Get-FileHash -LiteralPath $sourceFile -Algorithm SHA256).Hash
        if ($actualHash -ne $expectedHash.Value) {
            throw "Checksum mismatch for $fileName."
        }
        $fileHashes[$fileName] = $actualHash
    }

    New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
    foreach ($fileName in @($bundledFiles) + $markerName) {
        $targetFile = Join-Path $moduleDataPath $fileName
        if (Test-Path -LiteralPath $targetFile -PathType Leaf) {
            Copy-Item -LiteralPath $targetFile -Destination $backupPath
        }
    }

    $copyStarted = $true
    foreach ($fileName in $bundledFiles) {
        Copy-Item -LiteralPath (Join-Path $baselineDataPath $fileName) -Destination (Join-Path $moduleDataPath $fileName) -Force
    }

    $versionMarker = [ordered]@{
        dataVersion = $dataVersion
        schemaVersion = $schemaVersion.ToString()
        sourceRepository = $baselineManifest.source.repository
        sourceRevision = $sourceRevision
        files = $fileHashes
    }
    $markerJson = (($versionMarker | ConvertTo-Json -Depth 5) + "`n").Replace("`r`n", "`n")
    [System.IO.File]::WriteAllText((Join-Path $moduleDataPath $markerName), $markerJson, [System.Text.UTF8Encoding]::new($false))
    $copyStarted = $false
    Write-Host "Updated Log Horizon to baseline $dataVersion."
}
catch {
    if ($copyStarted) {
        foreach ($fileName in @($bundledFiles) + $markerName) {
            $backupFile = Join-Path $backupPath $fileName
            $targetFile = Join-Path $moduleDataPath $fileName
            if (Test-Path -LiteralPath $backupFile -PathType Leaf) {
                Copy-Item -LiteralPath $backupFile -Destination $targetFile -Force
            }
            elseif (Test-Path -LiteralPath $targetFile -PathType Leaf) {
                Remove-Item -LiteralPath $targetFile -Force
            }
        }
    }
    throw
}
finally {
    if (Test-Path -LiteralPath $temporaryPath) {
        Remove-Item -LiteralPath $temporaryPath -Recurse -Force
    }
}
