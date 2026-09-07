function Get-CollectionCacheKey {
    <#
    .SYNOPSIS
        Deterministic cache key for a Phase 1 collection: SHA-256 over every input
        that changes what is collected or how it is priced, plus the module version
        so a cache written by an older module shape is never reused.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$WorkspaceName,
        [int]$DaysBack = 90,
        [int]$DetectionLookbackDays = 90,
        [bool]$IncludeDefenderXDR = $false,
        [bool]$IncludeDetectionAnalyzer = $false,
        [decimal]$PricePerGB = 5.59,
        [decimal]$BasicPricePerGB = 1.15,
        [decimal]$LakePricePerGB = 0.20,
        [string]$ModuleVersion = ''
    )

    $inv = [cultureinfo]::InvariantCulture
    $material = (@(
        $SubscriptionId.ToLowerInvariant()
        $ResourceGroup.ToLowerInvariant()
        $WorkspaceName.ToLowerInvariant()
        "days=$DaysBack"
        "detdays=$DetectionLookbackDays"
        "xdr=$IncludeDefenderXDR"
        "da=$IncludeDetectionAnalyzer"
        "price=$($PricePerGB.ToString($inv))"
        "basic=$($BasicPricePerGB.ToString($inv))"
        "lake=$($LakePricePerGB.ToString($inv))"
        "v=$ModuleVersion"
    ) -join '|')

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($material))
        ([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

function Get-CollectionCachePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Key,
        [string]$CachePath
    )

    if ([string]::IsNullOrWhiteSpace($CachePath)) {
        $base = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } elseif ($env:XDG_CACHE_HOME) { $env:XDG_CACHE_HOME } else { Join-Path $HOME '.cache' }
        $CachePath = Join-Path $base 'LogHorizon\cache'
    }
    Join-Path $CachePath "collection-$Key.clixml"
}

function Get-CollectionCache {
    <#
    .SYNOPSIS
        Returns a cached Phase 1 collection when a fresh enough entry exists.
    .OUTPUTS
        PSCustomObject with Data (the cached collection), SavedAt, AgeMinutes and
        Path, or $null on a miss (absent, expired, unreadable, wrong shape).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Key,
        [string]$CachePath,
        [int]$MaxAgeMinutes = 60
    )

    $file = Get-CollectionCachePath -Key $Key -CachePath $CachePath
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        Write-Verbose "Cache miss (no file): $file"
        return $null
    }

    try {
        $envelope = Import-Clixml -LiteralPath $file
    }
    catch {
        Write-Warning "Cache file could not be read and will be ignored: $file ($($_.Exception.Message))"
        return $null
    }

    if (-not $envelope -or -not $envelope.PSObject.Properties['SavedAt'] -or -not $envelope.PSObject.Properties['Data'] -or $envelope.Key -ne $Key) {
        Write-Verbose "Cache miss (unexpected shape): $file"
        return $null
    }

    $savedAt = [datetime]$envelope.SavedAt
    $age = ((Get-Date).ToUniversalTime() - $savedAt.ToUniversalTime()).TotalMinutes
    if ($age -gt $MaxAgeMinutes) {
        Write-Verbose "Cache miss (expired, $([math]::Round($age)) min old): $file"
        return $null
    }

    [PSCustomObject]@{
        Data       = $envelope.Data
        SavedAt    = $savedAt
        AgeMinutes = [math]::Round($age, 1)
        Path       = $file
        Version    = $envelope.Version
    }
}

function Save-CollectionCache {
    <#
    .SYNOPSIS
        Persists a Phase 1 collection with Export-Clixml. The Context (which
        carries tokens) is never written; any property whose name ends in Token
        is stripped defensively as well.
    .OUTPUTS
        The cache file path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][object]$Data,
        [string]$CachePath,
        [string]$Version
    )

    $file = Get-CollectionCachePath -Key $Key -CachePath $CachePath
    $dir = Split-Path -Path $file -Parent
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $safe = [ordered]@{}
    foreach ($p in $Data.PSObject.Properties) {
        if ($p.Name -eq 'Context') { continue }
        if ($p.Name -match '(?i)token$') { continue }
        $safe[$p.Name] = $p.Value
    }

    $envelope = [PSCustomObject]@{
        Key     = $Key
        SavedAt = (Get-Date).ToUniversalTime().ToString('o')
        Version = $Version
        Data    = [PSCustomObject]$safe
    }
    $envelope | Export-Clixml -LiteralPath $file -Depth 12 -Force
    $file
}
