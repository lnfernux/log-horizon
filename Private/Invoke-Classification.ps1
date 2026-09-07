function Invoke-Classification {
    <#
    .SYNOPSIS
        Classifies each ingesting table as primary or secondary using the static
        classification DB plus dynamic heuristics for unknown tables.
    .OUTPUTS
        Hashtable keyed by table name with classification objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$TableUsage,
        [Parameter(Mandatory)][hashtable]$RuleTableCoverage,
        [string[]]$Keywords,
        [string]$CustomClassificationPath
    )

    # Load static classification DB
    $dbPath = Join-Path $PSScriptRoot '..\Data\log-classifications.json'
    $db = Get-Content $dbPath -Raw | ConvertFrom-Json

    $lookup = @{}
    foreach ($entry in $db) {
        $lookup[$entry.tableName] = $entry
    }

    # Merge custom classifications (add or override)
    $customCount = 0
    if ($CustomClassificationPath) {
        $customDb = Get-Content $CustomClassificationPath -Raw | ConvertFrom-Json
        foreach ($entry in @($customDb)) {
            $normalized = ConvertTo-ValidClassificationEntry -Entry $entry -SourceLabel $CustomClassificationPath
            if (-not $normalized) { continue }
            $lookup[$normalized.tableName] = $normalized
            $customCount++
        }
        # Rebuild $db from the merged lookup so keyword gap analysis includes custom entries
        $db = @($lookup.Values)
        Write-Verbose "Merged $customCount custom classification(s) from '$CustomClassificationPath'"
    }

    Write-Verbose "Classification DB loaded: $($db.Count) entries. Classifying $($TableUsage.Count) ingesting table(s)."

    # Classify each ingesting table
    $classified = @{}

    foreach ($table in $TableUsage) {
        $name = $table.TableName

        # Detect _SPLT_CL tables (Sentinel split/filter Data Lake copies)
        if ($name -match '^(.+)_SPLT_CL$') {
            $parentName = $Matches[1]
            $parentEntry = $lookup[$parentName]
            $classified[$name] = [PSCustomObject]@{
                TableName              = $name
                Classification         = 'secondary'
                Category               = 'Split Table (Data Lake)'
                Description            = "Data Lake copy of $parentName via Sentinel split transform"
                RecommendedTier        = 'datalake'
                IsFree                 = $false
                Source                 = 'split-detection'
                Connector              = if ($parentEntry) { $parentEntry.connector } else { 'Unknown' }
                MitreSources           = if ($parentEntry) { $parentEntry.mitreSources } else { @() }
                RecommendedRetentionDays = if ($parentEntry -and $parentEntry.recommendedRetentionDays) { [int]$parentEntry.recommendedRetentionDays } else { 90 }
                IsSplitTable           = $true
                ParentTable            = $parentName
                Status                 = $null
                ReplacedBy             = @()
                IsPlatform             = $false
                XdrStreamable          = $null
            }
            continue
        }

        if ($lookup.ContainsKey($name)) {
            $entry = $lookup[$name]
            $classified[$name] = [PSCustomObject]@{
                TableName              = $name
                Classification         = $entry.classification
                Category               = $entry.category
                Description            = $entry.description
                RecommendedTier        = $entry.recommendedTier
                IsFree                 = $entry.isFree
                Source                 = 'database'
                Connector              = $entry.connector
                MitreSources           = $entry.mitreSources
                RecommendedRetentionDays = if ($entry.recommendedRetentionDays) { [int]$entry.recommendedRetentionDays } else { 90 }
                IsSplitTable           = $false
                ParentTable            = $null
                Status                 = Get-ClassificationEntryStatus -Entry $entry
                ReplacedBy             = @(@($entry.replacedBy) | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") })
                IsPlatform             = ($entry.platform -eq $true)
                XdrStreamable          = if ($entry.PSObject.Properties.Name -contains 'xdrStreamable' -and $null -ne $entry.xdrStreamable) { [bool]$entry.xdrStreamable } else { $null }
            }
        }
        else {
            # Dynamic heuristic classification for unknown tables
            $cls = Resolve-DynamicClassification -TableName $name -RuleCount ($RuleTableCoverage[$name] ?? 0) -MonthlyGB $table.MonthlyGB
            $classified[$name] = $cls
        }
    }

    # Keyword gap analysis: find tables in DB not currently ingesting
    $gaps = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($Keywords -and $Keywords.Count -gt 0) {
        $ingestingNames = @($TableUsage.TableName)
        foreach ($entry in $db) {
            if ($entry.tableName -in $ingestingNames) { continue }

            $matchedKeywords = @($Keywords | Where-Object { Test-ClassificationKeywordMatch -Entry $entry -Keyword $_ })
            if ($matchedKeywords.Count -eq 0) { continue }

            $gaps.Add([PSCustomObject]@{
                TableName      = $entry.tableName
                Connector      = $entry.connector
                Classification = $entry.classification
                Category       = $entry.category
                Description    = $entry.description
                MatchedKeyword = ($matchedKeywords -join ', ')
            })
        }
    }

    [PSCustomObject]@{
        Classifications      = $classified
        KeywordGaps          = @($gaps)
        DatabaseEntries      = $db.Count
        CustomEntries        = $customCount
    }
}

function Test-ClassificationKeywordMatch {
    <#
    .SYNOPSIS
        Case-insensitive substring match of a keyword against a classification
        entry's name, keywords, connector and description. Null-safe.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Entry,
        [AllowEmptyString()][string]$Keyword
    )

    if ([string]::IsNullOrWhiteSpace($Keyword)) { return $false }
    $pattern = "*$Keyword*"
    if ("$($Entry.tableName)" -like $pattern) { return $true }
    if ("$($Entry.connector)" -like $pattern) { return $true }
    if ("$($Entry.description)" -like $pattern) { return $true }
    foreach ($k in @($Entry.keywords)) { if ("$k" -like $pattern) { return $true } }
    $false
}

function ConvertTo-ValidClassificationEntry {
    <#
    .SYNOPSIS
        Validates a custom classification entry and fills defaults. Returns $null
        (with a warning) when tableName is missing or classification is not
        primary/secondary.
    #>
    [CmdletBinding()]
    param(
        [object]$Entry,
        [string]$SourceLabel = 'custom classifications'
    )

    if ($null -eq $Entry) { return $null }
    $name = "$($Entry.tableName)".Trim()
    if ([string]::IsNullOrWhiteSpace($name)) {
        Write-Warning "Skipping custom classification without tableName in $SourceLabel."
        return $null
    }
    $cls = "$($Entry.classification)".Trim().ToLowerInvariant()
    if ($cls -notin 'primary', 'secondary') {
        Write-Warning "Skipping custom classification '$name': classification must be primary or secondary (got '$($Entry.classification)')."
        return $null
    }

    $tier = "$($Entry.recommendedTier)".Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($tier)) { $tier = 'analytics' }
    elseif ($tier -in 'datalake', 'auxiliary', 'lake', 'data lake') { $tier = 'datalake' }
    elseif ($tier -ne 'analytics') {
        Write-Warning "Custom classification '$name': recommendedTier must be analytics or datalake (got '$($Entry.recommendedTier)'); using analytics."
        $tier = 'analytics'
    }

    $retention = 90
    $parsed = 0
    if ($null -ne $Entry.recommendedRetentionDays -and [int]::TryParse("$($Entry.recommendedRetentionDays)", [ref]$parsed) -and $parsed -gt 0) { $retention = $parsed }

    $isFree = ConvertTo-ClassificationBoolean -Value $Entry.isFree
    if ($null -eq $isFree) { $isFree = $false }

    $normalized = [ordered]@{
        tableName                = $name
        connector                = if ([string]::IsNullOrWhiteSpace("$($Entry.connector)")) { 'Custom' } else { "$($Entry.connector)" }
        classification           = $cls
        category                 = if ([string]::IsNullOrWhiteSpace("$($Entry.category)")) { 'Custom' } else { "$($Entry.category)" }
        description              = if ($null -eq $Entry.description) { '' } else { "$($Entry.description)" }
        keywords                 = @(@($Entry.keywords) | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") } | ForEach-Object { "$_" })
        mitreSources             = @(@($Entry.mitreSources) | Where-Object { $null -ne $_ })
        recommendedTier          = $tier
        isFree                   = $isFree
        recommendedRetentionDays = $retention
    }

    # Optional lifecycle keys pass through when valid
    $status = Get-ClassificationEntryStatus -Entry $Entry
    if ($status) { $normalized.status = $status }
    elseif (-not [string]::IsNullOrWhiteSpace("$($Entry.status)")) { Write-Warning "Custom classification '$name': status must be deprecated or legacy (got '$($Entry.status)'); ignoring." }
    $replacedBy = @(@($Entry.replacedBy) | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") } | ForEach-Object { "$_" })
    if ($replacedBy.Count -gt 0) { $normalized.replacedBy = $replacedBy }
    $platform = ConvertTo-ClassificationBoolean -Value $Entry.platform
    if ($null -ne $platform) { $normalized.platform = $platform }
    $xdrStreamable = ConvertTo-ClassificationBoolean -Value $Entry.xdrStreamable
    if ($null -ne $xdrStreamable) { $normalized.xdrStreamable = $xdrStreamable }

    [PSCustomObject]$normalized
}

function ConvertTo-ClassificationBoolean {
    <#
    .SYNOPSIS
        Nullable boolean from a JSON value: real booleans pass through, the strings
        true/false parse, anything else (including "false" cast the wrong way) is $null.
    #>
    [CmdletBinding()]
    param([object]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value }
    $parsed = $false
    if ([bool]::TryParse("$Value".Trim(), [ref]$parsed)) { return $parsed }
    $null
}

function Get-ClassificationEntryStatus {
    <#
    .SYNOPSIS
        Returns 'deprecated' or 'legacy' from an entry's status key, or $null
        when the key is absent or holds any other value.
    #>
    [CmdletBinding()]
    param([object]$Entry)

    if ($null -eq $Entry) { return $null }
    $s = "$($Entry.status)".Trim().ToLowerInvariant()
    if ($s -in 'deprecated', 'legacy') { return $s }
    $null
}

function Resolve-DynamicClassification {
    <#
    .SYNOPSIS
        Heuristic classifier for tables not in the static DB.
    .DESCRIPTION
        Order of evaluation: security-related name tokens (PascalCase-aware) ->
        infrastructure telemetry tokens -> tables referenced by analytics rules ->
        Microsoft first-party name prefixes -> generic *Logs names -> high volume
        with no detections -> unknown.
    #>
    [CmdletBinding()]
    param(
        [string]$TableName,
        [int]$RuleCount,
        [double]$MonthlyGB
    )

    $classification = 'unknown'
    $category = 'Unknown / Custom'
    $reason = 'Not found in classification database'
    $tier = 'analytics'

    # Tokens must start a PascalCase word (start of name, or after a lowercase letter, digit or underscore)
    $primaryTokens   = @('Alert', 'Incident', 'Threat', 'Security', 'SignIn', 'Signin', 'Logon', 'Login', 'Audit', 'Risk', 'Anomal', 'Detection')
    $secondaryTokens = @('Flow', 'Metric', 'Diagnostic', 'Perf', 'Heartbeat', 'Health', 'Trace', 'Inventory', 'Usage', 'Telemetry')
    $tokenPattern = { param($tokens) '(^|[a-z0-9_])(' + ($tokens -join '|') + ')' }

    $matchesPrimary   = @($primaryTokens   | Where-Object { $TableName -cmatch (& $tokenPattern @($_)) })
    $matchesSecondary = @($secondaryTokens | Where-Object { $TableName -cmatch (& $tokenPattern @($_)) })
    $isMicrosoftNative = ($TableName -notmatch '_CL$') -and ($TableName -cmatch '^(AAD|Microsoft|Graph|Azure|Defender|MDC|Purview|Entra|Sentinel|Office|Intune|Windows)')

    if ($matchesPrimary.Count -gt 0) {
        $classification = 'primary'
        $category = 'Heuristic: Security-related name pattern'
        $reason = "Table name matches primary pattern: $($matchesPrimary -join ', ')"
        $tier = 'analytics'
    }
    elseif ($matchesSecondary.Count -gt 0) {
        $classification = 'secondary'
        $category = 'Heuristic: Infrastructure/telemetry name pattern'
        $reason = "Table name matches secondary pattern: $($matchesSecondary -join ', ')"
        $tier = 'datalake'
    }
    elseif ($RuleCount -gt 0) {
        $classification = 'primary'
        $category = 'Heuristic: Has active analytics rules'
        $reason = "Referenced by $RuleCount analytics rule(s)"
        $tier = 'analytics'
    }
    elseif ($isMicrosoftNative) {
        $classification = 'primary'
        $category = 'Heuristic: Microsoft first-party table'
        $reason = 'Microsoft-provided table not yet in the classification database; review and add it'
        $tier = 'analytics'
    }
    elseif ($TableName -cmatch 'Logs?(_CL)?$') {
        $classification = 'secondary'
        $category = 'Heuristic: Generic log table'
        $reason = 'Generic *Log(s) table name with no security token, rules or Microsoft prefix'
        $tier = 'datalake'
    }
    elseif ($MonthlyGB -gt 10 -and $RuleCount -eq 0) {
        $classification = 'secondary'
        $category = 'Heuristic: High volume, no detections'
        $reason = "High volume ($([math]::Round($MonthlyGB, 1)) GB/mo) with zero detection rules"
        $tier = 'datalake'
    }

    # Custom tables (_CL suffix)
    if ($TableName -match '_CL$') {
        $category = "Custom Log: $category"
    }

    [PSCustomObject]@{
        TableName              = $TableName
        Classification         = $classification
        Category               = $category
        Description            = $reason
        RecommendedTier        = $tier
        IsFree                 = $false
        Source                 = 'heuristic'
        Connector              = 'Unknown'
        MitreSources           = @()
        RecommendedRetentionDays = 90
        IsSplitTable           = $false
        ParentTable            = $null
        Status                 = $null
        ReplacedBy             = @()
        IsPlatform             = $false
        XdrStreamable          = $null
    }
}
