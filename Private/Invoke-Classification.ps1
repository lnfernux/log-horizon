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
        foreach ($entry in $customDb) {
            if (-not $entry.tableName) { continue }
            $lookup[$entry.tableName] = $entry
            $customCount++
        }
        # Rebuild $db from the merged lookup so keyword gap analysis includes custom entries
        $db = $lookup.Values
        Write-Verbose "Merged $customCount custom classification(s) from '$CustomClassificationPath'"
    }

    # Classify each ingesting table
    $classified = @{}

    foreach ($table in $TableUsage) {
        $name = $table.TableName

        if ($lookup.ContainsKey($name)) {
            $entry = $lookup[$name]
            $classified[$name] = [PSCustomObject]@{
                TableName       = $name
                Classification  = $entry.classification
                Category        = $entry.category
                Description     = $entry.description
                RecommendedTier = $entry.recommendedTier
                IsFree          = $entry.isFree
                Source          = 'database'
                Connector       = $entry.connector
                MitreSources    = $entry.mitreSources
            }
        }
        else {
            # Dynamic heuristic classification for unknown tables
            $cls = Resolve-DynamicClassification -TableName $name -RuleCount ($RuleTableCoverage[$name] ?? 0) -MonthlyGB $table.MonthlyGB
            $classified[$name] = $cls
        }
    }

    # Keyword gap analysis: find tables in DB not currently ingesting
    $gaps = @()
    if ($Keywords -and $Keywords.Count -gt 0) {
        $ingestingNames = $TableUsage.TableName
        foreach ($entry in $db) {
            if ($entry.tableName -in $ingestingNames) { continue }

            $matched = $false
            foreach ($kw in $Keywords) {
                $kwLower = $kw.ToLower()
                if ($entry.tableName.ToLower().Contains($kwLower) -or
                    ($entry.keywords | Where-Object { $_.ToLower().Contains($kwLower) }) -or
                    $entry.connector.ToLower().Contains($kwLower) -or
                    $entry.description.ToLower().Contains($kwLower)) {
                    $matched = $true
                    break
                }
            }

            if ($matched) {
                $gaps += [PSCustomObject]@{
                    TableName      = $entry.tableName
                    Connector      = $entry.connector
                    Classification = $entry.classification
                    Category       = $entry.category
                    Description    = $entry.description
                    MatchedKeyword = ($Keywords | Where-Object {
                        $kl = $_.ToLower()
                        $entry.tableName.ToLower().Contains($kl) -or
                        ($entry.keywords | Where-Object { $_.ToLower().Contains($kl) }) -or
                        $entry.connector.ToLower().Contains($kl)
                    }) -join ', '
                }
            }
        }
    }

    [PSCustomObject]@{
        Classifications      = $classified
        KeywordGaps          = $gaps
        DatabaseEntries      = $db.Count
        CustomEntries        = $customCount
    }
}

function Resolve-DynamicClassification {
    <#
    .SYNOPSIS
        Heuristic classifier for tables not in the static DB.
    #>
    param(
        [string]$TableName,
        [int]$RuleCount,
        [double]$MonthlyGB
    )

    $classification = 'unknown'
    $category = 'Unknown / Custom'
    $reason = 'Not found in classification database'
    $tier = 'analytics'

    # Heuristic rules
    $primaryPatterns = @('Alert', 'Incident', 'Threat', 'Security', 'Signin', 'Logon', 'Audit', 'Risk', 'Anomal')
    $secondaryPatterns = @('Flow', 'Metric', 'Diagnostic', 'Perf', 'Heartbeat', 'Health', 'Trace', 'Log$', 'Inventory')

    $matchesPrimary   = $primaryPatterns   | Where-Object { $TableName -match $_ }
    $matchesSecondary = $secondaryPatterns  | Where-Object { $TableName -match $_ }

    if ($matchesPrimary) {
        $classification = 'primary'
        $category = 'Heuristic: Security-related name pattern'
        $reason = "Table name matches primary pattern: $($matchesPrimary -join ', ')"
        $tier = 'analytics'
    }
    elseif ($matchesSecondary) {
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
        TableName       = $TableName
        Classification  = $classification
        Category        = $category
        Description     = $reason
        RecommendedTier = $tier
        IsFree          = $false
        Source          = 'heuristic'
        Connector       = 'Unknown'
        MitreSources    = @()
    }
}
