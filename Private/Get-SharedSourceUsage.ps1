function Get-SharedTableSource {
    <#
    .SYNOPSIS
        Loads the bundled shared-table source catalogue (CEF and Syslog sources
        that share CommonSecurityLog or Syslog, identified by a row filter).
    #>
    [CmdletBinding()]
    param([string]$Path = (Join-Path $PSScriptRoot '..\Data\shared-table-sources.json'))

    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    @(Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}

function ConvertTo-KqlGroup {
    <#
    .SYNOPSIS
        Parenthesizes a KQL expression unless one outer pair already encloses it.
        Quoted strings are skipped when matching parentheses.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Kql)

    $text = $Kql.Trim()
    if (-not $text.StartsWith('(')) { return "($text)" }
    $depth = 0
    $quoted = $false
    for ($i = 0; $i -lt $text.Length; $i++) {
        $char = $text[$i]
        if ($char -eq '"' -and ($i -eq 0 -or $text[$i - 1] -ne '\')) { $quoted = -not $quoted }
        if ($quoted) { continue }
        if ($char -eq '(') { $depth++ }
        elseif ($char -eq ')') { $depth-- }
        if ($depth -eq 0 -and $i -lt $text.Length - 1) { return "($text)" }
    }
    $text
}

function Get-SharedSourceHintKql {
    <#
    .SYNOPSIS
        All split hints of a shared source joined with or, or $null when it has none.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Source)

    $hints = @(@($Source.splitHints) | ForEach-Object { "$($_.kql)".Trim() } | Where-Object { $_ })
    if ($hints.Count -eq 0) { return $null }
    if ($hints.Count -eq 1) { return (ConvertTo-KqlGroup $hints[0]) }
    "($(($hints | ForEach-Object { ConvertTo-KqlGroup $_ }) -join ' or '))"
}

function Get-SharedSourceUsageQuery {
    <#
    .SYNOPSIS
        Builds the KQL that attributes billed bytes in a shared table to catalogue
        sources (first matching filter wins) and flags rows matched by the source's
        split hints and by deployed rule conditions.
    .DESCRIPTION
        With -KeyColumns the rows are first summarized by the columns the filters and
        hints read, so the 40-branch case() runs on distinct values, not on every row.
        Rule conditions are evaluated per row before that, because they can read any column.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TableName,
        [Parameter(Mandatory)][array]$Sources,
        [int]$SampleDays = 7,
        [string[]]$RuleConditions = @(),
        [string[]]$KeyColumns = @()
    )

    $sourceCases = ($Sources | ForEach-Object { "$(ConvertTo-KqlGroup $_.filter), `"$($_.sourceId)`"" }) -join ",`n    "
    $hinted = @($Sources | Where-Object { Get-SharedSourceHintKql -Source $_ })
    $hintExpr = if ($hinted.Count -gt 0) {
        "case(" + (($hinted | ForEach-Object { "LogHorizonSource == `"$($_.sourceId)`", $(Get-SharedSourceHintKql -Source $_)" }) -join ",`n    ") + ",`n    false)"
    } else { 'false' }
    $ruleExpr = if (@($RuleConditions).Count -gt 0) { (@($RuleConditions) | ForEach-Object { ConvertTo-KqlGroup $_ }) -join ' or ' } else { 'false' }

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add($TableName)
    $lines.Add("| where TimeGenerated > ago(${SampleDays}d)")
    $lines.Add("| extend LogHorizonRule = $ruleExpr")
    $bytes = '_BilledSize'
    if (@($KeyColumns).Count -gt 0) {
        $lines.Add("| summarize LogHorizonBytes = sum(_BilledSize) by $(@($KeyColumns) -join ', '), LogHorizonRule")
        $bytes = 'LogHorizonBytes'
    }
    $lines.Add("| extend LogHorizonSource = case($sourceCases,`n    `"`")")
    $lines.Add("| extend LogHorizonHint = $hintExpr")
    $lines.Add("| summarize BilledBytes = sum($bytes) by LogHorizonSource, LogHorizonHint, LogHorizonRule")
    $lines -join "`n"
}

function Get-SharedSourceKeyColumn {
    <#
    .SYNOPSIS
        Schema columns read by the catalogue filters and split hints of a table, or
        none when the schema is unknown (the query then evaluates every row).
    #>
    [CmdletBinding()]
    param(
        [array]$Sources = @(),
        [string[]]$SchemaColumns = @()
    )

    $SchemaColumns = @($SchemaColumns | Where-Object { $_ })
    if ($SchemaColumns.Count -eq 0) { return @() }
    $schemaSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$SchemaColumns, [StringComparer]::Ordinal)
    # Any identifier that is a schema column; a missed key column would make the summarize-first query fail
    $expressions = @($Sources | ForEach-Object { $_.filter; Get-SharedSourceHintKql -Source $_ } | Where-Object { $_ })
    $identifiers = @($expressions | ForEach-Object { [regex]::Matches((Remove-KqlLiteral -Kql $_), '\b[A-Za-z_]\w*\b') | ForEach-Object Value })
    @($identifiers | Where-Object { $schemaSet.Contains($_) } | Sort-Object -Unique -CaseSensitive)
}

function Get-SharedTableRuleCondition {
    <#
    .SYNOPSIS
        Where-predicates from enabled rules on the table whose columns all exist in
        the schema, so the split keeps the rows those rules read.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TableName,
        [array]$Rules = @(),
        [string[]]$SchemaColumns = @()
    )

    $conditions = @($Rules | Where-Object { $_.Enabled -and $_.Query -and @($_.Tables) -contains $TableName } |
        ForEach-Object { Get-KqlWhereCondition -Kql $_.Query } | Select-Object -Unique)
    @((Select-KqlConditionInSchema -Conditions $conditions -SchemaColumns $SchemaColumns).Kept)
}

function Get-SharedSourceUsage {
    <#
    .SYNOPSIS
        Measures billed volume per shared-table source in CommonSecurityLog and Syslog.
    .DESCRIPTION
        Runs one summarize query per shared table over a short sample window. Tables
        that are not ingesting, or are not on the Analytics plan (queries on Basic and
        Auxiliary are billed per GB scanned), are skipped. The configured plan from the
        Tables API decides; without it every observed Usage plan must be Analytics.
        A query that fails with rule conditions is retried once without them; other
        failures become warnings.
    .OUTPUTS
        One object per table with TableName, SampleDays, RuleConditions and Rows
        (SourceId, HintMatch, RuleMatch, BilledBytes).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Context,
        [array]$TableUsage = @(),
        [array]$TableRetention = @(),
        [array]$Rules = @(),
        [ValidateRange(1, 30)][int]$SampleDays = 7,
        [array]$Sources = (Get-SharedTableSource)
    )

    $headers = @{
        Authorization  = "Bearer $($Context.LaToken)"
        'Content-Type' = 'application/json'
    }
    $uri = "$(Get-LogHorizonEndpoint -Name LogAnalytics -Context $Context)/workspaces/$($Context.WorkspaceId)/query"

    $results = foreach ($group in ($Sources | Group-Object table)) {
        $usage = $TableUsage | Where-Object TableName -eq $group.Name | Select-Object -First 1
        if (-not $usage -or $usage.MonthlyGB -le 0) { continue }
        $ret = $TableRetention | Where-Object TableName -eq $group.Name | Select-Object -First 1
        $plans = @($usage.ObservedPlans | Where-Object { $_ -and $_ -ne 'Unknown' } | Sort-Object -Unique)
        $isAnalytics = if ($ret -and $ret.Plan) { $ret.Plan -eq 'Analytics' } else { -not ($plans | Where-Object { $_ -ne 'Analytics' }) }
        if (-not $isAnalytics) {
            Write-Verbose "$($group.Name) is not on the Analytics plan; skipping the shared source breakdown."
            continue
        }
        $schema = @(if ($ret -and $ret.Columns) { $ret.Columns })
        $keyColumns = Get-SharedSourceKeyColumn -Sources @($group.Group) -SchemaColumns $schema
        $ruleConditions = @(Get-SharedTableRuleCondition -TableName $group.Name -Rules $Rules -SchemaColumns $schema)
        $response = $null
        foreach ($attempt in 1..2) {
            $query = Get-SharedSourceUsageQuery -TableName $group.Name -Sources @($group.Group) -SampleDays $SampleDays -RuleConditions $ruleConditions -KeyColumns $keyColumns
            try {
                $response = Invoke-AzRestWithRetry -Uri $uri -Method Post -Headers $headers -Body (@{ query = $query } | ConvertTo-Json -Compress)
                break
            }
            catch {
                if ($attempt -eq 1 -and $ruleConditions.Count -gt 0) {
                    Write-Warning "Shared source breakdown for $($group.Name) failed with rule conditions; retrying without them: $($_.Exception.Message)"
                    $ruleConditions = @()
                    continue
                }
                Write-Warning "Shared source breakdown for $($group.Name) skipped: $($_.Exception.Message)"
                break
            }
        }
        if (-not $response) { continue }

        $columns = @($response.tables[0].columns | ForEach-Object name)
        $iSource = [array]::IndexOf($columns, 'LogHorizonSource')
        $iHint = [array]::IndexOf($columns, 'LogHorizonHint')
        $iRule = [array]::IndexOf($columns, 'LogHorizonRule')
        $iBytes = [array]::IndexOf($columns, 'BilledBytes')
        [PSCustomObject]@{
            TableName      = $group.Name
            SampleDays     = $SampleDays
            RuleConditions = $ruleConditions
            Rows           = @(@($response.tables[0].rows) | ForEach-Object {
                [PSCustomObject]@{
                    SourceId    = "$($_[$iSource])"
                    HintMatch   = ConvertTo-UsageBoolean -Value $_[$iHint]
                    RuleMatch   = if ($iRule -ge 0) { ConvertTo-UsageBoolean -Value $_[$iRule] } else { $false }
                    BilledBytes = [double]$_[$iBytes]
                }
            })
        }
    }
    @($results)
}

function Get-SharedTableSplitRule {
    <#
    .SYNOPSIS
        Composes one split condition for a shared table: rows that match stay in
        Analytics, everything else goes to <Table>_SPLT. Matches the baseline explorer.
    #>
    [CmdletBinding()]
    param(
        [array]$Sources = @(),
        [string[]]$RuleConditions = @(),
        [ValidateSet('analytics', 'datalake')][string]$RemainderTier = 'analytics',
        [int]$RemainderRetentionDays = 90
    )

    $analytics = @($Sources | Where-Object recommendedTier -ne 'datalake')
    $lake = @($Sources | Where-Object recommendedTier -eq 'datalake')
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $analytics) { $parts.Add((ConvertTo-KqlGroup $s.filter)) }
    foreach ($s in $lake) {
        $hint = Get-SharedSourceHintKql -Source $s
        if ($hint) { $parts.Add("($(ConvertTo-KqlGroup $s.filter) and $hint)") }
    }
    foreach ($c in @($RuleConditions)) { if ($c) { $parts.Add((ConvertTo-KqlGroup $c)) } }
    # case() because transformations do not list not() as supported
    if ($RemainderTier -eq 'analytics') {
        $parts.Add($(if ($Sources.Count -gt 0) { "case($(($Sources | ForEach-Object { ConvertTo-KqlGroup $_.filter }) -join ' or '), false, true)" } else { 'true' }))
    }

    $tableRetention = @($analytics | ForEach-Object { [int]$_.recommendedRetentionDays }) + @(if ($RemainderTier -eq 'analytics') { $RemainderRetentionDays })
    $splitRetention = @($lake | ForEach-Object { [int]$_.recommendedRetentionDays }) + @(if ($RemainderTier -eq 'datalake') { $RemainderRetentionDays })
    [PSCustomObject]@{
        Condition          = $parts -join "`nor "
        TableRetentionDays = if ($tableRetention.Count) { ($tableRetention | Measure-Object -Maximum).Maximum } else { $null }
        SplitRetentionDays = if ($splitRetention.Count) { ($splitRetention | Measure-Object -Maximum).Maximum } else { $null }
    }
}

function Get-SharedSourceAnalysis {
    <#
    .SYNOPSIS
        Turns measured shared-source volumes into per-source monthly estimates, a
        composed split rule and the volume that rule would move to the data lake.
    .DESCRIPTION
        Each source's share of the sampled billed bytes is applied to the table's
        monthly Usage volume and cost. The remainder (rows no catalogue filter
        matches) follows the table record's recommended tier.
    #>
    [CmdletBinding()]
    param(
        [array]$SharedSourceUsage = @(),
        [array]$TableAnalysis = @(),
        [array]$Sources = @(),
        [array]$Rules = @(),
        [decimal]$LakePricePerGB = 0.20
    )

    $results = foreach ($usage in $SharedSourceUsage) {
        $t = $TableAnalysis | Where-Object TableName -eq $usage.TableName | Select-Object -First 1
        if (-not $t) { continue }
        $tableSources = @($Sources | Where-Object table -eq $usage.TableName)
        $catalogue = @{}
        foreach ($s in $tableSources) { $catalogue[$s.sourceId] = $s }
        $remainderTier = if ($t.RecommendedTier -eq 'datalake') { 'datalake' } else { 'analytics' }

        $bytesBySource = @{}
        $total = 0.0
        $kept = 0.0
        foreach ($row in @($usage.Rows)) {
            $bytes = [double]$row.BilledBytes
            $total += $bytes
            $bytesBySource[$row.SourceId] = [double]$bytesBySource[$row.SourceId] + $bytes
            $src = $catalogue[$row.SourceId]
            $keep = if ([bool]$row.RuleMatch) { $true }
                    elseif (-not $src) { $remainderTier -eq 'analytics' }
                    elseif ($src.recommendedTier -ne 'datalake') { $true }
                    else { [bool]$row.HintMatch -and [bool](Get-SharedSourceHintKql -Source $src) }
            if ($keep) { $kept += $bytes }
        }
        if ($total -le 0) { continue }

        $gbPerByte = $t.MonthlyGB / $total
        $costPerByte = $t.EstMonthlyCostUSD / $total
        $deployed = @($tableSources | Where-Object { $bytesBySource[$_.sourceId] -gt 0 })
        $sourceRows = foreach ($s in $deployed) {
            $bytes = $bytesBySource[$s.sourceId]
            $ruleCount = 0
            if ($s.parser) {
                $pattern = "(?<![\w.$])$([regex]::Escape($s.parser))(?![\w])"
                $ruleCount = @($Rules | Where-Object { $_.Enabled -and (Remove-KqlLiteral -Kql $_.Query) -cmatch $pattern }).Count
            }
            [PSCustomObject]@{
                SourceId                 = $s.sourceId
                DisplayName              = $s.displayName
                RecommendedTier          = $s.recommendedTier
                RecommendedRetentionDays = [int]$s.recommendedRetentionDays
                HasSplitHints            = [bool](Get-SharedSourceHintKql -Source $s)
                Share                    = [math]::Round($bytes / $total, 4)
                MonthlyGB                = [math]::Round($bytes * $gbPerByte, 2)
                EstMonthlyCostUSD        = [math]::Round($bytes * $costPerByte, 2)
                ParserRuleCount          = $ruleCount
            }
        }
        $unmatched = [double]$bytesBySource['']
        $movedGB = ($total - $kept) * $gbPerByte
        $effectivePrice = if ($t.MonthlyGB -gt 0 -and -not $t.IsFree) { $t.EstMonthlyCostUSD / $t.MonthlyGB } else { 0 }
        $ruleConditions = if ($usage.PSObject.Properties.Name -contains 'RuleConditions') { @($usage.RuleConditions) } else { @() }
        $rule = Get-SharedTableSplitRule -Sources $deployed -RuleConditions $ruleConditions -RemainderTier $remainderTier -RemainderRetentionDays ([int]$t.RecommendedRetentionDays)

        [PSCustomObject]@{
            TableName          = $usage.TableName
            SampleDays         = $usage.SampleDays
            MonthlyGB          = $t.MonthlyGB
            Sources            = @($sourceRows | Sort-Object MonthlyGB -Descending)
            UnmatchedShare     = [math]::Round($unmatched / $total, 4)
            UnmatchedMonthlyGB = [math]::Round($unmatched * $gbPerByte, 2)
            RemainderTier      = $remainderTier
            RuleConditionCount = $ruleConditions.Count
            LakeMonthlyGB      = [math]::Round($movedGB, 2)
            SplitCondition     = $rule.Condition
            TableRetentionDays = $rule.TableRetentionDays
            SplitRetentionDays = $rule.SplitRetentionDays
            EstSavingsUSD      = [math]::Max(0.0, [math]::Round($movedGB * ($effectivePrice - [double]$LakePricePerGB), 2))
        }
    }
    @($results)
}
