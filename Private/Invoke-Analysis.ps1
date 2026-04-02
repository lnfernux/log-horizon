function Invoke-Analysis {
    <#
    .SYNOPSIS
        Computes the cost-value matrix and generates prioritised recommendations.
    .OUTPUTS
        PSCustomObject with TableAnalysis (array), Recommendations (array),
        and Summary statistics.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$TableUsage,
        [Parameter(Mandatory)][PSCustomObject]$Classifications,
        [Parameter(Mandatory)][PSCustomObject]$RulesData,
        [Parameter(Mandatory)][PSCustomObject]$HuntingData,
        [PSCustomObject]$DefenderXDR,
        [array]$SocRecommendations,
        [array]$TableRetention,
        [int]$WorkspaceRetentionDays = 0,
        [decimal]$PricePerGB = 5.59,
        [PSCustomObject]$DataTransforms,
        [hashtable]$HighValueFields
    )

    $classMap       = $Classifications.Classifications   # hashtable
    $ruleCoverage   = $RulesData.TableCoverage            # hashtable: table -> count
    $huntCoverage   = $HuntingData.TableCoverage          # hashtable: table -> count
    $xdrCoverage    = if ($DefenderXDR) { $DefenderXDR.XDRTableCoverage } else { @{} }
    $xdrStreaming   = if ($DefenderXDR) { $DefenderXDR.StreamingTables } else { @() }

    # Build retention lookup from Tables API data
    $retentionMap = @{}
    if ($TableRetention) {
        foreach ($tr in $TableRetention) {
            $retentionMap[$tr.TableName] = $tr
        }
    }

    # Build transform lookup from DCR data
    $transformLookup = @{}
    if ($DataTransforms -and $DataTransforms.TableLookup) {
        $transformLookup = $DataTransforms.TableLookup
    }

    # Per-table analysis
    $tableAnalysis = foreach ($table in $TableUsage) {
        $name = $table.TableName
        $cls  = $classMap[$name]

        $ruleCount    = [int]($ruleCoverage[$name])
        $huntCount    = [int]($huntCoverage[$name])
        $xdrRuleCount = [int]($xdrCoverage[$name])
        $totalCoverage = $ruleCount + $huntCount

        # Cost tier
        $costTier = switch ($true) {
            ($table.IsFree)              { 'Free'; break }
            ($table.MonthlyGB -ge 50)    { 'Very High'; break }
            ($table.MonthlyGB -ge 10)    { 'High'; break }
            ($table.MonthlyGB -ge 1)     { 'Medium'; break }
            default                      { 'Low' }
        }

        # Detection value tier
        $detectionTier = switch ($true) {
            ($totalCoverage -ge 10) { 'High'; break }
            ($totalCoverage -ge 3)  { 'Medium'; break }
            ($totalCoverage -ge 1)  { 'Low'; break }
            default                 { 'None' }
        }

        $classification = if ($cls) { $cls.Classification } else { 'unknown' }

        # Combined assessment
        $assessment = Get-Assessment -Classification $classification `
                                      -CostTier $costTier `
                                      -DetectionTier $detectionTier `
                                      -RuleCount $ruleCount `
                                      -IsFree $table.IsFree

        $isXDRStreaming = $name -in $xdrStreaming

        # Retention data
        $ret = $retentionMap[$name]
        $recommendedRetention = if ($cls -and $null -ne $cls.RecommendedRetentionDays -and $cls.RecommendedRetentionDays -gt 0) { [int]$cls.RecommendedRetentionDays } else { 90 }
        $actualTotal = if ($ret) { [int]$ret.TotalRetentionInDays } else { $null }
        $actualInteractive = if ($ret) { [int]$ret.RetentionInDays } else { $null }
        $tablePlan = if ($ret) { $ret.Plan } else { $null }
        $tableSubType = if ($ret) { $ret.TableSubType } else { $null }
        # Compliant = at least 90 days total retention (baseline)
        $retentionCompliant = if ($null -ne $actualTotal -and $tablePlan -eq 'Analytics') { $actualTotal -ge 90 } else { $null }
        # Can improve = meets 90d baseline but below category-specific recommendation
        $retentionCanImprove = if ($retentionCompliant -and $recommendedRetention -gt 90) { $actualTotal -lt $recommendedRetention } else { $false }

        # Transform data
        $tableTransforms = $transformLookup[$name]
        $hasTransform = $null -ne $tableTransforms -and $tableTransforms.Count -gt 0
        $transformTypes = if ($hasTransform) { @($tableTransforms | ForEach-Object { $_.TransformType } | Select-Object -Unique) } else { @() }
        $transformKql = if ($hasTransform) { @($tableTransforms | ForEach-Object { $_.TransformKql }) } else { @() }

        # Split table detection
        $isSplitTable = if ($cls) { [bool]$cls.IsSplitTable } else { $false }
        $parentTable = if ($cls) { $cls.ParentTable } else { $null }

        [PSCustomObject]@{
            TableName                    = $name
            Classification               = $classification
            Category                     = if ($cls) { $cls.Category } else { 'Unknown' }
            MonthlyGB                    = $table.MonthlyGB
            EstMonthlyCostUSD            = $table.EstMonthlyCostUSD
            IsFree                       = $table.IsFree
            AnalyticsRules               = $ruleCount
            HuntingQueries               = $huntCount
            XDRRules                     = $xdrRuleCount
            TotalCoverage                = $totalCoverage
            CostTier                     = $costTier
            DetectionTier                = $detectionTier
            Assessment                   = $assessment
            IsXDRStreaming               = $isXDRStreaming
            RecommendedTier              = if ($cls) { $cls.RecommendedTier } else { 'analytics' }
            ActualRetentionDays          = $actualTotal
            ActualInteractiveRetentionDays = $actualInteractive
            RecommendedRetentionDays     = $recommendedRetention
            TablePlan                    = $tablePlan
            TableSubType                 = $tableSubType
            RetentionCompliant           = $retentionCompliant
            RetentionCanImprove          = $retentionCanImprove
            HasTransform                 = $hasTransform
            TransformTypes               = $transformTypes
            TransformKql                 = $transformKql
            IsSplitTable                 = $isSplitTable
            ParentTable                  = $parentTable
        }
    }

    # Generate recommendations
    $recommendations = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($t in $tableAnalysis) {
        # 1. Data lake candidates: secondary + high cost + low rules
        if ($t.Classification -eq 'secondary' -and
            $t.CostTier -in @('High', 'Very High') -and
            $t.DetectionTier -in @('None', 'Low')) {

            $savings = [math]::Round($t.EstMonthlyCostUSD * 0.95, 2)  # ~95% savings at data lake pricing
            $recommendations.Add([PSCustomObject]@{
                Priority     = 'High'
                Type         = 'DataLake'
                TableName    = $t.TableName
                Title        = "Move $($t.TableName) to Data Lake tier"
                Detail       = "Secondary source ingesting $($t.MonthlyGB) GB/mo with $($t.TotalCoverage) detection(s). " +
                               "Create summary rules to aggregate key events back to analytics tier."
                EstSavingsUSD = $savings
                CurrentCost   = $t.EstMonthlyCostUSD
            })
        }

        # 2. Zero-detection high-cost tables
        if (-not $t.IsFree -and
            $t.CostTier -in @('High', 'Very High') -and
            $t.DetectionTier -eq 'None') {

            $recommendations.Add([PSCustomObject]@{
                Priority     = 'High'
                Type         = 'LowValue'
                TableName    = $t.TableName
                Title        = "$($t.TableName) has zero detections"
                Detail       = "Ingesting $($t.MonthlyGB) GB/mo (~`$$($t.EstMonthlyCostUSD)/mo) with no analytics rules or hunting queries. " +
                               "Consider: add analytics rules, apply ingest-time filtering, or move to data lake."
                EstSavingsUSD = $t.EstMonthlyCostUSD
                CurrentCost   = $t.EstMonthlyCostUSD
            })
        }

        # 3. XDR streaming optimization
        if ($t.IsXDRStreaming -and $t.AnalyticsRules -eq 0 -and $t.XDRRules -gt 0) {
            $recommendations.Add([PSCustomObject]@{
                Priority     = 'Medium'
                Type         = 'XDROptimize'
                TableName    = $t.TableName
                Title        = "Stop streaming $($t.TableName) to Sentinel"
                Detail       = "$($t.XDRRules) Defender XDR custom detection rule(s) cover this table. " +
                               "No Sentinel-specific rules exist. Stop streaming to save cost; use unified XDR portal instead."
                EstSavingsUSD = $t.EstMonthlyCostUSD
                CurrentCost   = $t.EstMonthlyCostUSD
            })
        }

        # 4. Missing coverage on primary sources
        if ($t.Classification -eq 'primary' -and
            -not $t.IsFree -and
            $t.TotalCoverage -eq 0) {
            $recommendations.Add([PSCustomObject]@{
                Priority     = 'Medium'
                Type         = 'MissingCoverage'
                TableName    = $t.TableName
                Title        = "No detections for $($t.TableName)"
                Detail       = "Primary security source with zero analytics rules or hunting queries. " +
                               "Add detection rules to realise value from this data source."
                EstSavingsUSD = 0
                CurrentCost   = $t.EstMonthlyCostUSD
            })
        }

        # 5. Ingest-time filtering candidates
        if (-not $t.IsFree -and
            $t.MonthlyGB -ge 20 -and
            $t.Classification -eq 'primary' -and
            $t.TotalCoverage -ge 1 -and $t.TotalCoverage -le 3) {
            $recommendations.Add([PSCustomObject]@{
                Priority     = 'Low'
                Type         = 'Filter'
                TableName    = $t.TableName
                Title        = "Consider filtering $($t.TableName)"
                Detail       = "High-volume primary source ($($t.MonthlyGB) GB/mo) with only $($t.TotalCoverage) detection(s). " +
                               "Review if ingest-time transformation can filter unneeded event types."
                EstSavingsUSD = [math]::Round($t.EstMonthlyCostUSD * 0.3, 2)
                CurrentCost   = $t.EstMonthlyCostUSD
            })
        }

        # 9. Split candidate — high-volume tables with some detections that could benefit from split
        if (-not $t.IsFree -and
            -not $t.IsSplitTable -and
            -not $t.HasTransform -and
            $t.MonthlyGB -ge 10 -and
            $t.TotalCoverage -ge 1 -and
            $t.Classification -eq 'primary') {

            $splitSavings = [math]::Round($t.EstMonthlyCostUSD * 0.50, 2)

            # Generate split KQL suggestion
            $splitSuggestion = New-SplitKql -TableName $t.TableName `
                                            -Rules $RulesData.Rules `
                                            -HighValueFieldsDB $HighValueFields

            $detail = "High-volume primary source ($($t.MonthlyGB) GB/mo) with $($t.TotalCoverage) detection(s). " +
                      "Use a Sentinel split transform to route low-value events to Data Lake tier " +
                      "while keeping detection-relevant events in Analytics."
            if ($splitSuggestion.Source -ne 'none') {
                $detail += " Split KQL suggestion available (source: $($splitSuggestion.Source))."
            }

            $recommendations.Add([PSCustomObject]@{
                Priority        = 'Medium'
                Type            = 'SplitCandidate'
                TableName       = $t.TableName
                Title           = "Consider split transform for $($t.TableName)"
                Detail          = $detail
                EstSavingsUSD   = $splitSavings
                CurrentCost     = $t.EstMonthlyCostUSD
                SplitSuggestion = $splitSuggestion
            })
        }
    }

    # Correlation data pass-through
    $corrExcluded = @($RulesData.Rules | Where-Object ExcludedFromCorrelation)
    $corrIncluded = @($RulesData.Rules | Where-Object IncludedInCorrelation)

    # 6. Workspace retention check
    if ($WorkspaceRetentionDays -gt 0 -and $WorkspaceRetentionDays -lt 90) {
        $recommendations.Add([PSCustomObject]@{
            Priority      = 'High'
            Type          = 'RetentionShortfall'
            TableName     = '(workspace default)'
            Title         = "Workspace default retention is $($WorkspaceRetentionDays)d — increase to at least 90d"
            Detail        = "The workspace default retention is $($WorkspaceRetentionDays) days. " +
                            "A 90-day minimum is recommended as a security baseline. " +
                            "Tables inheriting the default will not meet compliance requirements."
            EstSavingsUSD = 0
            CurrentCost   = 0
        })
    }

    # 7. Per-table retention below 90d baseline
    foreach ($t in $tableAnalysis) {
        if ($null -eq $t.RetentionCompliant -or $t.RetentionCompliant) { continue }

        $prio = if ($t.Classification -eq 'primary') { 'High' } else { 'Medium' }
        $recommendations.Add([PSCustomObject]@{
            Priority      = $prio
            Type          = 'RetentionShortfall'
            TableName     = $t.TableName
            Title         = "$($t.TableName) retention below 90d baseline ($($t.ActualRetentionDays)d)"
            Detail        = "Total retention is $($t.ActualRetentionDays) days. A 90-day minimum is the recommended " +
                            "security baseline. Increase total retention or add archive retention."
            EstSavingsUSD = 0
            CurrentCost   = $t.EstMonthlyCostUSD
        })
    }

    # 8. Retention improvement opportunities (meets 90d but below category recommendation)
    foreach ($t in $tableAnalysis) {
        if (-not $t.RetentionCanImprove) { continue }

        $recommendations.Add([PSCustomObject]@{
            Priority      = 'Low'
            Type          = 'RetentionImprovement'
            TableName     = $t.TableName
            Title         = "$($t.TableName) could benefit from $($t.RecommendedRetentionDays)d retention (currently $($t.ActualRetentionDays)d)"
            Detail        = "Meets the 90-day baseline but best-practice guidance recommends $($t.RecommendedRetentionDays) days " +
                            "for $($t.Category) tables."
            EstSavingsUSD = 0
            CurrentCost   = $t.EstMonthlyCostUSD
        })
    }
    $sortedRecs = $recommendations | Sort-Object EstSavingsUSD -Descending

    # Summary stats
    $primaryTables   = @($tableAnalysis | Where-Object Classification -eq 'primary')
    $secondaryTables = @($tableAnalysis | Where-Object Classification -eq 'secondary')
    $unknownTables   = @($tableAnalysis | Where-Object Classification -eq 'unknown')

    $totalMonthlyGB   = ($tableAnalysis | Measure-Object MonthlyGB -Sum).Sum
    $totalMonthlyCost = ($tableAnalysis | Measure-Object EstMonthlyCostUSD -Sum).Sum
    $totalSavings     = ($sortedRecs | Measure-Object EstSavingsUSD -Sum).Sum

    $tablesWithRules  = @($tableAnalysis | Where-Object { $_.TotalCoverage -gt 0 }).Count
    $coveragePercent  = if ($tableAnalysis.Count -gt 0) {
        [math]::Round(($tablesWithRules / $tableAnalysis.Count) * 100, 0)
    } else { 0 }

    $retentionCompliantCount  = @($tableAnalysis | Where-Object { $_.RetentionCompliant -eq $true }).Count
    $retentionNonCompliant    = @($tableAnalysis | Where-Object { $_.RetentionCompliant -eq $false }).Count
    $retentionChecked         = $retentionCompliantCount + $retentionNonCompliant
    $retentionImprovableCount = @($tableAnalysis | Where-Object { $_.RetentionCanImprove -eq $true }).Count

    # Transform stats
    $tablesWithTransforms = @($tableAnalysis | Where-Object { $_.HasTransform }).Count
    $splitTables          = @($tableAnalysis | Where-Object { $_.IsSplitTable }).Count
    $transformDCRCount    = if ($DataTransforms) { $DataTransforms.RelevantDCRs.Count } else { 0 }

    [PSCustomObject]@{
        TableAnalysis       = $tableAnalysis
        Recommendations     = @($sortedRecs)
        KeywordGaps         = $Classifications.KeywordGaps
        SocRecommendations  = $SocRecommendations
        CorrelationExcluded = $corrExcluded
        CorrelationIncluded = $corrIncluded
        DataTransforms      = $DataTransforms
        Summary             = [PSCustomObject]@{
            TotalTables            = $tableAnalysis.Count
            PrimaryCount           = $primaryTables.Count
            SecondaryCount         = $secondaryTables.Count
            UnknownCount           = $unknownTables.Count
            TotalMonthlyGB         = [math]::Round($totalMonthlyGB, 2)
            TotalMonthlyCost       = [math]::Round($totalMonthlyCost, 2)
            TotalRules             = $RulesData.TotalRules
            EnabledRules           = $RulesData.EnabledRules
            DontCorrCount          = $RulesData.DontCorrCount
            IncCorrCount           = $RulesData.IncCorrCount
            HuntingQueries         = $HuntingData.TotalQueries
            CoveragePercent        = $coveragePercent
            EstTotalSavings        = [math]::Round($totalSavings, 2)
            PricePerGB             = $PricePerGB
            WorkspaceRetentionDays = $WorkspaceRetentionDays
            RetentionCompliant     = $retentionCompliantCount
            RetentionNonCompliant  = $retentionNonCompliant
            RetentionChecked       = $retentionChecked
            RetentionImprovable    = $retentionImprovableCount
            TablesWithTransforms   = $tablesWithTransforms
            SplitTables            = $splitTables
            TransformDCRs          = $transformDCRCount
        }
    }
}

function Get-Assessment {
    param(
        [string]$Classification,
        [string]$CostTier,
        [string]$DetectionTier,
        [int]$RuleCount,
        [bool]$IsFree
    )

    if ($IsFree) { return 'Free Tier' }

    switch ($true) {
        ($Classification -eq 'primary' -and $DetectionTier -in @('High', 'Medium')) {
            'High Value'; break
        }
        ($Classification -eq 'primary' -and $DetectionTier -eq 'Low' -and $CostTier -in @('Low', 'Medium')) {
            'Good Value'; break
        }
        ($Classification -eq 'primary' -and $DetectionTier -eq 'None') {
            'Missing Coverage'; break
        }
        ($Classification -eq 'secondary' -and $CostTier -in @('High', 'Very High') -and $DetectionTier -in @('None', 'Low')) {
            'Optimize'; break
        }
        ($CostTier -in @('High', 'Very High') -and $DetectionTier -eq 'None') {
            'Low Value'; break
        }
        ($DetectionTier -eq 'None') {
            'Underutilized'; break
        }
        default {
            'Good Value'
        }
    }
}
