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
        [decimal]$PricePerGB = 5.59
    )

    $classMap       = $Classifications.Classifications   # hashtable
    $ruleCoverage   = $RulesData.TableCoverage            # hashtable: table -> count
    $huntCoverage   = $HuntingData.TableCoverage          # hashtable: table -> count
    $xdrCoverage    = if ($DefenderXDR) { $DefenderXDR.XDRTableCoverage } else { @{} }
    $xdrStreaming   = if ($DefenderXDR) { $DefenderXDR.StreamingTables } else { @() }

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

        [PSCustomObject]@{
            TableName          = $name
            Classification     = $classification
            Category           = if ($cls) { $cls.Category } else { 'Unknown' }
            MonthlyGB          = $table.MonthlyGB
            EstMonthlyCostUSD  = $table.EstMonthlyCostUSD
            IsFree             = $table.IsFree
            AnalyticsRules     = $ruleCount
            HuntingQueries     = $huntCount
            XDRRules           = $xdrRuleCount
            TotalCoverage      = $totalCoverage
            CostTier           = $costTier
            DetectionTier      = $detectionTier
            Assessment         = $assessment
            IsXDRStreaming     = $isXDRStreaming
            RecommendedTier    = if ($cls) { $cls.RecommendedTier } else { 'analytics' }
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
    }

    # Sort recommendations by estimated savings descending
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

    [PSCustomObject]@{
        TableAnalysis    = $tableAnalysis
        Recommendations  = @($sortedRecs)
        KeywordGaps      = $Classifications.KeywordGaps
        SocRecommendations = $SocRecommendations
        Summary          = [PSCustomObject]@{
            TotalTables      = $tableAnalysis.Count
            PrimaryCount     = $primaryTables.Count
            SecondaryCount   = $secondaryTables.Count
            UnknownCount     = $unknownTables.Count
            TotalMonthlyGB   = [math]::Round($totalMonthlyGB, 2)
            TotalMonthlyCost = [math]::Round($totalMonthlyCost, 2)
            TotalRules       = $RulesData.TotalRules
            EnabledRules     = $RulesData.EnabledRules
            HuntingQueries   = $HuntingData.TotalQueries
            CoveragePercent  = $coveragePercent
            EstTotalSavings  = [math]::Round($totalSavings, 2)
            PricePerGB       = $PricePerGB
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
