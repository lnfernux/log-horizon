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
        [hashtable]$HighValueFields,
        [array]$Incidents = @(),
        [array]$AutomationRules = @()
    )

    $classMap       = $Classifications.Classifications   # hashtable
    $ruleCoverage   = $RulesData.TableCoverage            # hashtable: table -> count
    $huntCoverage   = $HuntingData.TableCoverage          # hashtable: table -> count
    $xdrCoverage    = if ($DefenderXDR) { $DefenderXDR.XDRTableCoverage } else { @{} }
    $knownXDRTables = if ($DefenderXDR) { $DefenderXDR.KnownXDRTables } else { @() }

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

        $ruleCount    = if ($ruleCoverage.ContainsKey($name)) { [int]$ruleCoverage[$name] } else { 0 }
        $huntCount    = if ($huntCoverage.ContainsKey($name)) { [int]$huntCoverage[$name] } else { 0 }
        $xdrRuleCount = if ($xdrCoverage.ContainsKey($name)) { [int]$xdrCoverage[$name] } else { 0 }
        $totalCoverage = $ruleCount + $huntCount
        $effectiveCoverage = $ruleCount + $huntCount + $xdrRuleCount

        # Cost tier
        $costTier = switch ($true) {
            ($table.IsFree)              { 'Free'; break }
            ($table.MonthlyGB -ge 50)    { 'Very High'; break }
            ($table.MonthlyGB -ge 10)    { 'High'; break }
            ($table.MonthlyGB -ge 1)     { 'Medium'; break }
            default                      { 'Low' }
        }

        # Detection value tier (includes CDR coverage for accurate assessment)
        $detectionTier = switch ($true) {
            ($effectiveCoverage -ge 10) { 'High'; break }
            ($effectiveCoverage -ge 3)  { 'Medium'; break }
            ($effectiveCoverage -ge 1)  { 'Low'; break }
            default                     { 'None' }
        }

        $classification = if ($cls) { $cls.Classification } else { 'unknown' }

        # Combined assessment
        $assessment = Get-Assessment -Classification $classification `
                                      -CostTier $costTier `
                                      -DetectionTier $detectionTier `
                                      -IsFree $table.IsFree

        # Retention data
        $ret = $retentionMap[$name]

        # XDR state: known XDR table + plan from workspace (null = not XDR, NotStreaming = XDR default 30d only)
        $isKnownXDR = $name -in $knownXDRTables
        $xdrState = if (-not $isKnownXDR) { $null }
                    elseif (-not $ret) { 'NotStreaming' }
                    else { $ret.Plan }  # Analytics, Basic, or Auxiliary
        $isXDRStreaming = $isKnownXDR -and ($null -ne $ret)

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

        $splitSuggestion = Get-SplitKql -TableName $name `
                                        -Rules $RulesData.Rules `
                                        -HighValueFieldsDB $HighValueFields

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
            EffectiveCoverage            = $effectiveCoverage
            CostTier                     = $costTier
            DetectionTier                = $detectionTier
            Assessment                   = $assessment
            IsXDRStreaming               = $isXDRStreaming
            XDRState                     = $xdrState
            RecommendedTier              = if ($cls) { $cls.RecommendedTier } else { 'analytics' }
            ActualRetentionDays          = $actualTotal
            ActualInteractiveRetentionDays = $actualInteractive
            ArchiveRetentionInDays       = if ($ret) { [int]$ret.ArchiveRetentionInDays } else { $null }
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
            SplitSuggestion              = $splitSuggestion
        }
    }

    $cdrRules = if ($DefenderXDR -and $DefenderXDR.CustomRules) { $DefenderXDR.CustomRules } else { @() }
    $detectionAnalyzer = Get-DetectionAnalyzerData -Rules $RulesData.Rules `
                                                   -Incidents $Incidents `
                                                   -AutomationRules $AutomationRules `
                                                   -CustomDetectionRules $cdrRules

    $xdrChecker = Get-XdrCheckerData -TableAnalysis $tableAnalysis -KnownXDRTables $knownXDRTables

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
                Detail       = "Secondary source ingesting $($t.MonthlyGB) GB/mo with $($t.EffectiveCoverage) detection(s). " +
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
            $t.EffectiveCoverage -eq 0) {
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
            $t.EffectiveCoverage -ge 1 -and $t.EffectiveCoverage -le 3) {
            $recommendations.Add([PSCustomObject]@{
                Priority     = 'Low'
                Type         = 'Filter'
                TableName    = $t.TableName
                Title        = "Consider filtering $($t.TableName)"
                Detail       = "High-volume primary source ($($t.MonthlyGB) GB/mo) with only $($t.EffectiveCoverage) detection(s). " +
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
            $t.EffectiveCoverage -ge 1 -and
            $t.Classification -eq 'primary') {

            $splitSavings = [math]::Round($t.EstMonthlyCostUSD * 0.50, 2)

            # Use cached split KQL suggestion
            $splitSuggestion = $t.SplitSuggestion

            $detail = "High-volume primary source ($($t.MonthlyGB) GB/mo) with $($t.EffectiveCoverage) detection(s). " +
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

    foreach ($rec in $detectionAnalyzer.Recommendations) {
        $recommendations.Add($rec)
    }

    foreach ($rec in $xdrChecker.Recommendations) {
        $recommendations.Add($rec)
    }

    $sortedRecs = $recommendations | Sort-Object EstSavingsUSD -Descending

    # Summary stats
    $primaryTables   = @($tableAnalysis | Where-Object Classification -eq 'primary')
    $secondaryTables = @($tableAnalysis | Where-Object Classification -eq 'secondary')
    $unknownTables   = @($tableAnalysis | Where-Object Classification -eq 'unknown')

    $totalMonthlyGB   = ($tableAnalysis | Measure-Object MonthlyGB -Sum).Sum
    $totalMonthlyCost = ($tableAnalysis | Measure-Object EstMonthlyCostUSD -Sum).Sum
    $totalSavings     = ($sortedRecs | Measure-Object EstSavingsUSD -Sum).Sum

    $tablesWithRules  = @($tableAnalysis | Where-Object { $_.EffectiveCoverage -gt 0 }).Count
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
        DetectionAnalyzer   = $detectionAnalyzer
        XdrChecker          = $xdrChecker
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
            DetectionRulesAnalyzed = $detectionAnalyzer.Summary.RulesAnalyzed
            NoisyRulesDetected     = $detectionAnalyzer.Summary.NoisyRules
            AutoClosedIncidents    = $detectionAnalyzer.Summary.AutoClosedIncidents
            XdrCheckerIssues       = $xdrChecker.Summary.IssueCount
            XdrAdvisoryRetention   = $xdrChecker.Summary.AdvisoryRetentionDays
        }
    }
}

function Get-Assessment {
    param(
        [string]$Classification,
        [string]$CostTier,
        [string]$DetectionTier,
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

function Get-DetectionAnalyzerData {
    [CmdletBinding()]
    param(
        [array]$Rules,
        [array]$Incidents,
        [array]$AutomationRules,
        [array]$CustomDetectionRules = @()
    )

    $allRulesEmpty = (-not $Rules -or $Rules.Count -eq 0) -and (-not $CustomDetectionRules -or $CustomDetectionRules.Count -eq 0)
    if ($allRulesEmpty) {
        return [PSCustomObject]@{
            RuleMetrics = @()
            Recommendations = @()
            Summary = [PSCustomObject]@{
                RulesAnalyzed = 0
                NoisyRules = 0
                IncidentsAnalyzed = 0
                AutoClosedIncidents = 0
                CustomDetectionRules = 0
                CDRCorrelatedIncidents = 0
            }
        }
    }

    # Build a unified rule list: analytics rules first, then CDRs
    $unifiedRules = [System.Collections.Generic.List[object]]::new()

    if ($Rules) {
        foreach ($rule in $Rules) {
            $unifiedRules.Add([PSCustomObject]@{
                RuleName = $rule.RuleName
                Kind     = $rule.Kind
                Enabled  = $rule.Enabled
                Source   = 'Sentinel'
                Tables   = @()
                Frequency = $null
            })
        }
    }

    $cdrCount = 0
    if ($CustomDetectionRules -and $CustomDetectionRules.Count -gt 0) {
        foreach ($cdr in $CustomDetectionRules) {
            $displayName = $null
            if ($cdr.PSObject.Properties.Name -contains 'displayName') { $displayName = $cdr.displayName }
            if (-not $displayName -and $cdr.PSObject.Properties.Name -contains 'detectionAction') { $displayName = $cdr.detectionAction }
            if (-not $displayName) { $displayName = "CDR-$cdrCount" }

            $isEnabled = $true
            if ($cdr.PSObject.Properties.Name -contains 'isEnabled') { $isEnabled = [bool]$cdr.isEnabled }

            $tables = @()
            $query = $null
            if ($cdr.PSObject.Properties.Name -contains 'queryCondition' -and $cdr.queryCondition) {
                $query = $cdr.queryCondition.queryText
            }
            if ($query) {
                $tables = @(Get-TablesFromKql -Kql $query)
            }

            $frequency = $null
            if ($cdr.PSObject.Properties.Name -contains 'schedule' -and $cdr.schedule) {
                if ($cdr.schedule.PSObject.Properties.Name -contains 'period') {
                    $frequency = $cdr.schedule.period
                }
            }

            $unifiedRules.Add([PSCustomObject]@{
                RuleName  = $displayName
                Kind      = 'CustomDetection'
                Enabled   = $isEnabled
                Source    = 'DefenderXDR'
                Tables    = $tables
                Frequency = $frequency
            })
            $cdrCount++
        }
    }

    # Build incident buckets keyed by rule name
    $incidentBuckets = @{}
    foreach ($rule in $unifiedRules) {
        $incidentBuckets[$rule.RuleName] = [System.Collections.Generic.List[object]]::new()
    }

    foreach ($incident in $Incidents) {
        $candidateNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($n in @($incident.RelatedAnalyticRuleNames)) {
            if (-not [string]::IsNullOrWhiteSpace($n)) { [void]$candidateNames.Add($n) }
        }

        # Title heuristic fallback — works for both analytics and CDR rules
        if ($candidateNames.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($incident.Title)) {
            foreach ($rule in $unifiedRules) {
                if ($incident.Title -like "*$($rule.RuleName)*") {
                    [void]$candidateNames.Add($rule.RuleName)
                }
            }
        }

        foreach ($ruleName in $candidateNames) {
            if ($incidentBuckets.ContainsKey($ruleName)) {
                $incidentBuckets[$ruleName].Add($incident)
            }
        }
    }

    # Compute per-rule metrics
    $ruleMetrics = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in $unifiedRules) {
        $ruleIncidents = @($incidentBuckets[$rule.RuleName])
        $total = $ruleIncidents.Count
        $closed = @($ruleIncidents | Where-Object { $_.Status -eq 'Closed' })

        $autoClosed = @()
        foreach ($inc in $closed) {
            $matched = @($AutomationRules | Where-Object {
                $_.IsCloseIncidentRule -and $_.Enabled -and (Test-AutomationRuleIncidentMatch -AutomationRule $_ -IncidentTitle $inc.Title)
            })
            if ($matched.Count -gt 0) {
                $autoClosed += $inc
            }
        }

        $manualClosed = @($closed | Where-Object { $_ -notin $autoClosed })
        $falsePositive = @($closed | Where-Object { $_.Classification -eq 'FalsePositive' })
        $benignPositive = @($closed | Where-Object { $_.Classification -eq 'BenignPositive' })
        $truePositive = @($closed | Where-Object { $_.Classification -eq 'TruePositive' })

        $closeMinutes = @($closed | ForEach-Object {
            if ($_.CreatedTimeUtc -and $_.ClosedTimeUtc) {
                [math]::Max([math]::Round(($_.ClosedTimeUtc - $_.CreatedTimeUtc).TotalMinutes, 2), 0)
            }
        } | Where-Object { $null -ne $_ })

        $avgClose = if ($closeMinutes.Count -gt 0) { [math]::Round((($closeMinutes | Measure-Object -Average).Average), 2) } else { $null }
        $autoCloseRatio = if ($closed.Count -gt 0) { [math]::Round(($autoClosed.Count / $closed.Count), 4) } else { 0 }
        $falseRatio = if ($closed.Count -gt 0) { [math]::Round(($falsePositive.Count / $closed.Count), 4) } else { 0 }
        $benignRatio = if ($closed.Count -gt 0) { [math]::Round(($benignPositive.Count / $closed.Count), 4) } else { 0 }

        $ruleMetrics.Add([PSCustomObject]@{
            RuleName                = $rule.RuleName
            RuleKind                = $rule.Kind
            Enabled                 = $rule.Enabled
            Source                  = $rule.Source
            Tables                  = $rule.Tables
            Frequency               = $rule.Frequency
            IncidentsTotal          = $total
            IncidentsClosed         = $closed.Count
            IncidentsAutoClosed     = $autoClosed.Count
            IncidentsManualClosed   = $manualClosed.Count
            FalsePositiveClosed     = $falsePositive.Count
            BenignPositiveClosed    = $benignPositive.Count
            TruePositiveClosed      = $truePositive.Count
            AutoCloseRatio          = $autoCloseRatio
            FalsePositiveRatio      = $falseRatio
            BenignPositiveRatio     = $benignRatio
            AvgCloseMinutes         = $avgClose
            LinkedAutomationRules   = @($AutomationRules | Where-Object {
                $_.IsCloseIncidentRule -and $_.Enabled -and $_.TitleFilters.Count -gt 0
            } | ForEach-Object DisplayName | Select-Object -Unique)
        })
    }

    # Noisiness scoring — only score rules that have incident data
    $scorableMetrics = @($ruleMetrics | Where-Object { $_.IncidentsTotal -gt 0 })

    if ($scorableMetrics.Count -gt 0) {
        $volumes = @($scorableMetrics | ForEach-Object IncidentsTotal)
        $autoRatios = @($scorableMetrics | ForEach-Object AutoCloseRatio)
        $falseRatios = @($scorableMetrics | ForEach-Object FalsePositiveRatio)

        foreach ($metric in $scorableMetrics) {
            $volumePct = Get-PercentileRank -Value $metric.IncidentsTotal -Population $volumes
            $autoPct = Get-PercentileRank -Value $metric.AutoCloseRatio -Population $autoRatios
            $falsePct = Get-PercentileRank -Value $metric.FalsePositiveRatio -Population $falseRatios

            $score = [math]::Round(($volumePct * 0.35) + ($autoPct * 0.40) + ($falsePct * 0.25), 2)
            Add-Member -InputObject $metric -NotePropertyName NoisinessScore -NotePropertyValue $score
            Add-Member -InputObject $metric -NotePropertyName PercentileVolume -NotePropertyValue $volumePct
            Add-Member -InputObject $metric -NotePropertyName PercentileAutoClose -NotePropertyValue $autoPct
            Add-Member -InputObject $metric -NotePropertyName PercentileFalsePositive -NotePropertyValue $falsePct
        }
    }

    # Rules with no incidents get null score (listing-only in UI)
    foreach ($metric in $ruleMetrics) {
        if (-not ($metric.PSObject.Properties.Name -contains 'NoisinessScore')) {
            Add-Member -InputObject $metric -NotePropertyName NoisinessScore -NotePropertyValue $null
            Add-Member -InputObject $metric -NotePropertyName PercentileVolume -NotePropertyValue $null
            Add-Member -InputObject $metric -NotePropertyName PercentileAutoClose -NotePropertyValue $null
            Add-Member -InputObject $metric -NotePropertyName PercentileFalsePositive -NotePropertyValue $null
        }
    }

    $noisyRules = @($ruleMetrics | Where-Object {
        $_.Enabled -and $_.IncidentsTotal -ge 5 -and $null -ne $_.NoisinessScore -and $_.NoisinessScore -ge 70
    })

    $recList = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in $noisyRules) {
        $recList.Add([PSCustomObject]@{
            Priority     = 'High'
            Type         = 'DetectionAnalyzer'
            TableName    = '(rule-level)'
            Title        = "Review noisy rule: $($rule.RuleName)"
            Detail       = "Rule appears noisy (score $($rule.NoisinessScore)). Auto-close ratio: $($rule.AutoCloseRatio), false positive ratio: $($rule.FalsePositiveRatio), incidents: $($rule.IncidentsTotal)."
            EstSavingsUSD = 0
            CurrentCost   = 0
        })
    }

    $cdrMetrics = @($ruleMetrics | Where-Object { $_.RuleKind -eq 'CustomDetection' })
    $cdrCorrelated = @($cdrMetrics | Where-Object { $_.IncidentsTotal -gt 0 }).Count

    [PSCustomObject]@{
        RuleMetrics = @($ruleMetrics)
        Recommendations = @($recList)
        Summary = [PSCustomObject]@{
            RulesAnalyzed = $ruleMetrics.Count
            NoisyRules = $noisyRules.Count
            IncidentsAnalyzed = $Incidents.Count
            AutoClosedIncidents = @($ruleMetrics | Measure-Object IncidentsAutoClosed -Sum).Sum
            CustomDetectionRules = $cdrMetrics.Count
            CDRCorrelatedIncidents = $cdrCorrelated
        }
    }
}

function Get-XdrCheckerData {
    [CmdletBinding()]
    param(
        [array]$TableAnalysis,
        [array]$KnownXDRTables = @(),
        [int]$AdvisoryRetentionDays = 365
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $recommendations = [System.Collections.Generic.List[object]]::new()

    $xdrStreamedTables = @($TableAnalysis | Where-Object IsXDRStreaming)

    # Identify known XDR tables not streamed to Sentinel at all
    $streamedNames = @($xdrStreamedTables | ForEach-Object { $_.TableName })
    $notStreamedNames = @($KnownXDRTables | Where-Object { $_ -notin $streamedNames })

    foreach ($tableName in $notStreamedNames) {
        $findings.Add([PSCustomObject]@{
            Type      = 'NotStreaming'
            TableName = $tableName
            Severity  = 'Information'
            Detail    = 'Known Defender XDR table is not streamed to Sentinel. Data is only available via XDR Advanced Hunting with 30-day retention.'
        })

        $recommendations.Add([PSCustomObject]@{
            Priority      = 'Low'
            Type          = 'XDRChecker'
            TableName     = $tableName
            Title         = "Consider streaming $tableName to Sentinel"
            Detail        = 'This Defender XDR table is not ingested into the workspace. Consider streaming to Analytics or Data Lake tier for long-term retention and cross-workspace correlation.'
            EstSavingsUSD = 0
            CurrentCost   = 0
        })
    }

    foreach ($table in $xdrStreamedTables) {
        if ($table.AnalyticsRules -eq 0 -and $table.XDRRules -eq 0) {
            $findings.Add([PSCustomObject]@{
                Type = 'StreamingNoCoverage'
                TableName = $table.TableName
                Severity = 'Medium'
                Detail = 'Table is streamed from Defender XDR but has no Sentinel analytics or Defender custom rule coverage.'
            })

            $recommendations.Add([PSCustomObject]@{
                Priority      = 'Medium'
                Type          = 'XDRChecker'
                TableName     = $table.TableName
                Title         = "Validate necessity of streaming $($table.TableName)"
                Detail        = 'No Sentinel or Defender custom detection coverage found for this streamed table. Consider reducing ingestion if not needed.'
                EstSavingsUSD = $table.EstMonthlyCostUSD
                CurrentCost   = $table.EstMonthlyCostUSD
            })
        }

        if ($table.XDRState -ne 'Auxiliary' -and $null -ne $table.ArchiveRetentionInDays -and $table.ArchiveRetentionInDays -eq 0) {
            $findings.Add([PSCustomObject]@{
                Type = 'NotForwardedToDataLake'
                TableName = $table.TableName
                Severity = 'Low'
                Detail = "XDR streaming table has no archive/data lake retention configured. Consider forwarding to Data Lake tier for long-term investigations."
            })

            $recommendations.Add([PSCustomObject]@{
                Priority      = 'Low'
                Type          = 'XDRChecker'
                TableName     = $table.TableName
                Title         = "Forward $($table.TableName) to Data Lake tier"
                Detail        = "XDR streaming table is only in Analytics tier with no archive retention. Configure Data Lake forwarding for at least $AdvisoryRetentionDays days."
                EstSavingsUSD = 0
                CurrentCost   = $table.EstMonthlyCostUSD
            })
        }
        elseif ($null -ne $table.ActualRetentionDays -and $table.ActualRetentionDays -lt $AdvisoryRetentionDays) {
            $findings.Add([PSCustomObject]@{
                Type = 'AdvisoryRetentionGap'
                TableName = $table.TableName
                Severity = 'Low'
                Detail = "Retention is $($table.ActualRetentionDays)d. Advisory target for XDR-related logs is at least $AdvisoryRetentionDays days in Data Lake."
            })

            $recommendations.Add([PSCustomObject]@{
                Priority      = 'Low'
                Type          = 'XDRChecker'
                TableName     = $table.TableName
                Title         = "Consider one-year retention path for $($table.TableName)"
                Detail        = "Advisory guidance: keep XDR-related telemetry available in Data Lake for at least $AdvisoryRetentionDays days for long-term investigations."
                EstSavingsUSD = 0
                CurrentCost   = $table.EstMonthlyCostUSD
            })
        }
    }

    [PSCustomObject]@{
        Findings = @($findings)
        Recommendations = @($recommendations)
        Summary = [PSCustomObject]@{
            IssueCount = $findings.Count
            AdvisoryRetentionDays = $AdvisoryRetentionDays
            StreamedTableCount = $xdrStreamedTables.Count
            NotStreamedCount = $notStreamedNames.Count
        }
    }
}

function Get-PercentileRank {
    [CmdletBinding()]
    param(
        [double]$Value,
        [array]$Population
    )

    $clean = @($Population | Where-Object { $null -ne $_ } | ForEach-Object { [double]$_ })
    if ($clean.Count -eq 0) { return 0 }
    if ($clean.Count -eq 1) { return 100 }

    # If all values are identical, percentile carries no relative signal.
    # Return 0 so rules are not falsely classified as noisy when everything is flat (for example all zeros).
    $min = ($clean | Measure-Object -Minimum).Minimum
    $max = ($clean | Measure-Object -Maximum).Maximum
    if ($min -eq $max) { return 0 }

    $lessOrEqual = @($clean | Where-Object { $_ -le $Value }).Count
    return [math]::Round((100 * $lessOrEqual / $clean.Count), 2)
}

function Test-AutomationRuleIncidentMatch {
    [CmdletBinding()]
    param(
        [PSCustomObject]$AutomationRule,
        [string]$IncidentTitle
    )

    if ([string]::IsNullOrWhiteSpace($IncidentTitle)) { return $false }

    $filters = @($AutomationRule.TitleFilters)
    if ($filters.Count -eq 0) { return $false }

    foreach ($filter in $filters) {
        if ([string]::IsNullOrWhiteSpace($filter)) { continue }

        $pattern = [regex]::Escape($filter).Replace('\*', '.*')
        if ($IncidentTitle -match $pattern) { return $true }
    }

    return $false
}
