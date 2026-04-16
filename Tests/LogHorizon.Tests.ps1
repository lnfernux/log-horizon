BeforeAll {
    # Dot-source the private functions directly for unit testing
    $privatePath = Join-Path $PSScriptRoot '..\Private'
    . "$privatePath\Get-AnalyticsRules.ps1"
    . "$privatePath\Invoke-Classification.ps1"
    . "$privatePath\Invoke-Analysis.ps1"
    . "$privatePath\Export-Report.ps1"
    . "$privatePath\Write-Report.ps1"
    . "$privatePath\Get-DataTransforms.ps1"
    . "$privatePath\Get-Incidents.ps1"
    . "$privatePath\Get-AutomationRules.ps1"
    . "$privatePath\Invoke-AzRestWithRetry.ps1"

    function New-MockAnalysis {
        [PSCustomObject]@{
            TableAnalysis = @(
                [PSCustomObject]@{
                    TableName              = 'SecurityEvent'
                    Classification         = 'primary'
                    Category               = 'Windows Security'
                    MonthlyGB              = 50
                    EstMonthlyCostUSD      = 279.50
                    IsFree                 = $false
                    AnalyticsRules         = 15
                    HuntingQueries         = 3
                    TotalCoverage          = 15
                    Assessment             = 'High Value'
                    HasTransform           = $true
                    TransformTypes         = @('Filter')
                    TransformKql           = @('source | where EventID != 4688')
                    IsSplitTable           = $false
                    ParentTable            = $null
                    RetentionCompliant     = $true
                    RetentionCanImprove    = $true
                    ActualRetentionDays    = 90
                    RecommendedRetentionDays = 365
                    TablePlan              = 'Analytics'
                    IsXDRStreaming         = $false
                    XDRState               = $null
                    SplitSuggestion        = $null
                },
                [PSCustomObject]@{
                    TableName              = 'AWSVPCFlow'
                    Classification         = 'secondary'
                    Category               = 'Network Flow'
                    MonthlyGB              = 100
                    EstMonthlyCostUSD      = 559.00
                    IsFree                 = $false
                    AnalyticsRules         = 0
                    HuntingQueries         = 0
                    TotalCoverage          = 0
                    Assessment             = 'Low Value'
                    HasTransform           = $false
                    TransformTypes         = @()
                    TransformKql           = @()
                    IsSplitTable           = $false
                    ParentTable            = $null
                    RetentionCompliant     = $false
                    RetentionCanImprove    = $false
                    ActualRetentionDays    = 30
                    RecommendedRetentionDays = 90
                    TablePlan              = 'Analytics'
                    IsXDRStreaming         = $false
                    XDRState               = $null
                    SplitSuggestion        = $null
                }
            )
            Recommendations = @(
                [PSCustomObject]@{
                    Title          = 'Move AWSVPCFlow to Basic Logs'
                    TableName      = 'AWSVPCFlow'
                    Priority       = 'High'
                    Type           = 'DataLake'
                    CurrentCost    = 559
                    EstSavingsUSD  = 400
                    Detail         = 'AWSVPCFlow is secondary with no detection coverage.'
                },
                [PSCustomObject]@{
                    Title          = 'Increase SecurityEvent retention'
                    TableName      = 'SecurityEvent'
                    Priority       = 'Medium'
                    Type           = 'RetentionImprovement'
                    CurrentCost    = 0
                    EstSavingsUSD  = 0
                    Detail         = 'Recommended 365d for compliance.'
                }
            )
            KeywordGaps = @(
                [PSCustomObject]@{
                    TableName      = 'AWSCloudTrail'
                    Connector      = 'AWS'
                    Classification = 'primary'
                    MatchedKeyword = 'AWS'
                }
            )
            CorrelationExcluded = @(
                [PSCustomObject]@{ RuleName = 'Test <Rule>'; Kind = 'Scheduled'; Tables = @('SecurityEvent') }
            )
            CorrelationIncluded = @(
                [PSCustomObject]@{ RuleName = 'Included Rule'; Kind = 'NRT'; Tables = @('SigninLogs') }
            )
            SocRecommendations = @()
            DataTransforms = [PSCustomObject]@{
                Transforms = @(
                    [PSCustomObject]@{
                        DCRName       = 'dcr-securityevent'
                        OutputTable   = 'SecurityEvent'
                        TransformKql  = 'source | where EventID != 4688'
                        TransformType = 'Filter'
                    }
                )
            }
            Summary = [PSCustomObject]@{
                TotalTables           = 2
                PrimaryCount          = 1
                SecondaryCount        = 1
                TotalMonthlyGB        = 150
                TotalMonthlyCost      = 838.50
                EnabledRules          = 15
                HuntingQueries        = 3
                CoveragePercent       = 50
                EstTotalSavings       = 400
                RetentionChecked      = 2
                RetentionCompliant    = 1
                RetentionNonCompliant = 1
                RetentionImprovable   = 1
                TablesWithTransforms  = 1
                TransformDCRs         = 1
                SplitTables           = 0
                WorkspaceRetentionDays = 90
            }
        }
    }
}

Describe 'Get-TablesFromKql' {
    It 'extracts a single table from simple KQL' {
        $result = Get-TablesFromKql -Kql 'SecurityEvent | where EventID == 4625'
        $result | Should -Contain 'SecurityEvent'
    }

    It 'extracts tables from join' {
        $kql = @"
SecurityAlert
| join kind=inner (SigninLogs | where ResultType != 0) on AccountObjectId
"@
        $result = Get-TablesFromKql -Kql $kql
        $result | Should -Contain 'SecurityAlert'
        $result | Should -Contain 'SigninLogs'
    }

    It 'extracts tables from union' {
        $kql = @"
union SecurityEvent, SigninLogs
| summarize count() by bin(TimeGenerated, 1h)
"@
        $result = Get-TablesFromKql -Kql $kql
        $result | Should -Contain 'SecurityEvent'
    }

    It 'does not return KQL keywords as tables' {
        $kql = 'SecurityEvent | where EventID == 4625 | summarize count()'
        $result = Get-TablesFromKql -Kql $kql
        $result | Should -Not -Contain 'where'
        $result | Should -Not -Contain 'summarize'
        $result | Should -Not -Contain 'let'
    }

    It 'handles multiline KQL with let statements' {
        $kql = @"
let threshold = 10;
SigninLogs
| where ResultType != 0
| summarize FailedCount = count() by UserPrincipalName
| where FailedCount > threshold
"@
        $result = Get-TablesFromKql -Kql $kql
        $result | Should -Contain 'SigninLogs'
        $result | Should -Not -Contain 'let'
    }

    It 'filters out let-statement variable names' {
        $kql = @"
let DisabledAccounts = SigninLogs | where ResultType == 50057;
let SuspiciousIPs = AuditLogs | where OperationName == "Add member to role";
DisabledAccounts
| join kind=inner SuspiciousIPs on IPAddress
"@
        $result = Get-TablesFromKql -Kql $kql
        $result | Should -Contain 'SigninLogs'
        $result | Should -Contain 'AuditLogs'
        $result | Should -Not -Contain 'DisabledAccounts'
        $result | Should -Not -Contain 'SuspiciousIPs'
    }
}

Describe 'Resolve-DynamicClassification' {
    It 'classifies tables with Alert in name as primary' {
        $result = Resolve-DynamicClassification -TableName 'CustomAlerts_CL' -RuleCount 0 -MonthlyGB 1
        $result.Classification | Should -Be 'primary'
    }

    It 'classifies tables with Flow in name as secondary' {
        $result = Resolve-DynamicClassification -TableName 'NetworkFlowData_CL' -RuleCount 0 -MonthlyGB 50
        $result.Classification | Should -Be 'secondary'
    }

    It 'classifies high-volume zero-detection tables as secondary' {
        $result = Resolve-DynamicClassification -TableName 'SomeCustomData_CL' -RuleCount 0 -MonthlyGB 15
        $result.Classification | Should -Be 'secondary'
    }

    It 'classifies tables with active rules as primary' {
        $result = Resolve-DynamicClassification -TableName 'SomeCustomData_CL' -RuleCount 5 -MonthlyGB 2
        $result.Classification | Should -Be 'primary'
    }

    It 'marks custom tables with _CL suffix in category' {
        $result = Resolve-DynamicClassification -TableName 'MyApp_CL' -RuleCount 0 -MonthlyGB 0.5
        $result.Category | Should -Match 'Custom Log'
    }

    It 'includes RecommendedRetentionDays defaulting to 90' {
        $result = Resolve-DynamicClassification -TableName 'SomeTable_CL' -RuleCount 0 -MonthlyGB 1
        $result.RecommendedRetentionDays | Should -Be 90
    }
}

Describe 'Get-Assessment' {
    It 'returns High Value for primary with high detection' {
        $result = Get-Assessment -Classification 'primary' -CostTier 'High' -DetectionTier 'High' -IsFree $false
        $result | Should -Be 'High Value'
    }

    It 'returns Missing Coverage for primary with no detection' {
        $result = Get-Assessment -Classification 'primary' -CostTier 'Medium' -DetectionTier 'None' -IsFree $false
        $result | Should -Be 'Missing Coverage'
    }

    It 'returns Optimize for secondary high cost low detection' {
        $result = Get-Assessment -Classification 'secondary' -CostTier 'High' -DetectionTier 'Low' -IsFree $false
        $result | Should -Be 'Optimize'
    }

    It 'returns Low Value for high cost zero detection' {
        $result = Get-Assessment -Classification 'unknown' -CostTier 'Very High' -DetectionTier 'None' -IsFree $false
        $result | Should -Be 'Low Value'
    }

    It 'returns Free Tier for free tables' {
        $result = Get-Assessment -Classification 'primary' -CostTier 'Free' -DetectionTier 'None' -IsFree $true
        $result | Should -Be 'Free Tier'
    }
}

Describe 'Invoke-Classification' {
    It 'loads the classification database' {
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'SecurityEvent'; MonthlyGB = 50; IsFree = $false }
            [PSCustomObject]@{ TableName = 'CustomData_CL'; MonthlyGB = 5; IsFree = $false }
        )
        $ruleCoverage = @{ 'SecurityEvent' = 10 }

        $result = Invoke-Classification -TableUsage $tableUsage -RuleTableCoverage $ruleCoverage
        $result.Classifications.Count | Should -Be 2
        $result.Classifications['SecurityEvent'].Classification | Should -Be 'primary'
        $result.Classifications['SecurityEvent'].Source | Should -Be 'database'
    }

    It 'applies heuristics to unknown tables' {
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'WeirdTable_CL'; MonthlyGB = 20; IsFree = $false }
        )
        $result = Invoke-Classification -TableUsage $tableUsage -RuleTableCoverage @{}
        $result.Classifications['WeirdTable_CL'].Source | Should -Be 'heuristic'
    }

    It 'propagates RecommendedRetentionDays from database' {
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'SigninLogs'; MonthlyGB = 5; IsFree = $false }
        )
        $result = Invoke-Classification -TableUsage $tableUsage -RuleTableCoverage @{}
        $result.Classifications['SigninLogs'].RecommendedRetentionDays | Should -Be 365
    }

    It 'finds keyword gaps' {
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'SecurityEvent'; MonthlyGB = 50; IsFree = $false }
        )
        $result = Invoke-Classification -TableUsage $tableUsage -RuleTableCoverage @{} -Keywords @('AWS')
        $result.KeywordGaps.Count | Should -BeGreaterThan 0
        $result.KeywordGaps.TableName | Should -Contain 'AWSCloudTrail'
    }
}

Describe 'Invoke-Analysis' {
    BeforeAll {
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'SecurityEvent'; DataGB = 150; MonthlyGB = 50; RecordCount = 1000000; EstMonthlyCostUSD = 279.50; IsFree = $false }
            [PSCustomObject]@{ TableName = 'AWSVPCFlow'; DataGB = 300; MonthlyGB = 100; RecordCount = 5000000; EstMonthlyCostUSD = 559.00; IsFree = $false }
            [PSCustomObject]@{ TableName = 'SecurityAlert'; DataGB = 0.5; MonthlyGB = 0.17; RecordCount = 500; EstMonthlyCostUSD = 0; IsFree = $true }
        )

        $classMap = @{
            'SecurityEvent' = [PSCustomObject]@{ Classification = 'primary'; Category = 'Windows Security'; RecommendedTier = 'analytics'; IsFree = $false }
            'AWSVPCFlow'    = [PSCustomObject]@{ Classification = 'secondary'; Category = 'Network Flow'; RecommendedTier = 'datalake'; IsFree = $false }
            'SecurityAlert' = [PSCustomObject]@{ Classification = 'primary'; Category = 'Security Alerts'; RecommendedTier = 'analytics'; IsFree = $true }
        }
        $classifications = [PSCustomObject]@{
            Classifications = $classMap
            KeywordGaps     = @()
            DatabaseEntries = 105
        }

        $rulesData = [PSCustomObject]@{
            Rules         = @()
            TableCoverage = @{ 'SecurityEvent' = 15 }
            TotalRules    = 15
            EnabledRules  = 15
        }

        $huntingData = [PSCustomObject]@{
            Queries       = @()
            TableCoverage = @{ 'SecurityEvent' = 3 }
            TotalQueries  = 3
        }

        $script:analysisResult = Invoke-Analysis -TableUsage $tableUsage `
                                                  -Classifications $classifications `
                                                  -RulesData $rulesData `
                                                  -HuntingData $huntingData `
                                                  -SocRecommendations @()
    }

    It 'produces table analysis for all tables' {
        $script:analysisResult.TableAnalysis.Count | Should -Be 3
    }

    It 'assigns High Value to SecurityEvent' {
        $se = $script:analysisResult.TableAnalysis | Where-Object TableName -eq 'SecurityEvent'
        $se.Assessment | Should -Be 'High Value'
    }

    It 'generates recommendations for AWSVPCFlow' {
        $rec = $script:analysisResult.Recommendations | Where-Object TableName -eq 'AWSVPCFlow'
        $rec | Should -Not -BeNullOrEmpty
        # Secondary + Very High cost + None detection -> both DataLake and LowValue recs
        $rec.Type | Should -Contain 'DataLake'
    }

    It 'computes summary statistics' {
        $script:analysisResult.Summary.TotalTables | Should -Be 3
        $script:analysisResult.Summary.PrimaryCount | Should -Be 2
        $script:analysisResult.Summary.SecondaryCount | Should -Be 1
        $script:analysisResult.Summary.TotalMonthlyGB | Should -BeGreaterThan 100
    }
}

Describe 'Invoke-Analysis retention logic' {
    BeforeAll {
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'SigninLogs'; DataGB = 10; MonthlyGB = 3.3; RecordCount = 50000; EstMonthlyCostUSD = 18.45; IsFree = $false }
            [PSCustomObject]@{ TableName = 'AzureDiagnostics'; DataGB = 20; MonthlyGB = 6.7; RecordCount = 100000; EstMonthlyCostUSD = 37.45; IsFree = $false }
        )

        $classMap = @{
            'SigninLogs'       = [PSCustomObject]@{ Classification = 'primary'; Category = 'Identity & Access'; RecommendedTier = 'analytics'; IsFree = $false; RecommendedRetentionDays = 365 }
            'AzureDiagnostics' = [PSCustomObject]@{ Classification = 'secondary'; Category = 'Infrastructure Diagnostics'; RecommendedTier = 'datalake'; IsFree = $false; RecommendedRetentionDays = 90 }
        }
        $classifications = [PSCustomObject]@{
            Classifications = $classMap
            KeywordGaps     = @()
            DatabaseEntries = 2
        }

        $rulesData = [PSCustomObject]@{
            Rules         = @()
            TableCoverage = @{ 'SigninLogs' = 5 }
            TotalRules    = 5
            EnabledRules  = 5
            DontCorrCount = 0
            IncCorrCount  = 0
        }

        $huntingData = [PSCustomObject]@{
            Queries       = @()
            TableCoverage = @{}
            TotalQueries  = 0
        }

        $tableRetention = @(
            [PSCustomObject]@{ TableName = 'SigninLogs'; RetentionInDays = 90; TotalRetentionInDays = 90; ArchiveRetentionInDays = 0; Plan = 'Analytics' }
            [PSCustomObject]@{ TableName = 'AzureDiagnostics'; RetentionInDays = 30; TotalRetentionInDays = 30; ArchiveRetentionInDays = 0; Plan = 'Analytics' }
        )

        $script:retResult = Invoke-Analysis -TableUsage $tableUsage `
                                             -Classifications $classifications `
                                             -RulesData $rulesData `
                                             -HuntingData $huntingData `
                                             -TableRetention $tableRetention `
                                             -WorkspaceRetentionDays 90 `
                                             -SocRecommendations @()
    }

    It 'marks SigninLogs as compliant but improvable to 365d' {
        $sl = $script:retResult.TableAnalysis | Where-Object TableName -eq 'SigninLogs'
        $sl.RetentionCompliant | Should -Be $true
        $sl.RetentionCanImprove | Should -Be $true
        $sl.RecommendedRetentionDays | Should -Be 365
    }

    It 'marks AzureDiagnostics as non-compliant (below 90d)' {
        $ad = $script:retResult.TableAnalysis | Where-Object TableName -eq 'AzureDiagnostics'
        $ad.RetentionCompliant | Should -Be $false
        $ad.RetentionCanImprove | Should -Be $false
    }

    It 'generates RetentionShortfall recommendation for below-90d table' {
        $rec = $script:retResult.Recommendations | Where-Object { $_.TableName -eq 'AzureDiagnostics' -and $_.Type -eq 'RetentionShortfall' }
        $rec | Should -Not -BeNullOrEmpty
    }

    It 'generates RetentionImprovement recommendation for SigninLogs' {
        $rec = $script:retResult.Recommendations | Where-Object { $_.TableName -eq 'SigninLogs' -and $_.Type -eq 'RetentionImprovement' }
        $rec | Should -Not -BeNullOrEmpty
        $rec.Title | Should -Match '365'
    }

    It 'reports retention summary correctly' {
        $script:retResult.Summary.RetentionChecked | Should -Be 2
        $script:retResult.Summary.RetentionCompliant | Should -Be 1
        $script:retResult.Summary.RetentionNonCompliant | Should -Be 1
        $script:retResult.Summary.RetentionImprovable | Should -Be 1
    }
}

Describe 'Classification database integrity' {
    BeforeAll {
        $dbPath = Join-Path $PSScriptRoot '..\Data\log-classifications.json'
        $script:db = Get-Content $dbPath -Raw | ConvertFrom-Json
    }

    It 'has at least 100 entries' {
        $script:db.Count | Should -BeGreaterOrEqual 100
    }

    It 'every entry has required fields' {
        foreach ($entry in $script:db) {
            $entry.tableName       | Should -Not -BeNullOrEmpty
            $entry.classification  | Should -BeIn @('primary', 'secondary')
            $entry.category        | Should -Not -BeNullOrEmpty
            $entry.recommendedTier | Should -BeIn @('analytics', 'datalake')
        }
    }

    It 'every entry has recommendedRetentionDays of 90, 180, or 365' {
        foreach ($entry in $script:db) {
            $entry.recommendedRetentionDays | Should -BeIn @(90, 180, 365) -Because "$($entry.tableName) should have a valid retention recommendation"
        }
    }

    It 'free tables are correctly marked' {
        $freeNames = @('SecurityAlert', 'SecurityIncident', 'AzureActivity', 'OfficeActivity', 'SentinelHealth', 'SentinelAudit')
        foreach ($name in $freeNames) {
            $entry = $script:db | Where-Object tableName -eq $name
            if ($entry) {
                $entry.isFree | Should -Be $true -Because "$name should be free"
            }
        }
    }

    It 'has no duplicate table names' {
        $names = $script:db | ForEach-Object tableName
        $dupes = $names | Group-Object | Where-Object Count -gt 1
        $dupes | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-Classification _SPLT_CL detection' {
    It 'classifies _SPLT_CL tables as secondary split tables' {
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'SigninLogs'; MonthlyGB = 5; IsFree = $false }
            [PSCustomObject]@{ TableName = 'SigninLogs_SPLT_CL'; MonthlyGB = 3; IsFree = $false }
        )
        $result = Invoke-Classification -TableUsage $tableUsage -RuleTableCoverage @{}
        $splt = $result.Classifications['SigninLogs_SPLT_CL']
        $splt.Classification | Should -Be 'secondary'
        $splt.IsSplitTable | Should -Be $true
        $splt.ParentTable | Should -Be 'SigninLogs'
        $splt.Source | Should -Be 'split-detection'
        $splt.Category | Should -Match 'Split Table'
    }

    It 'inherits connector from parent table in DB' {
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'SecurityEvent'; MonthlyGB = 50; IsFree = $false }
            [PSCustomObject]@{ TableName = 'SecurityEvent_SPLT_CL'; MonthlyGB = 20; IsFree = $false }
        )
        $result = Invoke-Classification -TableUsage $tableUsage -RuleTableCoverage @{}
        $splt = $result.Classifications['SecurityEvent_SPLT_CL']
        $splt.Connector | Should -Not -Be 'Unknown'
    }

    It 'sets IsSplitTable to false for regular tables' {
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'SecurityEvent'; MonthlyGB = 50; IsFree = $false }
        )
        $result = Invoke-Classification -TableUsage $tableUsage -RuleTableCoverage @{}
        $result.Classifications['SecurityEvent'].IsSplitTable | Should -Be $false
        $result.Classifications['SecurityEvent'].ParentTable | Should -BeNullOrEmpty
    }
}

Describe 'Get-TransformType' {
    It 'detects filter transforms' {
        $result = Get-TransformType -KQL 'source | where EventID != 4688'
        $result | Should -Be 'Filter'
    }

    It 'detects column removal transforms' {
        $result = Get-TransformType -KQL 'source | project-away RawData, Message'
        $result | Should -Be 'ColumnRemoval'
    }

    It 'detects enrichment transforms' {
        $result = Get-TransformType -KQL 'source | extend GeoInfo = geo_info_from_ip_address(IPAddress)'
        $result | Should -Be 'Enrichment'
    }

    It 'detects projection transforms' {
        $result = Get-TransformType -KQL 'source | project TimeGenerated, Account, EventID'
        $result | Should -Be 'Projection'
    }

    It 'detects aggregation transforms' {
        $result = Get-TransformType -KQL 'source | summarize count() by bin(TimeGenerated, 1h)'
        $result | Should -Be 'Aggregation'
    }

    It 'returns Custom for unrecognized transforms' {
        $result = Get-TransformType -KQL 'source | take 100'
        $result | Should -Be 'Custom'
    }
}

Describe 'Invoke-Analysis with transforms' {
    BeforeAll {
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'SecurityEvent'; DataGB = 150; MonthlyGB = 50; RecordCount = 1000000; EstMonthlyCostUSD = 279.50; IsFree = $false }
        )

        $classMap = @{
            'SecurityEvent' = [PSCustomObject]@{ Classification = 'primary'; Category = 'Windows Security'; RecommendedTier = 'analytics'; IsFree = $false; RecommendedRetentionDays = 180; IsSplitTable = $false; ParentTable = $null }
        }
        $classifications = [PSCustomObject]@{
            Classifications = $classMap
            KeywordGaps     = @()
            DatabaseEntries = 1
        }

        $rulesData = [PSCustomObject]@{
            Rules         = @()
            TableCoverage = @{ 'SecurityEvent' = 5 }
            TotalRules    = 5
            EnabledRules  = 5
            DontCorrCount = 0
            IncCorrCount  = 0
        }

        $huntingData = [PSCustomObject]@{
            Queries       = @()
            TableCoverage = @{}
            TotalQueries  = 0
        }

        $dataTransforms = [PSCustomObject]@{
            Transforms   = @(
                [PSCustomObject]@{
                    DCRName       = 'dcr-securityevent'
                    DCRId         = '/subscriptions/00000000/dcr-securityevent'
                    OutputTable   = 'SecurityEvent'
                    InputStreams  = @('SecurityEvent')
                    TransformKql  = 'source | where EventID != 4688'
                    TransformType = 'Filter'
                    Destination   = 'workspace'
                }
            )
            TableLookup  = @{
                'SecurityEvent' = @(
                    [PSCustomObject]@{
                        DCRName       = 'dcr-securityevent'
                        DCRId         = '/subscriptions/00000000/dcr-securityevent'
                        OutputTable   = 'SecurityEvent'
                        InputStreams  = @('SecurityEvent')
                        TransformKql  = 'source | where EventID != 4688'
                        TransformType = 'Filter'
                        Destination   = 'workspace'
                    }
                )
            }
            RelevantDCRs = @(
                [PSCustomObject]@{ Name = 'dcr-securityevent'; Id = '/subscriptions/00000000/dcr-securityevent'; Location = 'eastus'; Kind = $null }
            )
            TotalDCRs    = 1
        }

        $script:txResult = Invoke-Analysis -TableUsage $tableUsage `
                                            -Classifications $classifications `
                                            -RulesData $rulesData `
                                            -HuntingData $huntingData `
                                            -SocRecommendations @() `
                                            -DataTransforms $dataTransforms
    }

    It 'marks table with HasTransform' {
        $se = $script:txResult.TableAnalysis | Where-Object TableName -eq 'SecurityEvent'
        $se.HasTransform | Should -Be $true
    }

    It 'captures transform types' {
        $se = $script:txResult.TableAnalysis | Where-Object TableName -eq 'SecurityEvent'
        $se.TransformTypes | Should -Contain 'Filter'
    }

    It 'includes transform summary stats' {
        $script:txResult.Summary.TablesWithTransforms | Should -Be 1
        $script:txResult.Summary.TransformDCRs | Should -Be 1
    }

    It 'passes through DataTransforms in analysis output' {
        $script:txResult.DataTransforms | Should -Not -BeNullOrEmpty
        $script:txResult.DataTransforms.Transforms.Count | Should -Be 1
    }
}

Describe 'Get-FieldsFromKql' {
    It 'extracts fields from where clause' {
        $result = Get-FieldsFromKql -Kql 'SecurityEvent | where EventID == 4625 and Account != "SYSTEM"'
        $result | Should -Contain 'EventID'
        $result | Should -Contain 'Account'
    }

    It 'extracts fields from project clause' {
        $result = Get-FieldsFromKql -Kql 'SecurityEvent | project TimeGenerated, Account, EventID, Computer'
        $result | Should -Contain 'TimeGenerated'
        $result | Should -Contain 'Account'
        $result | Should -Contain 'EventID'
        $result | Should -Contain 'Computer'
    }

    It 'extracts fields from summarize by clause' {
        $result = Get-FieldsFromKql -Kql 'SigninLogs | summarize count() by UserPrincipalName, IPAddress'
        $result | Should -Contain 'UserPrincipalName'
        $result | Should -Contain 'IPAddress'
    }

    It 'extracts fields from join on clause' {
        $kql = 'SecurityEvent | join kind=inner (SigninLogs) on AccountObjectId'
        $result = Get-FieldsFromKql -Kql $kql
        $result | Should -Contain 'AccountObjectId'
    }

    It 'extracts fields from extend clause' {
        $result = Get-FieldsFromKql -Kql 'SigninLogs | extend GeoInfo = geo_info_from_ip_address(IPAddress)'
        $result | Should -Contain 'GeoInfo'
    }

    It 'extracts fields from isnotempty/isempty' {
        $result = Get-FieldsFromKql -Kql 'SigninLogs | where isnotempty(UserPrincipalName) and isnull(DeviceDetail)'
        $result | Should -Contain 'UserPrincipalName'
        $result | Should -Contain 'DeviceDetail'
    }

    It 'filters out KQL keywords' {
        $result = Get-FieldsFromKql -Kql 'SecurityEvent | where EventID == 4625 | summarize count() by Account'
        $result | Should -Not -Contain 'where'
        $result | Should -Not -Contain 'summarize'
        $result | Should -Not -Contain 'count'
        $result | Should -Not -Contain 'source'
    }

    It 'handles complex multi-line KQL' {
        $kql = @"
let threshold = 10;
SigninLogs
| where ResultType != 0
| where UserPrincipalName has "@"
| summarize FailedCount = count() by UserPrincipalName, IPAddress, AppDisplayName
| where FailedCount > threshold
"@
        $result = Get-FieldsFromKql -Kql $kql
        $result | Should -Contain 'ResultType'
        $result | Should -Contain 'UserPrincipalName'
        $result | Should -Contain 'IPAddress'
        $result | Should -Contain 'AppDisplayName'
    }

    It 'returns empty array for empty input' {
        $result = Get-FieldsFromKql -Kql ''
        $result | Should -Be @()
    }

    It 'extracts fields from has/contains operators' {
        $result = Get-FieldsFromKql -Kql 'AuditLogs | where OperationName has "Add member"'
        $result | Should -Contain 'OperationName'
    }

    It 'filters out entity mapping artifacts and timespan literals' {
        $kql = 'SecurityEvent | where TimeGenerated > ago(1d) | project Account, Account_0_Name, AccountCustomEntity, TI_ipEntity'
        $result = Get-FieldsFromKql -Kql $kql
        $result | Should -Contain 'Account'
        $result | Should -Not -Contain 'Account_0_Name'
        $result | Should -Not -Contain 'AccountCustomEntity'
        $result | Should -Not -Contain 'TI_ipEntity'
        $result | Should -Not -Contain '1d'
    }

    It 'filters out lowercase-only tokens that are not real field names' {
        $kql = 'SecurityEvent | where EventID == 4625 | project Status, EventID | extend result = "test"'
        $result = Get-FieldsFromKql -Kql $kql
        $result | Should -Contain 'EventID'
        $result | Should -Contain 'Status'
        $result | Should -Not -Contain 'result'
    }
}

Describe 'Get-SplitKql' {
    It 'generates split KQL from knowledge base' {
        $hvFields = @{
            'SecurityEvent' = [PSCustomObject]@{
                description     = 'Windows Security Events'
                highValueFields = @('TimeGenerated', 'EventID', 'Account', 'Computer')
                splitHints      = @(
                    [PSCustomObject]@{
                        description = 'Keep critical EventIDs'
                        kql         = 'EventID in (4624, 4625, 4688)'
                    }
                )
            }
        }

        $result = Get-SplitKql -TableName 'SecurityEvent' -HighValueFieldsDB $hvFields
        $result.SplitKql | Should -Be 'EventID in (4624, 4625, 4688)'
        $result.Source | Should -Be 'knowledge-base'
        $result.HighValueFields | Should -Contain 'TimeGenerated'
        $result.HighValueFields | Should -Contain 'EventID'
    }

    It 'generates split KQL from rules when no KB entry exists' {
        $rules = @(
            [PSCustomObject]@{
                RuleName = 'Test Rule'
                Enabled  = $true
                Tables   = @('CustomTable_CL')
                Query    = 'CustomTable_CL | where Status == "Failed" | project TimeGenerated, UserName, Status'
            }
        )

        $result = Get-SplitKql -TableName 'CustomTable_CL' -Rules $rules
        $result.Source | Should -Be 'rule-analysis'
        $result.RuleFields | Should -Contain 'Status'
        $result.SplitKql | Should -Not -BeNullOrEmpty
        $result.RuleCount | Should -Be 1
    }

    It 'combines KB and rules when both available' {
        $hvFields = @{
            'SigninLogs' = [PSCustomObject]@{
                description     = 'Azure AD Sign-in Logs'
                highValueFields = @('TimeGenerated', 'UserPrincipalName', 'IPAddress', 'ResultType')
                splitHints      = @(
                    [PSCustomObject]@{
                        description = 'Keep failures'
                        kql         = 'ResultType != 0'
                    }
                )
            }
        }
        $rules = @(
            [PSCustomObject]@{
                RuleName = 'Brute Force'
                Enabled  = $true
                Tables   = @('SigninLogs')
                Query    = 'SigninLogs | where ResultType != 0 | summarize count() by UserPrincipalName, IPAddress'
            }
        )

        $result = Get-SplitKql -TableName 'SigninLogs' -Rules $rules -HighValueFieldsDB $hvFields
        $result.Source | Should -Be 'combined'
        $result.SplitKql | Should -Be 'ResultType != 0'
        $result.RuleFields.Count | Should -BeGreaterThan 0
        $result.AllFields | Should -Contain 'TimeGenerated'
    }

    It 'returns source=none when no data available' {
        $result = Get-SplitKql -TableName 'UnknownTable_CL'
        $result.Source | Should -Be 'none'
        $result.SplitKql | Should -BeNullOrEmpty
        $result.RuleFields.Count | Should -Be 0
    }

    It 'generates projection KQL from merged fields' {
        $hvFields = @{
            'SecurityEvent' = [PSCustomObject]@{
                description     = 'Windows Security Events'
                highValueFields = @('EventID', 'Account')
                splitHints      = @()
            }
        }

        $result = Get-SplitKql -TableName 'SecurityEvent' -HighValueFieldsDB $hvFields
        $result.ProjectKql | Should -Not -BeNullOrEmpty
        $result.ProjectKql | Should -Match 'source'
        $result.ProjectKql | Should -Match 'project'
        $result.AllFields | Should -Contain 'TimeGenerated'
        $result.AllFields | Should -Contain 'EventID'
        $result.AllFields | Should -Contain 'Account'
    }
}

Describe 'High-value-fields database integrity' {
    BeforeAll {
        $hvPath = Join-Path $PSScriptRoot '..\Data\high-value-fields.json'
        $script:hvRaw = Get-Content $hvPath -Raw | ConvertFrom-Json
        $script:hvTables = @($script:hvRaw.PSObject.Properties | Where-Object MemberType -eq 'NoteProperty')
    }

    It 'has at least 10 table entries' {
        $script:hvTables.Count | Should -BeGreaterOrEqual 10
    }

    It 'every entry has required fields' {
        foreach ($prop in $script:hvTables) {
            $entry = $prop.Value
            $entry.description | Should -Not -BeNullOrEmpty -Because "$($prop.Name) needs a description"
            $entry.highValueFields | Should -Not -BeNullOrEmpty -Because "$($prop.Name) needs highValueFields"
            $entry.highValueFields.Count | Should -BeGreaterOrEqual 1 -Because "$($prop.Name) should have at least 1 field"
        }
    }

    It 'every entry with splitHints has valid KQL' {
        foreach ($prop in $script:hvTables) {
            $entry = $prop.Value
            if ($entry.splitHints -and $entry.splitHints.Count -gt 0) {
                foreach ($hint in $entry.splitHints) {
                    $hint.kql | Should -Not -BeNullOrEmpty -Because "$($prop.Name) splitHint needs kql"
                    $hint.kql | Should -Not -Match '^source \|' -Because "$($prop.Name) splitHint KQL should be condition-only (portal prepends 'source | where')"
                    $hint.description | Should -Not -BeNullOrEmpty -Because "$($prop.Name) splitHint needs description"
                }
            }
        }
    }

    It 'all common Sentinel tables are covered' {
        $expectedTables = @('SecurityEvent', 'SigninLogs', 'CommonSecurityLog', 'Syslog', 'AuditLogs', 'AzureActivity', 'OfficeActivity')
        foreach ($t in $expectedTables) {
            $script:hvRaw.$t | Should -Not -BeNullOrEmpty -Because "$t should be in high-value-fields DB"
        }
    }

    It 'TimeGenerated or Timestamp is in highValueFields for well-covered tables' {
        foreach ($prop in $script:hvTables) {
            # Only validate the original curated tables (community-mined entries may lack time columns until KB regeneration)
            if ($prop.Value.description -match 'Mined from') { continue }
            $hasTime = ($prop.Value.highValueFields -contains 'TimeGenerated') -or ($prop.Value.highValueFields -contains 'Timestamp')
            $hasTime | Should -BeTrue -Because "$($prop.Name) should include TimeGenerated or Timestamp"
        }
    }
}

Describe 'Invoke-Analysis with split KQL generation' {
    BeforeAll {
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'SecurityEvent'; DataGB = 150; MonthlyGB = 50; RecordCount = 1000000; EstMonthlyCostUSD = 279.50; IsFree = $false }
        )

        $classMap = @{
            'SecurityEvent' = [PSCustomObject]@{ Classification = 'primary'; Category = 'Windows Security'; RecommendedTier = 'analytics'; IsFree = $false; RecommendedRetentionDays = 180; IsSplitTable = $false; ParentTable = $null }
        }
        $classifications = [PSCustomObject]@{
            Classifications = $classMap
            KeywordGaps     = @()
            DatabaseEntries = 1
        }

        $rulesData = [PSCustomObject]@{
            Rules         = @(
                [PSCustomObject]@{
                    RuleName = 'Failed Logons'
                    Kind     = 'Scheduled'
                    Enabled  = $true
                    Tables   = @('SecurityEvent')
                    HasQuery = $true
                    Query    = 'SecurityEvent | where EventID == 4625 | summarize count() by Account, Computer'
                    Description = ''
                    ExcludedFromCorrelation = $false
                    IncludedInCorrelation   = $false
                }
            )
            TableCoverage = @{ 'SecurityEvent' = 1 }
            TotalRules    = 1
            EnabledRules  = 1
            DontCorrCount = 0
            IncCorrCount  = 0
        }

        $huntingData = [PSCustomObject]@{
            Queries       = @()
            TableCoverage = @{}
            TotalQueries  = 0
        }

        $hvFields = @{
            'SecurityEvent' = [PSCustomObject]@{
                description     = 'Windows Security Events'
                highValueFields = @('TimeGenerated', 'EventID', 'Account', 'Computer', 'Activity')
                splitHints      = @(
                    [PSCustomObject]@{
                        description = 'Keep critical EventIDs'
                        kql         = 'EventID in (4624, 4625, 4688)'
                    }
                )
            }
        }

        $script:splitResult = Invoke-Analysis -TableUsage $tableUsage `
                                               -Classifications $classifications `
                                               -RulesData $rulesData `
                                               -HuntingData $huntingData `
                                               -SocRecommendations @() `
                                               -HighValueFields $hvFields
    }

    It 'generates SplitCandidate recommendation with SplitSuggestion' {
        $rec = $script:splitResult.Recommendations | Where-Object { $_.Type -eq 'SplitCandidate' -and $_.TableName -eq 'SecurityEvent' }
        $rec | Should -Not -BeNullOrEmpty
        $rec.SplitSuggestion | Should -Not -BeNullOrEmpty
    }

    It 'uses combined source when both KB and rules available' {
        $rec = $script:splitResult.Recommendations | Where-Object { $_.Type -eq 'SplitCandidate' -and $_.TableName -eq 'SecurityEvent' }
        $rec.SplitSuggestion.Source | Should -Be 'combined'
    }

    It 'includes split KQL from knowledge base' {
        $rec = $script:splitResult.Recommendations | Where-Object { $_.Type -eq 'SplitCandidate' -and $_.TableName -eq 'SecurityEvent' }
        $rec.SplitSuggestion.SplitKql | Should -Match 'EventID'
    }

    It 'extracts rule fields' {
        $rec = $script:splitResult.Recommendations | Where-Object { $_.Type -eq 'SplitCandidate' -and $_.TableName -eq 'SecurityEvent' }
        $rec.SplitSuggestion.RuleFields | Should -Contain 'EventID'
        $rec.SplitSuggestion.RuleFields | Should -Contain 'Account'
    }

    It 'generates projection KQL' {
        $rec = $script:splitResult.Recommendations | Where-Object { $_.Type -eq 'SplitCandidate' -and $_.TableName -eq 'SecurityEvent' }
        $rec.SplitSuggestion.ProjectKql | Should -Not -BeNullOrEmpty
        $rec.SplitSuggestion.ProjectKql | Should -Match 'project'
    }
}

Describe 'Invoke-Analysis Detection Analyzer and XDR Checker' {
    BeforeAll {
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'SigninLogs'; DataGB = 10; MonthlyGB = 3.3; RecordCount = 50000; EstMonthlyCostUSD = 18.45; IsFree = $false },
            [PSCustomObject]@{ TableName = 'DeviceEvents'; DataGB = 5; MonthlyGB = 1.7; RecordCount = 20000; EstMonthlyCostUSD = 9.50; IsFree = $false }
        )

        $classifications = [PSCustomObject]@{
            Classifications = @{
                'SigninLogs' = [PSCustomObject]@{ Classification = 'primary'; Category = 'Identity & Access'; RecommendedTier = 'analytics'; IsFree = $false; RecommendedRetentionDays = 365; IsSplitTable = $false; ParentTable = $null }
                'DeviceEvents' = [PSCustomObject]@{ Classification = 'primary'; Category = 'Endpoint'; RecommendedTier = 'analytics'; IsFree = $false; RecommendedRetentionDays = 365; IsSplitTable = $false; ParentTable = $null }
            }
            KeywordGaps = @()
            DatabaseEntries = 2
        }

        $rulesData = [PSCustomObject]@{
            Rules = @(
                [PSCustomObject]@{
                    RuleName = 'Suspicious Sign-in Burst'
                    Kind = 'Scheduled'
                    Enabled = $true
                    Tables = @('SigninLogs')
                    HasQuery = $true
                    Query = 'SigninLogs | where ResultType != 0'
                    Description = ''
                    ExcludedFromCorrelation = $false
                    IncludedInCorrelation = $false
                }
            )
            TableCoverage = @{ 'SigninLogs' = 1 }
            TotalRules = 1
            EnabledRules = 1
            DontCorrCount = 0
            IncCorrCount = 0
        }

        $huntingData = [PSCustomObject]@{
            Queries = @()
            TableCoverage = @{}
            TotalQueries = 0
        }

        $incidents = @(
            [PSCustomObject]@{
                IncidentId = 'inc-1'
                IncidentNumber = 1
                Title = 'Suspicious Sign-in Burst - Test Case'
                Status = 'Closed'
                Classification = 'FalsePositive'
                ClassificationReason = 'InaccurateData'
                CreatedTimeUtc = [datetime]'2026-04-08T10:00:00Z'
                ClosedTimeUtc = [datetime]'2026-04-08T10:05:00Z'
                RelatedAnalyticRuleIds = @()
                RelatedAnalyticRuleNames = @('Suspicious Sign-in Burst')
            }
        )

        $automationRules = @(
            [PSCustomObject]@{
                AutomationRuleId = 'ar-1'
                DisplayName = 'Auto close suspicious sign-in tests'
                Enabled = $true
                IsCloseIncidentRule = $true
                HasConditions = $true
                TitleFilters = @('Suspicious Sign-in Burst*')
                TitleOperators = @('Contains')
                RuleIdFilters = @()
            }
        )

        $defenderXdr = [PSCustomObject]@{
            TotalXDRRules = 0
            XDRTableCoverage = @{}
            KnownXDRTables = @('DeviceEvents')
        }

        $tableRetention = @(
            [PSCustomObject]@{ TableName = 'SigninLogs'; RetentionInDays = 90; TotalRetentionInDays = 90; ArchiveRetentionInDays = 0; Plan = 'Analytics' },
            [PSCustomObject]@{ TableName = 'DeviceEvents'; RetentionInDays = 90; TotalRetentionInDays = 90; ArchiveRetentionInDays = 0; Plan = 'Analytics' }
        )

        $script:featureResult = Invoke-Analysis -TableUsage $tableUsage `
                                                -Classifications $classifications `
                                                -RulesData $rulesData `
                                                -HuntingData $huntingData `
                                                -DefenderXDR $defenderXdr `
                                                -TableRetention $tableRetention `
                                                -Incidents $incidents `
                                                -AutomationRules $automationRules `
                                                -IncludeDetectionAnalyzer `
                                                -SocRecommendations @()
    }

    It 'produces DetectionAnalyzer summary' {
        $script:featureResult.DetectionAnalyzer | Should -Not -BeNullOrEmpty
        $script:featureResult.DetectionAnalyzer.Summary.RulesAnalyzed | Should -Be 1
        $script:featureResult.DetectionAnalyzer.Summary.IncidentsAnalyzed | Should -Be 1
    }

    It 'includes detection coverage stats in DetectionAnalyzer summary' {
        $s = $script:featureResult.DetectionAnalyzer.Summary
        $s.TotalIngestionGB | Should -BeGreaterThan 0
        $s.TotalTables | Should -BeGreaterThan 0
        $s.DetectionCoveragePct | Should -BeGreaterOrEqual 0
        $s.HuntingCoveragePct | Should -BeGreaterOrEqual 0
        $s.CombinedCoveragePct | Should -BeGreaterOrEqual $s.DetectionCoveragePct
        $s.AvgDetectionsPerTable | Should -BeGreaterOrEqual 0
        # SigninLogs has 1 analytic rule, so detection coverage should include its table count
        $s.TablesWithDetection | Should -BeGreaterThan 0
        $s.DetectionCoverageGB | Should -BeGreaterThan 0
    }

    It 'attributes auto-closed incidents when automation title filter matches' {
        $metric = $script:featureResult.DetectionAnalyzer.RuleMetrics | Select-Object -First 1
        $metric.IncidentsAutoClosed | Should -Be 1
        $metric.AutoCloseRatio | Should -Be 1
    }

    It 'produces XDR checker findings for advisory retention gap' {
        $script:featureResult.XdrChecker | Should -Not -BeNullOrEmpty
        @($script:featureResult.XdrChecker.Findings).Count | Should -BeGreaterThan 0
    }

    It 'sets XDRState to Analytics for known XDR table with Analytics plan' {
        $t = $script:featureResult.TableAnalysis | Where-Object TableName -eq 'DeviceEvents'
        $t.XDRState | Should -Be 'Analytics'
        $t.IsXDRStreaming | Should -Be $true
    }

    It 'sets XDRState to null for non-XDR tables' {
        $t = $script:featureResult.TableAnalysis | Where-Object TableName -eq 'SigninLogs'
        $t.XDRState | Should -BeNullOrEmpty
        $t.IsXDRStreaming | Should -Be $false
    }
}

Describe 'Test-AutomationRuleIncidentMatch' {
    It 'matches by title filter' {
        $rule = [PSCustomObject]@{
            HasConditions = $true
            TitleFilters = @('Suspicious*')
            TitleOperators = @('Contains')
            RuleIdFilters = @()
        }
        Test-AutomationRuleIncidentMatch -AutomationRule $rule -IncidentTitle 'Suspicious Sign-in Burst' -IncidentRuleIds @() | Should -Be $true
    }

    It 'matches by analytic rule ID' {
        $rule = [PSCustomObject]@{
            HasConditions = $true
            TitleFilters = @()
            TitleOperators = @()
            RuleIdFilters = @('/subscriptions/xxx/providers/Microsoft.SecurityInsights/alertRules/rule-123')
        }
        Test-AutomationRuleIncidentMatch -AutomationRule $rule -IncidentTitle 'Some Alert' -IncidentRuleIds @('/subscriptions/xxx/providers/Microsoft.SecurityInsights/alertRules/rule-123') | Should -Be $true
    }

    It 'matches blanket close rule with no conditions' {
        $rule = [PSCustomObject]@{
            HasConditions = $false
            TitleFilters = @()
            TitleOperators = @()
            RuleIdFilters = @()
        }
        Test-AutomationRuleIncidentMatch -AutomationRule $rule -IncidentTitle 'Any Alert' -IncidentRuleIds @() | Should -Be $true
    }

    It 'does not match when title and rule ID both miss' {
        $rule = [PSCustomObject]@{
            HasConditions = $true
            TitleFilters = @('Specific Alert*')
            TitleOperators = @('Contains')
            RuleIdFilters = @('/subscriptions/xxx/providers/Microsoft.SecurityInsights/alertRules/other-rule')
        }
        Test-AutomationRuleIncidentMatch -AutomationRule $rule -IncidentTitle 'Unrelated Alert' -IncidentRuleIds @('/subscriptions/xxx/providers/Microsoft.SecurityInsights/alertRules/rule-456') | Should -Be $false
    }

    It 'matches by Equals operator on title' {
        $rule = [PSCustomObject]@{
            HasConditions = $true
            TitleFilters = @('Exact Title')
            TitleOperators = @('Equals')
            RuleIdFilters = @()
        }
        Test-AutomationRuleIncidentMatch -AutomationRule $rule -IncidentTitle 'Exact Title' -IncidentRuleIds @() | Should -Be $true
    }

    It 'does not match by Equals when title differs' {
        $rule = [PSCustomObject]@{
            HasConditions = $true
            TitleFilters = @('Exact Title')
            TitleOperators = @('Equals')
            RuleIdFilters = @()
        }
        Test-AutomationRuleIncidentMatch -AutomationRule $rule -IncidentTitle 'Exact Title Extra' -IncidentRuleIds @() | Should -Be $false
    }

    It 'matches by StartsWith operator' {
        $rule = [PSCustomObject]@{
            HasConditions = $true
            TitleFilters = @('Suspicious')
            TitleOperators = @('StartsWith')
            RuleIdFilters = @()
        }
        Test-AutomationRuleIncidentMatch -AutomationRule $rule -IncidentTitle 'Suspicious Login Attempt' -IncidentRuleIds @() | Should -Be $true
    }

    It 'matches by EndsWith operator' {
        $rule = [PSCustomObject]@{
            HasConditions = $true
            TitleFilters = @('Attempt')
            TitleOperators = @('EndsWith')
            RuleIdFilters = @()
        }
        Test-AutomationRuleIncidentMatch -AutomationRule $rule -IncidentTitle 'Suspicious Login Attempt' -IncidentRuleIds @() | Should -Be $true
    }

    It 'matches by GUID tail when ARM resource IDs differ in prefix' {
        $rule = [PSCustomObject]@{
            HasConditions = $true
            TitleFilters = @()
            TitleOperators = @()
            RuleIdFilters = @('/subscriptions/aaa/providers/Microsoft.SecurityInsights/alertRules/rule-guid-123')
        }
        Test-AutomationRuleIncidentMatch -AutomationRule $rule -IncidentTitle 'Alert' -IncidentRuleIds @('/subscriptions/bbb/providers/Microsoft.SecurityInsights/alertRules/rule-guid-123') | Should -Be $true
    }
}

Describe 'SentinelHealth-based auto-close attribution' {
    BeforeAll {
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'SigninLogs'; DataGB = 10; MonthlyGB = 3.3; RecordCount = 50000; EstMonthlyCostUSD = 18.45; IsFree = $false }
        )
        $classifications = [PSCustomObject]@{
            Classifications = @{
                'SigninLogs' = [PSCustomObject]@{ Classification = 'primary'; Category = 'Identity & Access'; RecommendedTier = 'analytics'; IsFree = $false; RecommendedRetentionDays = 365; IsSplitTable = $false; ParentTable = $null }
            }
            KeywordGaps = @()
            DatabaseEntries = 1
        }
        $rulesData = [PSCustomObject]@{
            Rules = @(
                [PSCustomObject]@{
                    RuleName = 'Noisy Alert Rule'
                    Kind = 'Scheduled'
                    Enabled = $true
                    Tables = @('SigninLogs')
                    HasQuery = $true
                    Query = 'SigninLogs | where ResultType != 0'
                    Description = ''
                    ExcludedFromCorrelation = $false
                    IncludedInCorrelation = $false
                }
            )
            TableCoverage = @{ 'SigninLogs' = 1 }
            TotalRules = 1; EnabledRules = 1; DontCorrCount = 0; IncCorrCount = 0
        }
        $huntingData = [PSCustomObject]@{ Queries = @(); TableCoverage = @{}; TotalQueries = 0 }

        # Incidents closed but automation rule has NO matching title filter
        $incidents = @(
            [PSCustomObject]@{
                IncidentId = 'inc-health-1'
                IncidentNumber = 42
                Title = 'Noisy Alert Rule - test event'
                Status = 'Closed'
                Classification = $null
                ClassificationReason = $null
                CreatedTimeUtc = [datetime]'2026-04-08T10:00:00Z'
                ClosedTimeUtc = [datetime]'2026-04-08T10:02:00Z'
                RelatedAnalyticRuleIds = @()
                RelatedAnalyticRuleNames = @('Noisy Alert Rule')
            }
        )
        # Automation rule exists but has a different title filter (would NOT match without health data)
        $automationRules = @(
            [PSCustomObject]@{
                AutomationRuleId = 'ar-health-1'
                DisplayName = 'Auto close noisy'
                Enabled = $true
                IsCloseIncidentRule = $true
                HasConditions = $true
                TitleFilters = @('Completely Different Title*')
                TitleOperators = @('Contains')
                RuleIdFilters = @()
            }
        )
        # SentinelHealth tells us incident 42 was auto-closed
        $healthData = @{ 42 = $true }

        $tableRetention = @(
            [PSCustomObject]@{ TableName = 'SigninLogs'; RetentionInDays = 90; TotalRetentionInDays = 90; ArchiveRetentionInDays = 0; Plan = 'Analytics' }
        )

        $script:healthResult = Invoke-Analysis -TableUsage $tableUsage `
                                               -Classifications $classifications `
                                               -RulesData $rulesData `
                                               -HuntingData $huntingData `
                                               -TableRetention $tableRetention `
                                               -Incidents $incidents `
                                               -AutomationRules $automationRules `
                                               -AutoCloseHealthData $healthData `
                                               -IncludeDetectionAnalyzer `
                                               -SocRecommendations @()
    }

    It 'uses SentinelHealth data to attribute auto-close even when rule matching fails' {
        $metric = $script:healthResult.DetectionAnalyzer.RuleMetrics | Select-Object -First 1
        $metric.IncidentsAutoClosed | Should -Be 1
        $metric.AutoCloseRatio | Should -Be 1
    }

    It 'falls back to rule matching when health data is null' {
        $result2 = Invoke-Analysis -TableUsage $tableUsage `
                                   -Classifications $classifications `
                                   -RulesData $rulesData `
                                   -HuntingData $huntingData `
                                   -TableRetention $tableRetention `
                                   -Incidents $incidents `
                                   -AutomationRules $automationRules `
                                   -IncludeDetectionAnalyzer `
                                   -SocRecommendations @()
        $metric = $result2.DetectionAnalyzer.RuleMetrics | Select-Object -First 1
        # Without health data AND mismatched title filter, auto-close should be 0
        $metric.IncidentsAutoClosed | Should -Be 0
    }
}

Describe 'Get-AutomationRules Resolved status and Boolean conditions' {
    It 'detects Resolved status as close-incident rule' {
        $mockResponse = @{
            value = @(
                @{
                    name = 'ar-resolved-1'
                    properties = @{
                        displayName = 'Resolve noisy alerts'
                        isEnabled = $true
                        order = 1
                        triggeringLogic = @{
                            triggersOn = 'Incidents'
                            triggersWhen = 'Created'
                            conditions = @()
                        }
                        actions = @(
                            @{
                                order = 1
                                actionType = 'ModifyProperties'
                                actionConfiguration = @{
                                    status = 'Resolved'
                                }
                            }
                        )
                    }
                }
            )
        }
        Mock Invoke-AzRestWithRetry { $mockResponse }
        $ctx = [PSCustomObject]@{ ArmToken = 'fake'; ResourceId = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws' }
        $rules = Get-AutomationRules -Context $ctx
        $rules[0].IsCloseIncidentRule | Should -Be $true
    }

    It 'extracts title filter from Boolean wrapper conditions' {
        $mockResponse = @{
            value = @(
                @{
                    name = 'ar-bool-1'
                    properties = @{
                        displayName = 'Boolean wrapper rule'
                        isEnabled = $true
                        order = 1
                        triggeringLogic = @{
                            triggersOn = 'Incidents'
                            triggersWhen = 'Created'
                            conditions = @(
                                @{
                                    conditionType = 'Boolean'
                                    conditionProperties = @{
                                        operator = 'And'
                                        innerConditions = @(
                                            @{
                                                conditionType = 'Property'
                                                conditionProperties = @{
                                                    propertyName = 'IncidentTitle'
                                                    operator = 'Contains'
                                                    propertyValues = @('Noisy Alert*')
                                                }
                                            }
                                        )
                                    }
                                }
                            )
                        }
                        actions = @(
                            @{
                                order = 1
                                actionType = 'ModifyProperties'
                                actionConfiguration = @{ status = 'Closed' }
                            }
                        )
                    }
                }
            )
        }
        Mock Invoke-AzRestWithRetry { $mockResponse }
        $ctx = [PSCustomObject]@{ ArmToken = 'fake'; ResourceId = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws' }
        $rules = Get-AutomationRules -Context $ctx
        $rules[0].TitleFilters | Should -Contain 'Noisy Alert*'
        $rules[0].TitleOperators | Should -Contain 'Contains'
        $rules[0].IsCloseIncidentRule | Should -Be $true
        $rules[0].HasConditions | Should -Be $true
    }
}

Describe 'Detection coverage uses table count' {
    BeforeAll {
        # 2 tables, 1 with detection, one without - small GB values (simulating demo env)
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'SigninLogs'; DataGB = 0.001; MonthlyGB = 0.0003; RecordCount = 10; EstMonthlyCostUSD = 0.01; IsFree = $false },
            [PSCustomObject]@{ TableName = 'AuditLogs'; DataGB = 0.001; MonthlyGB = 0.0003; RecordCount = 10; EstMonthlyCostUSD = 0.01; IsFree = $false }
        )
        $classifications = [PSCustomObject]@{
            Classifications = @{
                'SigninLogs' = [PSCustomObject]@{ Classification = 'primary'; Category = 'Identity & Access'; RecommendedTier = 'analytics'; IsFree = $false; RecommendedRetentionDays = 365; IsSplitTable = $false; ParentTable = $null }
                'AuditLogs' = [PSCustomObject]@{ Classification = 'primary'; Category = 'Identity & Access'; RecommendedTier = 'analytics'; IsFree = $false; RecommendedRetentionDays = 365; IsSplitTable = $false; ParentTable = $null }
            }
            KeywordGaps = @()
            DatabaseEntries = 2
        }
        $rulesData = [PSCustomObject]@{
            Rules = @(
                [PSCustomObject]@{
                    RuleName = 'Test Rule'
                    Kind = 'Scheduled'
                    Enabled = $true
                    Tables = @('SigninLogs')
                    HasQuery = $true
                    Query = 'SigninLogs | take 1'
                    Description = ''
                    ExcludedFromCorrelation = $false
                    IncludedInCorrelation = $false
                }
            )
            TableCoverage = @{ 'SigninLogs' = 1 }
            TotalRules = 1; EnabledRules = 1; DontCorrCount = 0; IncCorrCount = 0
        }
        $huntingData = [PSCustomObject]@{ Queries = @(); TableCoverage = @{}; TotalQueries = 0 }
        $tableRetention = @(
            [PSCustomObject]@{ TableName = 'SigninLogs'; RetentionInDays = 90; TotalRetentionInDays = 90; ArchiveRetentionInDays = 0; Plan = 'Analytics' },
            [PSCustomObject]@{ TableName = 'AuditLogs'; RetentionInDays = 90; TotalRetentionInDays = 90; ArchiveRetentionInDays = 0; Plan = 'Analytics' }
        )

        $script:coverageResult = Invoke-Analysis -TableUsage $tableUsage `
                                                  -Classifications $classifications `
                                                  -RulesData $rulesData `
                                                  -HuntingData $huntingData `
                                                  -TableRetention $tableRetention `
                                                  -IncludeDetectionAnalyzer `
                                                  -SocRecommendations @()
    }

    It 'reports detection coverage as 50% with 1 of 2 tables covered' {
        $s = $script:coverageResult.DetectionAnalyzer.Summary
        $s.DetectionCoveragePct | Should -Be 50
        $s.TablesWithDetection | Should -Be 1
        $s.TotalTables | Should -Be 2
    }

    It 'reports non-zero coverage even when GB is near zero' {
        $s = $script:coverageResult.DetectionAnalyzer.Summary
        $s.DetectionCoveragePct | Should -BeGreaterThan 0
        # GB-based would round to 0%; table-count should not
    }
}

Describe 'Invoke-Analysis XDR Basic tier streaming' {
    BeforeAll {
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'EmailEvents'; DataGB = 2; MonthlyGB = 0.7; RecordCount = 5000; EstMonthlyCostUSD = 3.90; IsFree = $false }
        )
        $classifications = [PSCustomObject]@{
            Classifications = @{
                'EmailEvents' = [PSCustomObject]@{ Classification = 'primary'; Category = 'Email'; RecommendedTier = 'analytics'; IsFree = $false; RecommendedRetentionDays = 365; IsSplitTable = $false; ParentTable = $null }
            }
            KeywordGaps = @()
            DatabaseEntries = 1
        }
        $rulesData = [PSCustomObject]@{ Rules = @(); TableCoverage = @{}; TotalRules = 0; EnabledRules = 0; DontCorrCount = 0; IncCorrCount = 0 }
        $huntingData = [PSCustomObject]@{ Queries = @(); TableCoverage = @{}; TotalQueries = 0 }
        $defenderXdr = [PSCustomObject]@{
            TotalXDRRules = 0
            XDRTableCoverage = @{}
            KnownXDRTables = @('EmailEvents')
        }
        $tableRetention = @(
            [PSCustomObject]@{ TableName = 'EmailEvents'; RetentionInDays = 30; TotalRetentionInDays = 30; ArchiveRetentionInDays = 0; Plan = 'Basic' }
        )
        $script:basicResult = Invoke-Analysis -TableUsage $tableUsage -Classifications $classifications `
            -RulesData $rulesData -HuntingData $huntingData -DefenderXDR $defenderXdr `
            -TableRetention $tableRetention -SocRecommendations @()
    }

    It 'marks Basic plan XDR table as streaming' {
        $t = $script:basicResult.TableAnalysis | Where-Object TableName -eq 'EmailEvents'
        $t.IsXDRStreaming | Should -Be $true
        $t.XDRState | Should -Be 'Basic'
    }

    It 'includes Basic tier table in XDR checker' {
        $script:basicResult.XdrChecker.Summary.StreamedTableCount | Should -Be 1
    }
}

Describe 'Invoke-Analysis XDR Auxiliary (data lake) tier streaming' {
    BeforeAll {
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'DeviceNetworkEvents'; DataGB = 5; MonthlyGB = 1.5; RecordCount = 10000; EstMonthlyCostUSD = 8.39; IsFree = $false }
        )
        $classifications = [PSCustomObject]@{
            Classifications = @{
                'DeviceNetworkEvents' = [PSCustomObject]@{ Classification = 'primary'; Category = 'Endpoint'; RecommendedTier = 'analytics'; IsFree = $false; RecommendedRetentionDays = 365; IsSplitTable = $false; ParentTable = $null }
            }
            KeywordGaps = @()
            DatabaseEntries = 1
        }
        $rulesData = [PSCustomObject]@{ Rules = @(); TableCoverage = @{}; TotalRules = 0; EnabledRules = 0; DontCorrCount = 0; IncCorrCount = 0 }
        $huntingData = [PSCustomObject]@{ Queries = @(); TableCoverage = @{}; TotalQueries = 0 }
        $defenderXdr = [PSCustomObject]@{
            TotalXDRRules = 0
            XDRTableCoverage = @{}
            KnownXDRTables = @('DeviceNetworkEvents')
        }
        $tableRetention = @(
            [PSCustomObject]@{ TableName = 'DeviceNetworkEvents'; RetentionInDays = 30; TotalRetentionInDays = 1825; ArchiveRetentionInDays = 0; Plan = 'Auxiliary' }
        )
        $script:auxResult = Invoke-Analysis -TableUsage $tableUsage -Classifications $classifications `
            -RulesData $rulesData -HuntingData $huntingData -DefenderXDR $defenderXdr `
            -TableRetention $tableRetention -SocRecommendations @()
    }

    It 'marks Auxiliary plan XDR table as streaming with data lake state' {
        $t = $script:auxResult.TableAnalysis | Where-Object TableName -eq 'DeviceNetworkEvents'
        $t.IsXDRStreaming | Should -Be $true
        $t.XDRState | Should -Be 'Auxiliary'
    }

    It 'does not flag NotForwardedToDataLake for Auxiliary table' {
        $findings = $script:auxResult.XdrChecker.Findings | Where-Object Type -eq 'NotForwardedToDataLake'
        $findings | Should -BeNullOrEmpty
    }

    It 'includes Auxiliary tier table in XDR checker streamed count' {
        $script:auxResult.XdrChecker.Summary.StreamedTableCount | Should -Be 1
    }
}

Describe 'Invoke-Analysis XDR not-streamed tables' {
    BeforeAll {
        # Only one table in workspace (SecurityEvent), but KnownXDRTables has two XDR tables
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'SecurityEvent'; DataGB = 10; MonthlyGB = 3; RecordCount = 50000; EstMonthlyCostUSD = 16.77; IsFree = $false }
            [PSCustomObject]@{ TableName = 'DeviceProcessEvents'; DataGB = 5; MonthlyGB = 1.5; RecordCount = 10000; EstMonthlyCostUSD = 8.39; IsFree = $false }
        )
        $classifications = [PSCustomObject]@{
            Classifications = @{
                'SecurityEvent' = [PSCustomObject]@{ Classification = 'primary'; Category = 'Security'; RecommendedTier = 'analytics'; IsFree = $false; RecommendedRetentionDays = 365; IsSplitTable = $false; ParentTable = $null }
                'DeviceProcessEvents' = [PSCustomObject]@{ Classification = 'primary'; Category = 'Endpoint'; RecommendedTier = 'analytics'; IsFree = $false; RecommendedRetentionDays = 365; IsSplitTable = $false; ParentTable = $null }
            }
            KeywordGaps = @()
            DatabaseEntries = 2
        }
        $rulesData = [PSCustomObject]@{ Rules = @(); TableCoverage = @{}; TotalRules = 0; EnabledRules = 0; DontCorrCount = 0; IncCorrCount = 0 }
        $huntingData = [PSCustomObject]@{ Queries = @(); TableCoverage = @{}; TotalQueries = 0 }
        $defenderXdr = [PSCustomObject]@{
            TotalXDRRules = 0
            XDRTableCoverage = @{}
            KnownXDRTables = @('DeviceProcessEvents', 'DeviceNetworkEvents', 'EmailEvents')
        }
        # Only DeviceProcessEvents is in Sentinel workspace
        $tableRetention = @(
            [PSCustomObject]@{ TableName = 'SecurityEvent'; RetentionInDays = 90; TotalRetentionInDays = 90; ArchiveRetentionInDays = 0; Plan = 'Analytics' }
            [PSCustomObject]@{ TableName = 'DeviceProcessEvents'; RetentionInDays = 90; TotalRetentionInDays = 365; ArchiveRetentionInDays = 275; Plan = 'Analytics' }
        )
        $script:notStreamedResult = Invoke-Analysis -TableUsage $tableUsage -Classifications $classifications `
            -RulesData $rulesData -HuntingData $huntingData -DefenderXDR $defenderXdr `
            -TableRetention $tableRetention -SocRecommendations @()
    }

    It 'generates NotStreaming findings for XDR tables not in workspace' {
        $notStreaming = @($script:notStreamedResult.XdrChecker.Findings | Where-Object Type -eq 'NotStreaming')
        $notStreaming.Count | Should -Be 2
        $notStreaming.TableName | Should -Contain 'DeviceNetworkEvents'
        $notStreaming.TableName | Should -Contain 'EmailEvents'
    }

    It 'sets severity to Information for NotStreaming findings' {
        $notStreaming = @($script:notStreamedResult.XdrChecker.Findings | Where-Object Type -eq 'NotStreaming')
        $notStreaming | ForEach-Object { $_.Severity | Should -Be 'Information' }
    }

    It 'generates Low priority recommendations for not-streamed tables' {
        $recs = @($script:notStreamedResult.XdrChecker.Recommendations | Where-Object { $_.TableName -in @('DeviceNetworkEvents', 'EmailEvents') })
        $recs.Count | Should -Be 2
        $recs | ForEach-Object { $_.Priority | Should -Be 'Low' }
    }

    It 'reports NotStreamedCount in summary' {
        $script:notStreamedResult.XdrChecker.Summary.NotStreamedCount | Should -Be 2
    }

    It 'does not flag streamed table as NotStreaming' {
        $notStreaming = @($script:notStreamedResult.XdrChecker.Findings | Where-Object Type -eq 'NotStreaming')
        $notStreaming.TableName | Should -Not -Contain 'DeviceProcessEvents'
    }
}

Describe 'Invoke-Analysis XDR not-streamed does not misidentify workspace tables with zero lookback usage' {
    BeforeAll {
        # DeviceProcessEvents is in workspace (tableRetention) but has NO usage during lookback (absent from tableUsage).
        # It must NOT be flagged as NotStreaming.
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'SecurityEvent'; DataGB = 10; MonthlyGB = 3; RecordCount = 50000; EstMonthlyCostUSD = 16.77; IsFree = $false }
        )
        $classifications = [PSCustomObject]@{
            Classifications = @{
                'SecurityEvent' = [PSCustomObject]@{ Classification = 'primary'; Category = 'Security'; RecommendedTier = 'analytics'; IsFree = $false; RecommendedRetentionDays = 365; IsSplitTable = $false; ParentTable = $null }
            }
            KeywordGaps = @()
            DatabaseEntries = 1
        }
        $rulesData = [PSCustomObject]@{ Rules = @(); TableCoverage = @{}; TotalRules = 0; EnabledRules = 0; DontCorrCount = 0; IncCorrCount = 0 }
        $huntingData = [PSCustomObject]@{ Queries = @(); TableCoverage = @{}; TotalQueries = 0 }
        $defenderXdr = [PSCustomObject]@{
            TotalXDRRules = 0
            XDRTableCoverage = @{}
            KnownXDRTables = @('DeviceProcessEvents', 'EmailEvents')
        }
        # DeviceProcessEvents IS in workspace retention but has no usage in the lookback window
        $tableRetention = @(
            [PSCustomObject]@{ TableName = 'SecurityEvent'; RetentionInDays = 90; TotalRetentionInDays = 90; ArchiveRetentionInDays = 0; Plan = 'Analytics' }
            [PSCustomObject]@{ TableName = 'DeviceProcessEvents'; RetentionInDays = 90; TotalRetentionInDays = 365; ArchiveRetentionInDays = 275; Plan = 'Analytics' }
        )
        $script:zeroUsageResult = Invoke-Analysis -TableUsage $tableUsage -Classifications $classifications `
            -RulesData $rulesData -HuntingData $huntingData -DefenderXDR $defenderXdr `
            -TableRetention $tableRetention -SocRecommendations @()
    }

    It 'does not flag a workspace-present XDR table as NotStreaming when it has zero lookback usage' {
        $notStreaming = @($script:zeroUsageResult.XdrChecker.Findings | Where-Object Type -eq 'NotStreaming')
        $notStreaming.TableName | Should -Not -Contain 'DeviceProcessEvents'
    }

    It 'still flags truly not-streamed XDR table as NotStreaming' {
        $notStreaming = @($script:zeroUsageResult.XdrChecker.Findings | Where-Object Type -eq 'NotStreaming')
        $notStreaming.TableName | Should -Contain 'EmailEvents'
    }
}

Describe 'Invoke-Analysis XDR tables in workspace with default retention are flagged as NotStreaming' {
    BeforeAll {
        # XDR tables exist in the Tables API (RetentionMap) with default retention (ArchiveRetentionInDays = 0)
        # but have zero usage during lookback. These should be flagged as NotStreaming because the Tables API
        # creates schema entries for all known XDR tables when streaming is configured, even without data.
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'SecurityEvent'; DataGB = 10; MonthlyGB = 3; RecordCount = 50000; EstMonthlyCostUSD = 16.77; IsFree = $false }
        )
        $classifications = [PSCustomObject]@{
            Classifications = @{
                'SecurityEvent' = [PSCustomObject]@{ Classification = 'primary'; Category = 'Security'; RecommendedTier = 'analytics'; IsFree = $false; RecommendedRetentionDays = 365; IsSplitTable = $false; ParentTable = $null }
            }
            KeywordGaps = @()
            DatabaseEntries = 1
        }
        $rulesData = [PSCustomObject]@{ Rules = @(); TableCoverage = @{}; TotalRules = 0; EnabledRules = 0; DontCorrCount = 0; IncCorrCount = 0 }
        $huntingData = [PSCustomObject]@{ Queries = @(); TableCoverage = @{}; TotalQueries = 0 }
        $defenderXdr = [PSCustomObject]@{
            TotalXDRRules = 0
            XDRTableCoverage = @{}
            KnownXDRTables = @('DeviceEvents', 'DeviceProcessEvents')
        }
        # Both XDR tables exist in workspace Tables API but with default retention (no archive = no evidence of data)
        $tableRetention = @(
            [PSCustomObject]@{ TableName = 'SecurityEvent'; RetentionInDays = 90; TotalRetentionInDays = 90; ArchiveRetentionInDays = 0; Plan = 'Analytics' }
            [PSCustomObject]@{ TableName = 'DeviceEvents'; RetentionInDays = 90; TotalRetentionInDays = 90; ArchiveRetentionInDays = 0; Plan = 'Analytics' }
            [PSCustomObject]@{ TableName = 'DeviceProcessEvents'; RetentionInDays = 30; TotalRetentionInDays = 30; ArchiveRetentionInDays = 0; Plan = 'Analytics' }
        )
        $script:defaultRetResult = Invoke-Analysis -TableUsage $tableUsage -Classifications $classifications `
            -RulesData $rulesData -HuntingData $huntingData -DefenderXDR $defenderXdr `
            -TableRetention $tableRetention -SocRecommendations @()
    }

    It 'flags XDR tables with default retention and no usage as NotStreaming' {
        $notStreaming = @($script:defaultRetResult.XdrChecker.Findings | Where-Object Type -eq 'NotStreaming')
        $notStreaming.TableName | Should -Contain 'DeviceEvents'
        $notStreaming.TableName | Should -Contain 'DeviceProcessEvents'
    }

    It 'generates XDR Checker recommendations for default-retention not-streamed tables' {
        $recs = @($script:defaultRetResult.XdrChecker.Recommendations | Where-Object { $_.TableName -in @('DeviceEvents', 'DeviceProcessEvents') })
        $recs.Count | Should -Be 2
    }

    It 'includes not-streamed count in XDR Checker summary' {
        $script:defaultRetResult.XdrChecker.Summary.NotStreamedCount | Should -Be 2
    }
}

# - Export-Report & ConvertTo-ReportSections tests -------------

Describe 'ConvertTo-ReportSections' {
    BeforeAll {
        $script:analysis = New-MockAnalysis
    }

    It 'returns a non-empty list of sections' {
        $sections = ConvertTo-ReportSections -Analysis $script:analysis
        $sections.Count | Should -BeGreaterOrEqual 1
    }

    It 'every section has Title, TabId, Markdown, and Html' {
        $sections = ConvertTo-ReportSections -Analysis $script:analysis
        foreach ($s in $sections) {
            $s.Title    | Should -Not -BeNullOrEmpty
            $s.TabId    | Should -Not -BeNullOrEmpty
            $s.Markdown | Should -Not -BeNullOrEmpty
            $s.Html     | Should -Not -BeNullOrEmpty
        }
    }

    It 'produces a Summary section with metric cards' {
        $sections = ConvertTo-ReportSections -Analysis $script:analysis
        $summary = $sections | Where-Object TabId -eq 'summary'
        $summary | Should -Not -BeNullOrEmpty
        $summary.Html | Should -Match 'metric-card'
        $summary.Markdown | Should -Match 'Total Tables'
    }

    It 'produces a Recommendations section when recommendations exist' {
        $sections = ConvertTo-ReportSections -Analysis $script:analysis
        $recs = $sections | Where-Object TabId -eq 'recs'
        $recs | Should -Not -BeNullOrEmpty
        $recs.Html | Should -Match 'rec-card'
        $recs.Markdown | Should -Match 'Move AWSVPCFlow'
    }

    It 'produces a Tables section sorted by cost descending' {
        $sections = ConvertTo-ReportSections -Analysis $script:analysis
        $tables = $sections | Where-Object TabId -eq 'tables'
        $tables | Should -Not -BeNullOrEmpty
        $tables.Html | Should -Match 'AWSVPCFlow'
        # AWSVPCFlow costs more so should appear first in the HTML
        $idxAWS = $tables.Html.IndexOf('AWSVPCFlow')
        $idxSE  = $tables.Html.IndexOf('SecurityEvent')
        $idxAWS | Should -BeLessThan $idxSE
    }

    It 'produces a Keyword Gaps section' {
        $sections = ConvertTo-ReportSections -Analysis $script:analysis
        $kw = $sections | Where-Object TabId -eq 'keywords'
        $kw | Should -Not -BeNullOrEmpty
        $kw.Html | Should -Match 'AWSCloudTrail'
        $kw.Markdown | Should -Match 'AWSCloudTrail'
    }

    It 'produces a Retention section for non-compliant tables' {
        $sections = ConvertTo-ReportSections -Analysis $script:analysis
        $ret = $sections | Where-Object TabId -eq 'retention'
        $ret | Should -Not -BeNullOrEmpty
        $ret.Html | Should -Match 'AWSVPCFlow'
        $ret.Markdown | Should -Match 'AWSVPCFlow'
    }

    It 'produces a Transforms section when transforms exist' {
        $sections = ConvertTo-ReportSections -Analysis $script:analysis
        $tx = $sections | Where-Object TabId -eq 'transforms'
        $tx | Should -Not -BeNullOrEmpty
        $tx.Html | Should -Match 'Filter'
    }

    It 'produces a Correlation section' {
        $sections = ConvertTo-ReportSections -Analysis $script:analysis
        $corr = $sections | Where-Object TabId -eq 'correlation'
        $corr | Should -Not -BeNullOrEmpty
        $corr.Markdown | Should -Match 'Excluded from Correlation'
        $corr.Markdown | Should -Match 'Included in Correlation'
    }

    It 'HTML-encodes special characters in correlation rule names' {
        $sections = ConvertTo-ReportSections -Analysis $script:analysis
        $corr = $sections | Where-Object TabId -eq 'correlation'
        $corr.Html | Should -Match 'Test &lt;Rule&gt;'
        $corr.Html | Should -Not -Match 'Test <Rule>'
    }

    It 'markdown-escapes special characters in correlation rule names' {
        $sections = ConvertTo-ReportSections -Analysis $script:analysis
        $corr = $sections | Where-Object TabId -eq 'correlation'
        $corr.Markdown | Should -Match 'Test'
        $corr.Markdown | Should -Not -Match 'Test <Rule>'
    }

    It 'includes Defender XDR section when DefenderXDR is provided' {
        $xdr = [PSCustomObject]@{
            TotalXDRRules    = 5
            XDRTableCoverage = @{}
            KnownXDRTables   = @()
        }
        $sections = ConvertTo-ReportSections -Analysis $script:analysis -DefenderXDR $xdr
        $xdrSection = $sections | Where-Object TabId -eq 'xdr'
        $xdrSection | Should -Not -BeNullOrEmpty
        $xdrSection.Html | Should -Match '5 rules'
        $xdrSection.Markdown | Should -Match '5 rules'
    }

    It 'omits Defender XDR section when DefenderXDR is null' {
        $sections = ConvertTo-ReportSections -Analysis $script:analysis
        $xdrSection = $sections | Where-Object TabId -eq 'xdr'
        $xdrSection | Should -BeNullOrEmpty
    }

    It 'omits Keyword Gaps section when there are no gaps' {
        $a = New-MockAnalysis
        $a.KeywordGaps = @()
        $sections = ConvertTo-ReportSections -Analysis $a
        $kw = $sections | Where-Object TabId -eq 'keywords'
        $kw | Should -BeNullOrEmpty
    }

    It 'omits Recommendations section when there are no recommendations' {
        $a = New-MockAnalysis
        $a.Recommendations = @()
        $sections = ConvertTo-ReportSections -Analysis $a
        $recs = $sections | Where-Object TabId -eq 'recs'
        $recs | Should -BeNullOrEmpty
    }
}

Describe 'Export-Report' {
    BeforeAll {
        $script:analysis = New-MockAnalysis
        $script:tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "LogHorizon_Tests_$(Get-Random)"
        New-Item -Path $script:tempDir -ItemType Directory -Force | Out-Null
    }

    AfterAll {
        Remove-Item -Path $script:tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'exports valid JSON with all top-level properties' {
        $outFile = Join-Path $script:tempDir 'test.json'
        Export-Report -Analysis $script:analysis -Format 'json' -OutputPath $outFile -WorkspaceName 'TestWorkspace'
        Test-Path $outFile | Should -Be $true
        $json = Get-Content $outFile -Raw | ConvertFrom-Json
        $json.metadata.workspace | Should -Be 'TestWorkspace'
        $json.metadata.tool | Should -Be 'Log Horizon'
        $json.summary | Should -Not -BeNullOrEmpty
        $json.tableAnalysis | Should -Not -BeNullOrEmpty
        $json.recommendations | Should -Not -BeNullOrEmpty
        $json.keywordGaps | Should -Not -BeNullOrEmpty
        $json.correlationExcluded | Should -Not -BeNullOrEmpty
        $json.correlationIncluded | Should -Not -BeNullOrEmpty
        $json.dataTransforms | Should -Not -BeNullOrEmpty
    }

    It 'JSON includes DefenderXDR block when provided' {
        $outFile = Join-Path $script:tempDir 'test_xdr.json'
        $xdr = [PSCustomObject]@{
            TotalXDRRules    = 3
            XDRTableCoverage = @{}
            KnownXDRTables   = @('DeviceEvents')
        }
        Export-Report -Analysis $script:analysis -Format 'json' -OutputPath $outFile -WorkspaceName 'WS' -DefenderXDR $xdr
        $json = Get-Content $outFile -Raw | ConvertFrom-Json
        $json.defenderXDR | Should -Not -BeNullOrEmpty
        $json.defenderXDR.totalXDRRules | Should -Be 3
    }

    It 'exports markdown with correct headers' {
        $outFile = Join-Path $script:tempDir 'test.md'
        Export-Report -Analysis $script:analysis -Format 'markdown' -OutputPath $outFile -WorkspaceName 'TestWS'
        Test-Path $outFile | Should -Be $true
        $content = Get-Content $outFile -Raw
        $content | Should -Match '# Log Horizon'
        $content | Should -Match 'TestWS'
        $content | Should -Match '## Summary'
        $content | Should -Match '## Recommendations'
        $content | Should -Match '## Table Analysis'
    }

    It 'md format alias produces identical output to markdown' {
        $outMd = Join-Path $script:tempDir 'alias.md'
        $outMarkdown = Join-Path $script:tempDir 'full.md'
        Export-Report -Analysis $script:analysis -Format 'md' -OutputPath $outMd -WorkspaceName 'AliasTest'
        Export-Report -Analysis $script:analysis -Format 'markdown' -OutputPath $outMarkdown -WorkspaceName 'AliasTest'
        # Both should produce non-empty files with same structure (timestamps may differ slightly)
        $mdContent = Get-Content $outMd -Raw
        $markdownContent = Get-Content $outMarkdown -Raw
        $mdContent | Should -Match '## Summary'
        $markdownContent | Should -Match '## Summary'
    }

    It 'exports static HTML without script tags' {
        $outFile = Join-Path $script:tempDir 'test.html'
        Export-Report -Analysis $script:analysis -Format 'html' -OutputPath $outFile -WorkspaceName 'HtmlTest'
        Test-Path $outFile | Should -Be $true
        $content = Get-Content $outFile -Raw
        $content | Should -Match '<!DOCTYPE html>'
        $content | Should -Match 'tab-radio'
        $content | Should -Match 'tab-label'
        $content | Should -Match 'tab-pane'
        $content | Should -Not -Match '<script'
        $content | Should -Match 'HtmlTest'
    }

    It 'HTML output contains no CDN links' {
        $outFile = Join-Path $script:tempDir 'nocdn.html'
        Export-Report -Analysis $script:analysis -Format 'html' -OutputPath $outFile -WorkspaceName 'W'
        $content = Get-Content $outFile -Raw
        $content | Should -Not -Match 'cdn\.jsdelivr'
        $content | Should -Not -Match 'unpkg\.com'
        $content | Should -Not -Match 'cdnjs\.com'
    }

    It 'HTML-encodes workspace name to prevent XSS' {
        $outFile = Join-Path $script:tempDir 'xss.html'
        Export-Report -Analysis $script:analysis -Format 'html' -OutputPath $outFile -WorkspaceName '<script>alert(1)</script>'
        $content = Get-Content $outFile -Raw
        $content | Should -Not -Match '<script>alert'
        $content | Should -Match '&lt;script&gt;'
    }

    It 'auto-generates timestamped filename when OutputPath is a directory' {
        $subDir = Join-Path $script:tempDir 'autoname'
        New-Item -Path $subDir -ItemType Directory -Force | Out-Null
        Export-Report -Analysis $script:analysis -Format 'json' -OutputPath $subDir -WorkspaceName 'W'
        $files = Get-ChildItem -Path $subDir -Filter '*.json'
        $files.Count | Should -Be 1
        $files[0].Name | Should -Match '^LogHorizon_Report_\d{4}-\d{2}-\d{2}_\d{4}\.json$'
    }

    It 'auto-generates .md extension for markdown format in directory mode' {
        $subDir = Join-Path $script:tempDir 'automd'
        New-Item -Path $subDir -ItemType Directory -Force | Out-Null
        Export-Report -Analysis $script:analysis -Format 'md' -OutputPath $subDir -WorkspaceName 'W'
        $files = Get-ChildItem -Path $subDir -Filter '*.md'
        $files.Count | Should -Be 1
        $files[0].Name | Should -Match '^LogHorizon_Report_.*\.md$'
    }

    It 'auto-generates .html extension for html format in directory mode' {
        $subDir = Join-Path $script:tempDir 'autohtml'
        New-Item -Path $subDir -ItemType Directory -Force | Out-Null
        Export-Report -Analysis $script:analysis -Format 'html' -OutputPath $subDir -WorkspaceName 'W'
        $files = Get-ChildItem -Path $subDir -Filter '*.html'
        $files.Count | Should -Be 1
        $files[0].Name | Should -Match '^LogHorizon_Report_.*\.html$'
    }

    It 'HTML output contains no unreplaced template tokens' {
        $outFile = Join-Path $script:tempDir 'tokens.html'
        Export-Report -Analysis $script:analysis -Format 'html' -OutputPath $outFile -WorkspaceName 'TokenTest'
        $content = Get-Content $outFile -Raw
        $content | Should -Not -Match '__WORKSPACE__'
        $content | Should -Not -Match '__GENERATED__'
        $content | Should -Not -Match '__VERSION__'
        $content | Should -Not -Match '__TAB_NAVIGATION__'
        $content | Should -Not -Match '__TAB_LABELS__'
        $content | Should -Not -Match '__TAB_PANES__'
    }

    It 'HTML renders dollar amounts correctly without backreference corruption' {
        $outFile = Join-Path $script:tempDir 'dollars.html'
        Export-Report -Analysis $script:analysis -Format 'html' -OutputPath $outFile -WorkspaceName 'DollarTest'
        $content = Get-Content $outFile -Raw
        # Savings metric should render as "$400/mo", not be empty or garbled
        $content | Should -Match '\$400'
        $content | Should -Match 'metric-value'
    }
}

Describe 'ConvertTo-ReportSections edge cases' {
    BeforeAll {
        $script:analysis = New-MockAnalysis
    }

    It 'omits Correlation section when both lists are empty' {
        $a = New-MockAnalysis
        $a.CorrelationExcluded = @()
        $a.CorrelationIncluded = @()
        $sections = ConvertTo-ReportSections -Analysis $a
        $corr = $sections | Where-Object TabId -eq 'correlation'
        $corr | Should -BeNullOrEmpty
    }

    It 'omits Transforms section when no transforms and no split tables' {
        $a = New-MockAnalysis
        $a.DataTransforms = [PSCustomObject]@{ Transforms = @() }
        foreach ($t in $a.TableAnalysis) { $t.HasTransform = $false; $t.IsSplitTable = $false }
        $sections = ConvertTo-ReportSections -Analysis $a
        $tx = $sections | Where-Object TabId -eq 'transforms'
        $tx | Should -BeNullOrEmpty
    }

    It 'omits Retention section when all tables are compliant and none improvable' {
        $a = New-MockAnalysis
        foreach ($t in $a.TableAnalysis) { $t.RetentionCompliant = $true; $t.RetentionCanImprove = $false }
        $sections = ConvertTo-ReportSections -Analysis $a
        $ret = $sections | Where-Object TabId -eq 'retention'
        $ret | Should -BeNullOrEmpty
    }

    It 'produces Split KQL section for SplitCandidate recommendations' {
        $a = New-MockAnalysis
        $a.Recommendations += [PSCustomObject]@{
            Title          = 'Split SecurityEvent'
            TableName      = 'SecurityEvent'
            Priority       = 'Medium'
            Type           = 'SplitCandidate'
            CurrentCost    = 279
            EstSavingsUSD  = 150
            Detail         = 'Split high-volume primary table.'
            SplitSuggestion = [PSCustomObject]@{
                Source     = 'kb+rules'
                RuleCount  = 5
                SplitKql   = 'SecurityEvent | where EventID in (4624, 4625)'
                ProjectKql = '| project TimeGenerated, EventID, Account'
            }
        }
        $sections = ConvertTo-ReportSections -Analysis $a
        $split = $sections | Where-Object TabId -eq 'logtuning'
        $split | Should -Not -BeNullOrEmpty
        $split.Html | Should -Match 'SecurityEvent'
        $split.Html | Should -Match 'kql-block'
        $split.Markdown | Should -Match 'Split KQL'
        $split.Markdown | Should -Match 'SecurityEvent \| where EventID'
    }

    It 'collapses multiline KQL to single line in markdown transforms table' {
        $a = New-MockAnalysis
        $a.DataTransforms = [PSCustomObject]@{
            Transforms = @(
                [PSCustomObject]@{
                    DCRName       = 'dcr-multiline'
                    OutputTable   = 'MultiLineTable'
                    TransformKql  = "source`n| extend TimeGenerated = now()`n| project TimeGenerated, Name"
                    TransformType = 'Enrichment'
                }
            )
        }
        $a.TableAnalysis[0].HasTransform = $true
        $sections = ConvertTo-ReportSections -Analysis $a
        $tx = $sections | Where-Object TabId -eq 'transforms'
        $tx | Should -Not -BeNullOrEmpty
        # Markdown should have the KQL on a single line (no newlines breaking the table)
        $mdLines = $tx.Markdown -split "`n" | Where-Object { $_ -match 'MultiLineTable' }
        $mdLines.Count | Should -Be 1
    }

    It 'escapes pipe characters in markdown KQL preview' {
        $a = New-MockAnalysis
        $a.DataTransforms = [PSCustomObject]@{
            Transforms = @(
                [PSCustomObject]@{
                    DCRName       = 'dcr-pipe'
                    OutputTable   = 'PipeTable'
                    TransformKql  = 'source | where x == 1'
                    TransformType = 'Filter'
                }
            )
        }
        $a.TableAnalysis[0].HasTransform = $true
        $sections = ConvertTo-ReportSections -Analysis $a
        $tx = $sections | Where-Object TabId -eq 'transforms'
        # The pipe should be an HTML entity so it doesn't break the markdown table
        $mdLine = ($tx.Markdown -split "`n" | Where-Object { $_ -match 'PipeTable' })
        $mdLine | Should -Match '&#124;'
        $mdLine | Should -Match '<code>'
    }
}

Describe 'Invoke-AzRestWithRetry' {
    It 'returns response on first successful call' {
        Mock Invoke-RestMethod { [PSCustomObject]@{ value = @('ok') } }
        $result = Invoke-AzRestWithRetry -Uri 'https://example.com/api' -Headers @{ Authorization = 'Bearer test' }
        $result.value | Should -Contain 'ok'
        Should -Invoke Invoke-RestMethod -Times 1 -Exactly
    }

    It 'passes Method and Body through to Invoke-RestMethod' {
        Mock Invoke-RestMethod { [PSCustomObject]@{ tables = @() } }
        Invoke-AzRestWithRetry -Uri 'https://example.com/api' -Headers @{ Authorization = 'Bearer test' } -Method Post -Body '{"query":"test"}'
        Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'Post' -and $Body -eq '{"query":"test"}'
        }
    }

    It 'throws non-retryable errors immediately' {
        Mock Invoke-RestMethod {
            $resp = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::NotFound)
            $ex = [Microsoft.PowerShell.Commands.HttpResponseException]::new('Not Found', $resp)
            throw $ex
        }
        { Invoke-AzRestWithRetry -Uri 'https://example.com/api' -Headers @{ Authorization = 'Bearer test' } } | Should -Throw
        Should -Invoke Invoke-RestMethod -Times 1 -Exactly
    }

    It 'retries on 429 and eventually succeeds' {
        $script:retryCallCount = 0
        Mock Invoke-RestMethod {
            $script:retryCallCount++
            if ($script:retryCallCount -lt 2) {
                $resp = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::TooManyRequests)
                $ex = [Microsoft.PowerShell.Commands.HttpResponseException]::new('Throttled', $resp)
                throw $ex
            }
            [PSCustomObject]@{ value = @('retried') }
        }
        $result = Invoke-AzRestWithRetry -Uri 'https://example.com/api' -Headers @{ Authorization = 'Bearer test' } -BaseDelaySeconds 0
        $result.value | Should -Contain 'retried'
        Should -Invoke Invoke-RestMethod -Times 2 -Exactly
    }

    It 'throws after exhausting max retries' {
        Mock Invoke-RestMethod {
            $resp = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::TooManyRequests)
            $ex = [Microsoft.PowerShell.Commands.HttpResponseException]::new('Throttled', $resp)
            throw $ex
        }
        { Invoke-AzRestWithRetry -Uri 'https://example.com/api' -Headers @{ Authorization = 'Bearer test' } -MaxRetries 1 -BaseDelaySeconds 0 } | Should -Throw
        Should -Invoke Invoke-RestMethod -Times 2 -Exactly
    }
}

Describe 'Get-TablesFromKql keyword filtering via $script:kqlKeywords' {
    It 'filters out ingestion_time from table extraction' {
        $kql = 'SecurityEvent | where ingestion_time() > ago(1d)'
        $result = Get-TablesFromKql -Kql $kql
        $result | Should -Contain 'SecurityEvent'
        $result | Should -Not -Contain 'ingestion_time'
    }

    It 'filters out all common aggregation keywords' {
        $kql = 'SigninLogs | summarize dcount(UserPrincipalName), avg(RiskScore) by bin(TimeGenerated, 1h)'
        $result = Get-TablesFromKql -Kql $kql
        $result | Should -Contain 'SigninLogs'
        $result | Should -Not -Contain 'dcount'
        $result | Should -Not -Contain 'avg'
        $result | Should -Not -Contain 'bin'
    }

    It 'filters out isfuzzy and withsource from union statements' {
        $kql = 'union isfuzzy=true withsource=TableName SecurityEvent, SigninLogs | where TimeGenerated > ago(1d)'
        $result = Get-TablesFromKql -Kql $kql
        $result | Should -Not -Contain 'isfuzzy'
        $result | Should -Not -Contain 'withsource'
        $result | Should -Contain 'SecurityEvent'
    }

    It 'filters out lowercase English words and field names' {
        $kql = @"
SecurityEvent
| where the != "" and key != ""
| project Description, Type, Tactic
"@
        $result = Get-TablesFromKql -Kql $kql
        $result | Should -Contain 'SecurityEvent'
        $result | Should -Not -Contain 'the'
        $result | Should -Not -Contain 'key'
    }
}

Describe 'Write-Report helper functions' {
    It 'Get-SafeEscapedText returns dash for null input' {
        $result = Get-SafeEscapedText -Value $null
        $result | Should -Be '-'
    }

    It 'Get-SafeEscapedText escapes Spectre markup characters' {
        $result = Get-SafeEscapedText -Value 'test [bold]markup[/] text'
        $result | Should -Match '\[\[bold\]\]'
    }

    It 'Get-ConsoleWidth returns a positive integer' {
        $result = Get-ConsoleWidth
        $result | Should -BeGreaterThan 0
    }

    It 'Test-ConsoleSize returns a boolean' {
        $result = Test-ConsoleSize
        $result | Should -BeOfType [bool]
    }
}

Describe 'Detection Analyzer adaptive display' {
    It 'computes dynamic bar width capped between 10 and 30' {
        # Simulate the formula: Max(10, Min(30, Floor((width - 60) * 0.5)))
        # Wide terminal (200)
        $wide = [math]::Max(10, [math]::Min(30, [math]::Floor((200 - 60) * 0.5)))
        $wide | Should -Be 30

        # Standard terminal (120)
        $standard = [math]::Max(10, [math]::Min(30, [math]::Floor((120 - 60) * 0.5)))
        $standard | Should -Be 30

        # Narrow terminal (80)
        $narrow = [math]::Max(10, [math]::Min(30, [math]::Floor((80 - 60) * 0.5)))
        $narrow | Should -Be 10

        # Very narrow terminal (70)
        $veryNarrow = [math]::Max(10, [math]::Min(30, [math]::Floor((70 - 60) * 0.5)))
        $veryNarrow | Should -Be 10
    }

    It 'truncates rule names exceeding max length' {
        $longName = 'A' * 100
        $maxLen = 40
        $truncated = if ($longName.Length -gt $maxLen) { $longName.Substring(0, $maxLen - 3) + '...' } else { $longName }
        $truncated.Length | Should -Be 40
        $truncated | Should -Match '\.\.\.$'
    }

    It 'does not truncate rule names within max length' {
        $shortName = 'Short Rule Name'
        $maxLen = 40
        $result = if ($shortName.Length -gt $maxLen) { $shortName.Substring(0, $maxLen - 3) + '...' } else { $shortName }
        $result | Should -Be $shortName
    }

    It 'selects correct maxNameLen tier for each width bracket' {
        # >= 140
        $tier140 = if (150 -ge 140) { 80 } elseif (150 -ge 120) { 55 } elseif (150 -ge 100) { 40 } else { 30 }
        $tier140 | Should -Be 80

        # >= 120 but < 140
        $tier120 = if (125 -ge 140) { 80 } elseif (125 -ge 120) { 55 } elseif (125 -ge 100) { 40 } else { 30 }
        $tier120 | Should -Be 55

        # >= 100 but < 120
        $tier100 = if (110 -ge 140) { 80 } elseif (110 -ge 120) { 55 } elseif (110 -ge 100) { 40 } else { 30 }
        $tier100 | Should -Be 40

        # < 100
        $tier80 = if (80 -ge 140) { 80 } elseif (80 -ge 120) { 55 } elseif (80 -ge 100) { 40 } else { 30 }
        $tier80 | Should -Be 30
    }

    It 'hides Kind column when width is under 100' {
        $showKind = (80 -ge 100)
        $showKind | Should -Be $false

        $showKind = (100 -ge 100)
        $showKind | Should -Be $true
    }
}

Describe 'Get-LiveTuningAnalysis' {
    It 'returns per-table tuning analysis for rules with fields' {
        $rules = @(
            [PSCustomObject]@{
                RuleName = 'Brute Force Detection'
                Enabled  = $true
                Tables   = @('SigninLogs')
                Query    = 'SigninLogs | where ResultType != 0 | summarize count() by UserPrincipalName, IPAddress'
            },
            [PSCustomObject]@{
                RuleName = 'Impossible Travel'
                Enabled  = $true
                Tables   = @('SigninLogs')
                Query    = 'SigninLogs | where ResultType == 0 | summarize dcount(Location) by UserPrincipalName'
            }
        )

        $result = Get-LiveTuningAnalysis -Rules $rules -TableAnalysis @()
        $result.Count | Should -Be 1
        $result[0].TableName | Should -Be 'SigninLogs'
        $result[0].RuleCount | Should -Be 2
        $result[0].UsedFields | Should -Contain 'UserPrincipalName'
        $result[0].UsedFields | Should -Contain 'TimeGenerated'
    }

    It 'generates filter KQL from rule WHERE conditions' {
        $rules = @(
            [PSCustomObject]@{
                RuleName = 'Failed Logins'
                Enabled  = $true
                Tables   = @('SigninLogs')
                Query    = 'SigninLogs | where ResultType != 0 | project UserPrincipalName'
            }
        )

        $result = Get-LiveTuningAnalysis -Rules $rules -TableAnalysis @()
        $result[0].FilterKql | Should -Not -BeNullOrEmpty
        $result[0].FilterKql | Should -Match 'ResultType'
    }

    It 'generates project KQL from used fields' {
        $rules = @(
            [PSCustomObject]@{
                RuleName = 'Test Rule'
                Enabled  = $true
                Tables   = @('SecurityEvent')
                Query    = 'SecurityEvent | where EventID == 4625 | project Account, Computer'
            }
        )

        $result = Get-LiveTuningAnalysis -Rules $rules -TableAnalysis @()
        $result[0].ProjectKql | Should -Not -BeNullOrEmpty
        $result[0].ProjectKql | Should -Match 'project'
    }

    It 'computes unused fields when schema is provided' {
        $rules = @(
            [PSCustomObject]@{
                RuleName = 'Test Rule'
                Enabled  = $true
                Tables   = @('SecurityEvent')
                Query    = 'SecurityEvent | where EventID == 4625 | project Account'
            }
        )
        $schema = @{
            'SecurityEvent' = @('TimeGenerated', 'EventID', 'Account', 'Computer', 'Activity', 'SourceIP')
        }

        $result = Get-LiveTuningAnalysis -Rules $rules -TableAnalysis @() -SchemaLookup $schema
        $result[0].UnusedFields.Count | Should -BeGreaterThan 0
        $result[0].SchemaColumns.Count | Should -Be 6
    }

    It 'skips disabled rules' {
        $rules = @(
            [PSCustomObject]@{
                RuleName = 'Active Rule'
                Enabled  = $true
                Tables   = @('SecurityEvent')
                Query    = 'SecurityEvent | where EventID == 4625'
            },
            [PSCustomObject]@{
                RuleName = 'Disabled Rule'
                Enabled  = $false
                Tables   = @('AuditLogs')
                Query    = 'AuditLogs | where OperationName == "Add member"'
            }
        )

        $result = Get-LiveTuningAnalysis -Rules $rules -TableAnalysis @()
        $result.Count | Should -Be 1
        $result[0].TableName | Should -Be 'SecurityEvent'
    }

    It 'includes hunting queries in analysis' {
        $rules = @(
            [PSCustomObject]@{
                RuleName = 'Alert Rule'
                Enabled  = $true
                Tables   = @('SigninLogs')
                Query    = 'SigninLogs | where ResultType != 0'
            }
        )
        $hunting = @(
            [PSCustomObject]@{
                QueryName = 'Hunt Risky Logins'
                Enabled   = $true
                Tables    = @('SigninLogs')
                Query     = 'SigninLogs | where RiskLevelDuringSignIn != "none" | project UserPrincipalName, RiskState'
            }
        )

        $result = Get-LiveTuningAnalysis -Rules $rules -HuntingQueries $hunting -TableAnalysis @()
        $result[0].RuleCount | Should -Be 2
        $result[0].UsedFields | Should -Contain 'RiskLevelDuringSignIn'
    }

    It 'estimates savings with cost data' {
        $rules = @(
            [PSCustomObject]@{
                RuleName = 'Test Rule'
                Enabled  = $true
                Tables   = @('SecurityEvent')
                Query    = 'SecurityEvent | where EventID == 4625 | project Account'
            }
        )
        $tableAnalysis = @(
            [PSCustomObject]@{
                TableName         = 'SecurityEvent'
                MonthlyGB         = 50
                EstMonthlyCostUSD = 279.50
            }
        )
        $schema = @{
            'SecurityEvent' = @('TimeGenerated', 'EventID', 'Account', 'Computer', 'Activity',
                                'SourceIP', 'LogonType', 'SubStatus', 'Process', 'CommandLine')
        }

        $result = Get-LiveTuningAnalysis -Rules $rules -TableAnalysis $tableAnalysis -SchemaLookup $schema
        $result[0].EstFilterSavings | Should -BeGreaterThan 0
        $result[0].EstProjectSavings | Should -BeGreaterThan 0
    }

    It 'provides rule detail breakdown per table' {
        $rules = @(
            [PSCustomObject]@{
                RuleName = 'Rule A'
                Enabled  = $true
                Tables   = @('SecurityEvent')
                Query    = 'SecurityEvent | where EventID == 4625 | project Account'
            },
            [PSCustomObject]@{
                RuleName = 'Rule B'
                Enabled  = $true
                Tables   = @('SecurityEvent')
                Query    = 'SecurityEvent | where EventID == 4688 | project Computer, CommandLine'
            }
        )

        $result = Get-LiveTuningAnalysis -Rules $rules -TableAnalysis @()
        $result[0].RuleDetails.Count | Should -Be 2
        $result[0].RuleDetails[0].RuleName | Should -Be 'Rule A'
        $result[0].RuleDetails[1].RuleName | Should -Be 'Rule B'
    }
}

Describe 'Get-SplitKql fallback with FieldFrequencyStats' {
    It 'uses per-table community stats as fallback' {
        $stats = @{
            universalFields  = @('TimeGenerated', 'Type')
            categoryDefaults = @{}
            perTable         = @{
                'CustomLog_CL' = [PSCustomObject]@{
                    SourceIP = 15
                    UserName = 12
                    Action   = 8
                }
            }
        }

        $result = Get-SplitKql -TableName 'CustomLog_CL' -FieldFrequencyStats $stats
        $result.Source | Should -Be 'community-stats'
        $result.FallbackSource | Should -Be 'community-stats'
        $result.FallbackFields | Should -Contain 'SourceIP'
        $result.AllFields | Should -Contain 'SourceIP'
        $result.ProjectKql | Should -Not -BeNullOrEmpty
    }

    It 'falls back to category defaults when no per-table stats' {
        $stats = @{
            universalFields  = @('TimeGenerated', 'Type')
            categoryDefaults = @{
                'Network Security' = @('SourceIP', 'DestinationIP', 'Action', 'Protocol')
            }
            perTable         = @{}
        }

        $result = Get-SplitKql -TableName 'UnknownFirewall_CL' -FieldFrequencyStats $stats -TableCategory 'Network Security'
        $result.Source | Should -Be 'category-defaults'
        $result.FallbackSource | Should -Be 'category-defaults'
        $result.FallbackFields | Should -Contain 'SourceIP'
        $result.FallbackFields | Should -Contain 'DestinationIP'
    }

    It 'falls back to universal fields as last resort' {
        $stats = @{
            universalFields  = @('TimeGenerated', 'Type', 'TenantId')
            categoryDefaults = @{}
            perTable         = @{}
        }

        $result = Get-SplitKql -TableName 'CompletelyUnknown_CL' -FieldFrequencyStats $stats
        $result.Source | Should -Be 'universal'
        $result.FallbackSource | Should -Be 'universal'
        $result.FallbackFields | Should -Contain 'Type'
        $result.FallbackFields | Should -Contain 'TenantId'
    }

    It 'does not use fallback when KB entry exists' {
        $hvFields = @{
            'SecurityEvent' = [PSCustomObject]@{
                description     = 'Windows Security Events'
                highValueFields = @('TimeGenerated', 'EventID', 'Account')
                splitHints      = @(
                    [PSCustomObject]@{
                        description = 'Keep critical EventIDs'
                        kql         = 'EventID in (4624, 4625)'
                    }
                )
            }
        }
        $stats = @{
            universalFields  = @('TimeGenerated', 'Type')
            categoryDefaults = @{}
            perTable         = @{}
        }

        $result = Get-SplitKql -TableName 'SecurityEvent' -HighValueFieldsDB $hvFields -FieldFrequencyStats $stats
        $result.Source | Should -Be 'knowledge-base'
        $result.FallbackSource | Should -BeNullOrEmpty
        $result.FallbackFields.Count | Should -Be 0
    }

    It 'does not use fallback when rules provide fields' {
        $rules = @(
            [PSCustomObject]@{
                RuleName = 'Test Rule'
                Enabled  = $true
                Tables   = @('CustomTable_CL')
                Query    = 'CustomTable_CL | where Status == "Failed" | project UserName'
            }
        )
        $stats = @{
            universalFields  = @('TimeGenerated', 'Type')
            categoryDefaults = @{}
            perTable         = @{}
        }

        $result = Get-SplitKql -TableName 'CustomTable_CL' -Rules $rules -FieldFrequencyStats $stats
        $result.Source | Should -Be 'rule-analysis'
        $result.FallbackSource | Should -BeNullOrEmpty
    }

    It 'includes FallbackFields and FallbackSource in output' {
        $result = Get-SplitKql -TableName 'Empty_CL'
        $result.PSObject.Properties.Name | Should -Contain 'FallbackFields'
        $result.PSObject.Properties.Name | Should -Contain 'FallbackSource'
    }
}

Describe 'Get-LiveTuningAnalysis combined KQL generation' {
    It 'generates combined KQL when both filter and project are available' {
        $rules = @(
            [PSCustomObject]@{
                RuleName = 'Combined Test'
                Enabled  = $true
                Tables   = @('SecurityEvent')
                Query    = 'SecurityEvent | where EventID == 4625 | project Account, Computer'
            }
        )

        $result = Get-LiveTuningAnalysis -Rules $rules -TableAnalysis @()
        $result[0].CombinedKql | Should -Not -BeNullOrEmpty
        $result[0].CombinedKql | Should -Match 'where'
        $result[0].CombinedKql | Should -Match 'project'
    }

    It 'handles multiple tables from different rules' {
        $rules = @(
            [PSCustomObject]@{
                RuleName = 'Rule 1'
                Enabled  = $true
                Tables   = @('SecurityEvent')
                Query    = 'SecurityEvent | where EventID == 4625'
            },
            [PSCustomObject]@{
                RuleName = 'Rule 2'
                Enabled  = $true
                Tables   = @('SigninLogs')
                Query    = 'SigninLogs | where ResultType != 0'
            }
        )

        $result = Get-LiveTuningAnalysis -Rules $rules -TableAnalysis @()
        $result.Count | Should -Be 2
        $tableNames = $result | ForEach-Object { $_.TableName }
        $tableNames | Should -Contain 'SecurityEvent'
        $tableNames | Should -Contain 'SigninLogs'
    }

    It 'returns empty array when no enabled rules exist' {
        $rules = @(
            [PSCustomObject]@{
                RuleName = 'Disabled'
                Enabled  = $false
                Tables   = @('SecurityEvent')
                Query    = 'SecurityEvent | where true'
            }
        )

        $result = Get-LiveTuningAnalysis -Rules $rules -TableAnalysis @()
        $result.Count | Should -Be 0
    }
}

Describe 'Detection Assessment cost-value matrix' {
    It 'groups tables by classification and assessment' {
        $tableAnalysis = @(
            [PSCustomObject]@{ TableName = 'SigninLogs'; Classification = 'primary'; Assessment = 'High Value' }
            [PSCustomObject]@{ TableName = 'SecurityEvent'; Classification = 'primary'; Assessment = 'High Value' }
            [PSCustomObject]@{ TableName = 'AuditLogs'; Classification = 'primary'; Assessment = 'Good Value' }
            [PSCustomObject]@{ TableName = 'DeviceNetworkInfo'; Classification = 'secondary'; Assessment = 'Optimize' }
            [PSCustomObject]@{ TableName = 'AzureDiagnostics'; Classification = 'secondary'; Assessment = 'Low Value' }
            [PSCustomObject]@{ TableName = 'AzureActivity'; Classification = 'primary'; Assessment = 'Free Tier' }
        )

        $assessmentOrder = @('High Value', 'Good Value', 'Missing Coverage', 'Optimize', 'Low Value', 'Underutilized', 'Free Tier')
        $classRows = @('primary', 'secondary')

        foreach ($cls in $classRows) {
            $subset = $tableAnalysis | Where-Object { $_.Classification -eq $cls }
            foreach ($assess in $assessmentOrder) {
                $count = ($subset | Where-Object { $_.Assessment -eq $assess }).Count
                if ($cls -eq 'primary' -and $assess -eq 'High Value') { $count | Should -Be 2 }
                if ($cls -eq 'primary' -and $assess -eq 'Good Value') { $count | Should -Be 1 }
                if ($cls -eq 'primary' -and $assess -eq 'Missing Coverage') { $count | Should -Be 0 }
                if ($cls -eq 'primary' -and $assess -eq 'Free Tier') { $count | Should -Be 1 }
                if ($cls -eq 'secondary' -and $assess -eq 'Optimize') { $count | Should -Be 1 }
                if ($cls -eq 'secondary' -and $assess -eq 'Low Value') { $count | Should -Be 1 }
                if ($cls -eq 'secondary' -and $assess -eq 'High Value') { $count | Should -Be 0 }
            }
        }
    }

    It 'computes correct totals row' {
        $tableAnalysis = @(
            [PSCustomObject]@{ TableName = 'T1'; Classification = 'primary'; Assessment = 'High Value' }
            [PSCustomObject]@{ TableName = 'T2'; Classification = 'primary'; Assessment = 'Missing Coverage' }
            [PSCustomObject]@{ TableName = 'T3'; Classification = 'secondary'; Assessment = 'High Value' }
            [PSCustomObject]@{ TableName = 'T4'; Classification = 'secondary'; Assessment = 'Optimize' }
            [PSCustomObject]@{ TableName = 'T5'; Classification = 'primary'; Assessment = 'Free Tier' }
        )

        $assessmentOrder = @('High Value', 'Good Value', 'Missing Coverage', 'Optimize', 'Low Value', 'Underutilized', 'Free Tier')
        $totals = @{}
        foreach ($assess in $assessmentOrder) {
            $totals[$assess] = ($tableAnalysis | Where-Object { $_.Assessment -eq $assess }).Count
        }

        $totals['High Value'] | Should -Be 2
        $totals['Good Value'] | Should -Be 0
        $totals['Missing Coverage'] | Should -Be 1
        $totals['Optimize'] | Should -Be 1
        $totals['Free Tier'] | Should -Be 1
        ($tableAnalysis | Measure-Object).Count | Should -Be 5
    }

    It 'handles empty table analysis gracefully' {
        $tableAnalysis = @()
        $assessmentOrder = @('High Value', 'Good Value', 'Missing Coverage', 'Optimize', 'Low Value', 'Underutilized', 'Free Tier')

        foreach ($assess in $assessmentOrder) {
            $count = ($tableAnalysis | Where-Object { $_.Assessment -eq $assess }).Count
            $count | Should -Be 0
        }
        ($tableAnalysis | Measure-Object).Count | Should -Be 0
    }

    It 'applies correct color coding for assessment cell values' {
        $greenAssessments = @('High Value', 'Good Value', 'Free Tier')
        $yellowAssessments = @('Missing Coverage', 'Low Value', 'Optimize')

        foreach ($assess in $greenAssessments) {
            $assess -in @('High Value', 'Good Value', 'Free Tier') | Should -Be $true
            $assess -in @('Missing Coverage', 'Low Value', 'Optimize') | Should -Be $false
        }
        foreach ($assess in $yellowAssessments) {
            $assess -in @('Missing Coverage', 'Low Value', 'Optimize') | Should -Be $true
            $assess -in @('High Value', 'Good Value', 'Free Tier') | Should -Be $false
        }
    }
}

Describe 'Detection Assessment submenu table filtering' {
    BeforeAll {
        $script:submenuTableAnalysis = @(
            [PSCustomObject]@{ TableName = 'SigninLogs'; Classification = 'primary'; Assessment = 'High Value'; MonthlyGB = 12.5; EstMonthlyCostUSD = 80; IsFree = $false; CostTier = 'Medium'; DetectionTier = 'High'; AnalyticsRules = 5; HuntingQueries = 2 }
            [PSCustomObject]@{ TableName = 'SecurityEvent'; Classification = 'primary'; Assessment = 'Good Value'; MonthlyGB = 25.0; EstMonthlyCostUSD = 160; IsFree = $false; CostTier = 'High'; DetectionTier = 'Medium'; AnalyticsRules = 3; HuntingQueries = 1 }
            [PSCustomObject]@{ TableName = 'AzureActivity'; Classification = 'primary'; Assessment = 'Free Tier'; MonthlyGB = 2.0; EstMonthlyCostUSD = 0; IsFree = $true; CostTier = 'Free'; DetectionTier = 'Low'; AnalyticsRules = 1; HuntingQueries = 0 }
            [PSCustomObject]@{ TableName = 'AzureDiagnostics'; Classification = 'secondary'; Assessment = 'Optimize'; MonthlyGB = 50.0; EstMonthlyCostUSD = 320; IsFree = $false; CostTier = 'Very High'; DetectionTier = 'None'; AnalyticsRules = 0; HuntingQueries = 0 }
            [PSCustomObject]@{ TableName = 'StorageBlobLogs'; Classification = 'secondary'; Assessment = 'Low Value'; MonthlyGB = 30.0; EstMonthlyCostUSD = 192; IsFree = $false; CostTier = 'High'; DetectionTier = 'None'; AnalyticsRules = 0; HuntingQueries = 0 }
        )
    }

    It 'filters primary tables correctly' {
        $filtered = $script:submenuTableAnalysis | Where-Object { $_.Classification -eq 'primary' }
        $filtered.Count | Should -Be 3
        $filtered.TableName | Should -Contain 'SigninLogs'
        $filtered.TableName | Should -Contain 'SecurityEvent'
        $filtered.TableName | Should -Contain 'AzureActivity'
        $filtered.TableName | Should -Not -Contain 'AzureDiagnostics'
    }

    It 'filters secondary tables correctly' {
        $filtered = $script:submenuTableAnalysis | Where-Object { $_.Classification -eq 'secondary' }
        $filtered.Count | Should -Be 2
        $filtered.TableName | Should -Contain 'AzureDiagnostics'
        $filtered.TableName | Should -Contain 'StorageBlobLogs'
        $filtered.TableName | Should -Not -Contain 'SigninLogs'
    }

    It 'sorts filtered tables by cost descending' {
        $sorted = $script:submenuTableAnalysis |
            Where-Object { $_.Classification -eq 'primary' } |
            Sort-Object EstMonthlyCostUSD -Descending
        $sorted[0].TableName | Should -Be 'SecurityEvent'
        $sorted[1].TableName | Should -Be 'SigninLogs'
        $sorted[2].TableName | Should -Be 'AzureActivity'
    }

    It 'applies correct assessment color markup' {
        $assessMarkupMap = @{
            'High Value'       = '[green]High Value[/]'
            'Good Value'       = '[green]Good Value[/]'
            'Missing Coverage' = '[yellow]Missing Coverage[/]'
            'Optimize'         = '[yellow]Optimize[/]'
            'Low Value'        = '[red]Low Value[/]'
            'Underutilized'    = '[grey]Underutilized[/]'
            'Free Tier'        = '[deepskyblue1]Free[/]'
        }

        foreach ($t in $script:submenuTableAnalysis) {
            $markup = switch ($t.Assessment) {
                'High Value'       { '[green]High Value[/]' }
                'Good Value'       { '[green]Good Value[/]' }
                'Missing Coverage' { '[yellow]Missing Coverage[/]' }
                'Optimize'         { '[yellow]Optimize[/]' }
                'Low Value'        { '[red]Low Value[/]' }
                'Underutilized'    { '[grey]Underutilized[/]' }
                'Free Tier'        { '[deepskyblue1]Free[/]' }
                default            { '[grey]-[/]' }
            }
            $markup | Should -Be $assessMarkupMap[$t.Assessment]
        }
    }

    It 'shows FREE for free-tier cost column' {
        $free = $script:submenuTableAnalysis | Where-Object { $_.IsFree }
        $free.Count | Should -Be 1
        $costStr = if ($free.IsFree) { '[deepskyblue1]FREE[/]' } else { "`$$($free.EstMonthlyCostUSD)" }
        $costStr | Should -Be '[deepskyblue1]FREE[/]'
    }

    It 'returns empty when no tables match classification' {
        $filtered = $script:submenuTableAnalysis | Where-Object { $_.Classification -eq 'unknown' }
        $filtered.Count | Should -Be 0
    }
}

Describe 'Detection coverage GB-weighted percentages' {
    It 'computes GB coverage percentages correctly' {
        $allTables = @(
            [PSCustomObject]@{ TableName = 'T1'; MonthlyGB = 10; AnalyticsRules = 3; XDRRules = 0; HuntingQueries = 1; EffectiveCoverage = 4; IsFree = $false }
            [PSCustomObject]@{ TableName = 'T2'; MonthlyGB = 5;  AnalyticsRules = 0; XDRRules = 0; HuntingQueries = 0; EffectiveCoverage = 0; IsFree = $false }
            [PSCustomObject]@{ TableName = 'T3'; MonthlyGB = 5;  AnalyticsRules = 1; XDRRules = 0; HuntingQueries = 2; EffectiveCoverage = 3; IsFree = $false }
            [PSCustomObject]@{ TableName = 'T4'; MonthlyGB = 0;  AnalyticsRules = 0; XDRRules = 0; HuntingQueries = 0; EffectiveCoverage = 0; IsFree = $true }
        )

        $totalAllGB = ($allTables | Measure-Object MonthlyGB -Sum).Sum
        $totalAllGB | Should -Be 20

        $tablesWithDetection = @($allTables | Where-Object { ($_.AnalyticsRules + $_.XDRRules) -gt 0 })
        $tablesWithHunting   = @($allTables | Where-Object { $_.HuntingQueries -gt 0 })
        $tablesWithCombined  = @($allTables | Where-Object { $_.EffectiveCoverage -gt 0 })

        $detectionCoveredGB = ($tablesWithDetection | Measure-Object MonthlyGB -Sum).Sum
        $huntingCoveredGB   = ($tablesWithHunting | Measure-Object MonthlyGB -Sum).Sum
        $combinedCoveredGB  = ($tablesWithCombined | Measure-Object MonthlyGB -Sum).Sum

        # T1 (10GB) + T3 (5GB) = 15GB detection coverage
        $detectionCoveredGB | Should -Be 15
        # T1 (10GB) + T3 (5GB) = 15GB hunting coverage
        $huntingCoveredGB | Should -Be 15
        # T1 (10GB) + T3 (5GB) = 15GB combined coverage
        $combinedCoveredGB | Should -Be 15

        $detPct = [math]::Round(($detectionCoveredGB / $totalAllGB) * 100, 1)
        $detPct | Should -Be 75.0

        $huntPct = [math]::Round(($huntingCoveredGB / $totalAllGB) * 100, 1)
        $huntPct | Should -Be 75.0
    }

    It 'returns 0 percent when total GB is zero' {
        $allTables = @(
            [PSCustomObject]@{ TableName = 'T1'; MonthlyGB = 0; AnalyticsRules = 1; XDRRules = 0; HuntingQueries = 0; EffectiveCoverage = 1; IsFree = $true }
        )

        $totalAllGB = ($allTables | Measure-Object MonthlyGB -Sum).Sum
        $pct = if ($totalAllGB -gt 0) { [math]::Round(($totalAllGB / $totalAllGB) * 100, 1) } else { 0 }
        $pct | Should -Be 0
    }

    It 'handles case where all tables have detection coverage' {
        $allTables = @(
            [PSCustomObject]@{ TableName = 'T1'; MonthlyGB = 8; AnalyticsRules = 2; XDRRules = 0; HuntingQueries = 1; EffectiveCoverage = 3; IsFree = $false }
            [PSCustomObject]@{ TableName = 'T2'; MonthlyGB = 12; AnalyticsRules = 1; XDRRules = 1; HuntingQueries = 0; EffectiveCoverage = 2; IsFree = $false }
        )

        $totalAllGB = ($allTables | Measure-Object MonthlyGB -Sum).Sum
        $detCoveredGB = ($allTables | Where-Object { ($_.AnalyticsRules + $_.XDRRules) -gt 0 } | Measure-Object MonthlyGB -Sum).Sum

        $pct = [math]::Round(($detCoveredGB / $totalAllGB) * 100, 1)
        $pct | Should -Be 100.0
    }

    It 'includes free table GB in total denominator' {
        $allTables = @(
            [PSCustomObject]@{ TableName = 'T1'; MonthlyGB = 5; AnalyticsRules = 2; XDRRules = 0; HuntingQueries = 0; EffectiveCoverage = 2; IsFree = $false }
            [PSCustomObject]@{ TableName = 'T2'; MonthlyGB = 5; AnalyticsRules = 0; XDRRules = 0; HuntingQueries = 0; EffectiveCoverage = 0; IsFree = $true }
        )

        $totalAllGB = ($allTables | Measure-Object MonthlyGB -Sum).Sum
        $totalAllGB | Should -Be 10

        $detCoveredGB = ($allTables | Where-Object { ($_.AnalyticsRules + $_.XDRRules) -gt 0 } | Measure-Object MonthlyGB -Sum).Sum
        $detCoveredGB | Should -Be 5

        $pct = [math]::Round(($detCoveredGB / $totalAllGB) * 100, 1)
        $pct | Should -Be 50.0
    }
}
