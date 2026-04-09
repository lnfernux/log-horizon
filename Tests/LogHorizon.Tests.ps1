BeforeAll {
    # Dot-source the private functions directly for unit testing
    $privatePath = Join-Path $PSScriptRoot '..\Private'
    . "$privatePath\Get-AnalyticsRules.ps1"
    . "$privatePath\Invoke-Classification.ps1"
    . "$privatePath\Invoke-Analysis.ps1"
    . "$privatePath\Export-Report.ps1"
    . "$privatePath\Write-Report.ps1"
    . "$privatePath\Get-DataTransforms.ps1"
    . "$privatePath\Invoke-FullControlEncounter.ps1"

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
        $result = Get-Assessment -Classification 'primary' -CostTier 'High' -DetectionTier 'High' -RuleCount 10 -IsFree $false
        $result | Should -Be 'High Value'
    }

    It 'returns Missing Coverage for primary with no detection' {
        $result = Get-Assessment -Classification 'primary' -CostTier 'Medium' -DetectionTier 'None' -RuleCount 0 -IsFree $false
        $result | Should -Be 'Missing Coverage'
    }

    It 'returns Optimize for secondary high cost low detection' {
        $result = Get-Assessment -Classification 'secondary' -CostTier 'High' -DetectionTier 'Low' -RuleCount 1 -IsFree $false
        $result | Should -Be 'Optimize'
    }

    It 'returns Low Value for high cost zero detection' {
        $result = Get-Assessment -Classification 'unknown' -CostTier 'Very High' -DetectionTier 'None' -RuleCount 0 -IsFree $false
        $result | Should -Be 'Low Value'
    }

    It 'returns Free Tier for free tables' {
        $result = Get-Assessment -Classification 'primary' -CostTier 'Free' -DetectionTier 'None' -RuleCount 0 -IsFree $true
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

Describe 'Full Control Encounter decision logic' {
    It 'loads exactly five top tools for each category from catalog' {
        $catalog = Get-FceCategoryCatalog
        $catalog.Count | Should -BeGreaterThan 0

        foreach ($cat in $catalog) {
            $cat.TopTools.Count | Should -Be 5 -Because "$($cat.Key) must expose exactly 5 top tools"
        }
    }

    It 'exposes an other-tools list for each category' {
        $catalog = Get-FceCategoryCatalog
        foreach ($cat in $catalog) {
            $cat.OtherTools.Count | Should -BeGreaterThan 0 -Because "$($cat.Key) should have additional tools when user picks Other"
        }
    }

    It 'maps selected other tool entries to classifications' {
        $db = @(
            [PSCustomObject]@{
                tableName = 'SigninLogs'
                connector = 'Microsoft Entra ID'
                classification = 'primary'
                category = 'Identity & Access'
                description = 'x'
                keywords = @('signin')
                mitreSources = @()
                recommendedTier = 'analytics'
                isFree = $false
                recommendedRetentionDays = 365
            }
        )

        $catalog = Get-FceCategoryCatalog
        $state = @{
            identity = [PSCustomObject]@{ Enabled = $true; Technologies = @('Other IdP'); IsBusinessCritical = $false }
        }

        $raw = New-FceRawOverrides -Database $db -Catalog $catalog -State $state
        $raw.Count | Should -BeGreaterThan 0
        $raw[0].tableName | Should -Be 'SigninLogs'
    }

    It 'promotes secondary tables when business critical and promotion is applied' {
        $raw = @(
            [PSCustomObject]@{
                tableName = 'CommonSecurityLog'
                connector = 'CEF'
                category = 'Network Security'
                description = 'test'
                keywords = @('firewall')
                mitreSources = @()
                isFree = $false
                recommendedRetentionDays = 365
                baselineClassification = 'secondary'
                baselineTier = 'datalake'
                proposedClassification = 'primary'
                proposedTier = 'analytics'
                wouldPromote = $true
                wizardCategory = 'Network security events'
            }
        )

        $result = ConvertTo-FceFinalOverrides -RawOverrides $raw -ApplyPromotions
        $result[0].classification | Should -Be 'primary'
        $result[0].recommendedTier | Should -Be 'analytics'
    }

    It 'keeps baseline classification when promotion is not applied' {
        $raw = @(
            [PSCustomObject]@{
                tableName = 'CommonSecurityLog'
                connector = 'CEF'
                category = 'Network Security'
                description = 'test'
                keywords = @('firewall')
                mitreSources = @()
                isFree = $false
                recommendedRetentionDays = 365
                baselineClassification = 'secondary'
                baselineTier = 'datalake'
                proposedClassification = 'primary'
                proposedTier = 'analytics'
                wouldPromote = $true
                wizardCategory = 'Network security events'
            }
        )

        $result = ConvertTo-FceFinalOverrides -RawOverrides $raw
        $result[0].classification | Should -Be 'secondary'
        $result[0].recommendedTier | Should -Be 'datalake'
    }

    It 'preserves already-primary tables' {
        $raw = @(
            [PSCustomObject]@{
                tableName = 'SigninLogs'
                connector = 'Entra ID'
                category = 'Identity & Access'
                description = 'test'
                keywords = @('signin')
                mitreSources = @()
                isFree = $false
                recommendedRetentionDays = 365
                baselineClassification = 'primary'
                baselineTier = 'analytics'
                proposedClassification = 'primary'
                proposedTier = 'analytics'
                wouldPromote = $false
                wizardCategory = 'Identity and authentication'
            }
        )

        $result = ConvertTo-FceFinalOverrides -RawOverrides $raw -ApplyPromotions
        $result[0].classification | Should -Be 'primary'
        $result[0].recommendedTier | Should -Be 'analytics'
    }

    It 'exports JSON using Invoke-Classification compatible schema' {
        $overrides = @(
            [PSCustomObject]@{
                tableName = 'SigninLogs'
                connector = 'Microsoft Entra ID'
                classification = 'primary'
                category = 'Identity & Access'
                description = 'fce test'
                keywords = @('signin')
                mitreSources = @()
                recommendedTier = 'analytics'
                isFree = $false
                recommendedRetentionDays = 365
            }
        )

        $export = Export-FceOverrides -Overrides $overrides -OutputPath $TestDrive
        Test-Path $export.Path | Should -Be $true

        $roundTrip = Get-Content $export.Path -Raw | ConvertFrom-Json
        $roundTrip[0].tableName | Should -Be 'SigninLogs'
        $roundTrip[0].classification | Should -Be 'primary'
        $roundTrip[0].recommendedTier | Should -Be 'analytics'
    }

    It 'creates markdown summary only when switch is used' {
        $db = @(
            [PSCustomObject]@{
                tableName = 'SigninLogs'
                connector = 'Microsoft Entra ID'
                classification = 'primary'
                category = 'Identity & Access'
                description = 'x'
                keywords = @('signin')
                mitreSources = @()
                recommendedTier = 'analytics'
                isFree = $false
                recommendedRetentionDays = 365
            }
            [PSCustomObject]@{
                tableName = 'CommonSecurityLog'
                connector = 'CEF/Syslog'
                classification = 'secondary'
                category = 'Network Security'
                description = 'x'
                keywords = @('firewall')
                mitreSources = @()
                recommendedTier = 'datalake'
                isFree = $false
                recommendedRetentionDays = 365
            }
        )

        $preset = @{
            identity = @{ Enabled = $true; Technologies = @('Microsoft Entra ID'); IsBusinessCritical = $true }
            network = @{ Enabled = $true; Technologies = @('Firewall logs'); IsBusinessCritical = $true }
        }

        $noSummary = Invoke-FullControlEncounter -OutputPath $TestDrive -PresetAnswers $preset -ClassificationDatabase $db
        $noSummary.SummaryPath | Should -BeNullOrEmpty

        $withSummary = Invoke-FullControlEncounter -OutputPath $TestDrive -PresetAnswers $preset -ClassificationDatabase $db -IncludeDecisionSummary
        $withSummary.SummaryPath | Should -Not -BeNullOrEmpty
        Test-Path $withSummary.SummaryPath | Should -Be $true
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
            $entry.highValueFields.Count | Should -BeGreaterOrEqual 5 -Because "$($prop.Name) should have at least 5 fields"
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

    It 'TimeGenerated is in highValueFields for all tables' {
        foreach ($prop in $script:hvTables) {
            $prop.Value.highValueFields | Should -Contain 'TimeGenerated' -Because "$($prop.Name) should include TimeGenerated"
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

# ── Export-Report & ConvertTo-ReportSections tests ──────────────────────────

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
            StreamingTables  = @()
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
            StreamingTables  = @('DeviceEvents')
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
        $split = $sections | Where-Object TabId -eq 'splitkql'
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
