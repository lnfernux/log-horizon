BeforeAll {
    # Dot-source the private functions directly for unit testing
    $privatePath = Join-Path $PSScriptRoot '..\Private'
    . "$privatePath\Get-AnalyticsRules.ps1"
    . "$privatePath\Invoke-Classification.ps1"
    . "$privatePath\Invoke-Analysis.ps1"
    . "$privatePath\Export-Report.ps1"
    . "$privatePath\Write-Report.ps1"
    . "$privatePath\Get-DataTransforms.ps1"
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

Describe 'New-SplitKql' {
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

        $result = New-SplitKql -TableName 'SecurityEvent' -HighValueFieldsDB $hvFields
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

        $result = New-SplitKql -TableName 'CustomTable_CL' -Rules $rules
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

        $result = New-SplitKql -TableName 'SigninLogs' -Rules $rules -HighValueFieldsDB $hvFields
        $result.Source | Should -Be 'combined'
        $result.SplitKql | Should -Be 'ResultType != 0'
        $result.RuleFields.Count | Should -BeGreaterThan 0
        $result.AllFields | Should -Contain 'TimeGenerated'
    }

    It 'returns source=none when no data available' {
        $result = New-SplitKql -TableName 'UnknownTable_CL'
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

        $result = New-SplitKql -TableName 'SecurityEvent' -HighValueFieldsDB $hvFields
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
