BeforeAll {
    # Dot-source the private functions directly for unit testing
    $privatePath = Join-Path $PSScriptRoot '..\Private'
    . "$privatePath\Get-AnalyticsRules.ps1"
    . "$privatePath\Invoke-Classification.ps1"
    . "$privatePath\Invoke-Analysis.ps1"
    . "$privatePath\Export-Report.ps1"
    . "$privatePath\Write-Report.ps1"
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
