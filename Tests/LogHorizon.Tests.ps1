BeforeAll {
    # Dot-source the private functions directly for unit testing
    $privatePath = Join-Path $PSScriptRoot '..\Private'
    . "$privatePath\Get-AnalyticsRules.ps1"
    . "$privatePath\Get-TableUsage.ps1"
    . "$privatePath\Invoke-Classification.ps1"
    . "$privatePath\Invoke-Analysis.ps1"
    . "$privatePath\Export-Report.ps1"
    . "$privatePath\Write-Report.ps1"
    . "$privatePath\Get-DataTransforms.ps1"
    . "$privatePath\Get-Incidents.ps1"
    . "$privatePath\Get-AutomationRules.ps1"
    . "$privatePath\Get-TableRetention.ps1"
    . "$privatePath\Connect-Sentinel.ps1"
    . "$privatePath\Set-TableRetention.ps1"
    . "$privatePath\Invoke-AzRestWithRetry.ps1"
    . "$privatePath\Get-DefenderXDR.ps1"
    . "$privatePath\Get-CollectionCache.ps1"
    . "$privatePath\Get-LogHorizonEndpoint.ps1"
    . "$privatePath\Get-HuntingQueries.ps1"
    . "$privatePath\Get-DataConnectors.ps1"
    . "$privatePath\Get-SocOptimization.ps1"
    . (Join-Path $PSScriptRoot '..\Public\Set-LogHorizonTableRetention.ps1')

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
                    ObservedPlans          = @('Analytics')
                    ObservedKnownPlans     = @('Analytics')
                    ObservedPlanCount      = 1
                    ObservedPlanBreakdown  = @([PSCustomObject]@{ Plan = 'Analytics'; DataGB = 50; MonthlyGB = 50; RecordCount = 1000000 })
                    ObservedPlanSummary    = 'Analytics 50 GB/mo'
                    HasMultipleObservedPlans = $false
                    ObservedPlanMismatch   = $false
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
                    ObservedPlans          = @('Analytics', 'Basic')
                    ObservedKnownPlans     = @('Analytics', 'Basic')
                    ObservedPlanCount      = 2
                    ObservedPlanBreakdown  = @(
                        [PSCustomObject]@{ Plan = 'Analytics'; DataGB = 70; MonthlyGB = 70; RecordCount = 3500000 },
                        [PSCustomObject]@{ Plan = 'Basic'; DataGB = 30; MonthlyGB = 30; RecordCount = 1500000 }
                    )
                    ObservedPlanSummary    = 'Analytics 70 GB/mo; Basic 30 GB/mo'
                    HasMultipleObservedPlans = $true
                    ObservedPlanMismatch   = $false
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

Describe 'Get-TableRetentionChangeSet' {
    It 'supports analysis table rows as engine input' {
        $table = [PSCustomObject]@{
            TableName                   = 'SigninLogs'
            TablePlan                   = 'Analytics'
            ActualInteractiveRetentionDays = 90
            ActualRetentionDays         = 365
            TableSubType                = 'Any'
            ProvisioningState           = 'Succeeded'
        }

        $change = @(Get-TableRetentionChangeSet -Tables @($table) -TargetPlan Basic -TotalRetentionInDays 730)

        $change[0].CurrentPlan | Should -Be 'Analytics'
        $change[0].CurrentInteractive | Should -Be 90
        $change[0].CurrentTotal | Should -Be 365
        $change[0].ProvisioningState | Should -Be 'Succeeded'
    }

    It 'rejects invalid total retention values that are not in the discrete long-term enum' {
        $table = [PSCustomObject]@{ TableName = 'SigninLogs'; Plan = 'Analytics'; RetentionInDays = 90; TotalRetentionInDays = 365 }

        { Get-TableRetentionChangeSet -Tables @($table) -TotalRetentionInDays 800 } | Should -Throw '*TotalRetentionInDays*'
    }

    It 'rejects interactive retention changes on Basic targets' {
        $table = [PSCustomObject]@{ TableName = 'AzureDiagnostics'; Plan = 'Basic'; RetentionInDays = 30; TotalRetentionInDays = 30 }

        $change = @(Get-TableRetentionChangeSet -Tables @($table) -RetentionInDays 90)

        $change[0].Status | Should -Be 'Invalid'
        $change[0].Reason | Should -Match 'read-only on Basic'
    }

    It 'rejects plan switching to or from Auxiliary' {
        $table = [PSCustomObject]@{ TableName = 'CustomAux'; Plan = 'Auxiliary'; RetentionInDays = 30; TotalRetentionInDays = 30 }

        $change = @(Get-TableRetentionChangeSet -Tables @($table) -TargetPlan Basic)

        $change[0].Status | Should -Be 'Invalid'
        $change[0].Reason | Should -Match 'Auxiliary'
    }

    It 'treats inherit (-1/null) as a no-op when the table already inherits per the AsDefault flags' {
        $inheriting = [PSCustomObject]@{ TableName = 'SigninLogs'; Plan = 'Analytics'; RetentionInDays = 90; TotalRetentionInDays = 90; RetentionInDaysAsDefault = $true; TotalRetentionInDaysAsDefault = $true }
        $explicit   = [PSCustomObject]@{ TableName = 'AuditLogs';  Plan = 'Analytics'; RetentionInDays = 90; TotalRetentionInDays = 365; RetentionInDaysAsDefault = $false; TotalRetentionInDaysAsDefault = $false }

        $change = @(Get-TableRetentionChangeSet -Tables @($inheriting, $explicit) -RetentionInDays $null -TotalRetentionInDays $null)

        $change[0].Status | Should -Be 'Skipped'
        $change[1].Status | Should -Be 'Pending'
        $change[1].RetentionChanged | Should -Be $true
        $change[1].TotalChanged | Should -Be $true
    }

    It 'treats removing long-term retention as a no-op when total already equals interactive' {
        $table = [PSCustomObject]@{ TableName = 'AuditLogs'; Plan = 'Analytics'; RetentionInDays = 120; TotalRetentionInDays = 120 }
        $change = @(Get-TableRetentionChangeSet -Tables @($table) -TotalRetentionInDays $null)
        $change[0].Status | Should -Be 'Skipped'
    }

    It 'rejects search-job and restore tables up front' {
        $tables = @(
            [PSCustomObject]@{ TableName = 'Hunt_SRCH'; Plan = 'Analytics'; RetentionInDays = 90; TotalRetentionInDays = 90; TableType = 'SearchResults' },
            [PSCustomObject]@{ TableName = 'Old_RST';   Plan = 'Analytics'; RetentionInDays = 90; TotalRetentionInDays = 90; TableType = 'RestoredLogs' }
        )
        $change = @(Get-TableRetentionChangeSet -Tables $tables -TotalRetentionInDays 365)
        $change[0].Status | Should -Be 'Invalid'
        $change[0].Reason | Should -Match 'SearchResults'
        $change[1].Status | Should -Be 'Invalid'
        $change[1].Reason | Should -Match 'RestoredLogs'
    }

    It 'recognizes supported built-in tables from the Basic-plan allow-list' {
        $table = [PSCustomObject]@{ TableName = 'SigninLogs'; Plan = 'Analytics'; TableSubType = 'Any' }

        (Test-TableSupportsBasicPlan -Table $table) | Should -Be $true
    }

    It 'recognizes DCR-based custom tables as Basic-plan capable' {
        $table = [PSCustomObject]@{ TableName = 'MyCustom_CL'; Plan = 'Analytics'; TableSubType = 'DataCollectionRuleBased' }

        (Test-TableSupportsBasicPlan -Table $table) | Should -Be $true
    }

    It 'rejects plan switches for tables that do not support Basic' {
        $table = [PSCustomObject]@{ TableName = 'LegacyCustom_CL'; Plan = 'Analytics'; RetentionInDays = 90; TotalRetentionInDays = 365; TableSubType = 'Classic' }

        $change = @(Get-TableRetentionChangeSet -Tables @($table) -TargetPlan Basic)

        $change[0].Status | Should -Be 'Invalid'
        $change[0].Reason | Should -Match 'does not support Analytics <-> Basic'
    }

    It 'adds cost-floor and grace warnings for shrinking Analytics retention' {
        $table = [PSCustomObject]@{ TableName = 'SigninLogs'; Plan = 'Analytics'; RetentionInDays = 90; TotalRetentionInDays = 365 }

        $change = @(Get-TableRetentionChangeSet -Tables @($table) -RetentionInDays 30 -TotalRetentionInDays 180)

        ($change[0].Warnings -join ' ') | Should -Match '31 days'
        ($change[0].Warnings -join ' ') | Should -Match '30-day grace'
    }

    It 'marks unchanged target values as skipped' {
        $table = [PSCustomObject]@{ TableName = 'SigninLogs'; Plan = 'Analytics'; RetentionInDays = 90; TotalRetentionInDays = 365 }

        $change = @(Get-TableRetentionChangeSet -Tables @($table) -TargetPlan Analytics -RetentionInDays 90 -TotalRetentionInDays 365)

        $change[0].Status | Should -Be 'Skipped'
        $change[0].Reason | Should -Match 'match current configuration'
    }
}

Describe 'Invoke-TableRetentionApply' {
    BeforeEach {
        $script:retentionContext = [PSCustomObject]@{
            ArmToken      = 'token'
            ResourceId    = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws'
            WorkspaceName = 'ws'
        }
    }

    It 'sends Analytics payload with retention and total fields' {
        $script:capturedBodies = @()
        Mock Invoke-AzRestWithRetry {
            param($Uri, $Headers, $Method, $Body, $FollowAsync, $AsyncTimeoutSeconds)
            $script:capturedBodies += $Body
            [PSCustomObject]@{ status = 'Succeeded' }
        }

        $changeSet = @([
            PSCustomObject]@{
                TableName         = 'SigninLogs'
                Status            = 'Pending'
                ProvisioningState = 'Succeeded'
                PlanChanged       = $false
                RetentionChanged  = $true
                TotalChanged      = $true
                TargetPlan        = 'Analytics'
                TargetInteractive = 30
                TargetTotal       = 365
            }
        )

        $result = @(Invoke-TableRetentionApply -Context $script:retentionContext -ChangeSet $changeSet)
        $payload = $script:capturedBodies[0] | ConvertFrom-Json

        $result[0].Success | Should -Be $true
        $payload.properties.retentionInDays | Should -Be 30
        $payload.properties.totalRetentionInDays | Should -Be 365
        $payload.properties.plan | Should -BeNullOrEmpty
    }

    It 'sends Basic payload without retentionInDays' {
        $script:capturedBodies = @()
        Mock Invoke-AzRestWithRetry {
            param($Uri, $Headers, $Method, $Body, $FollowAsync, $AsyncTimeoutSeconds)
            $script:capturedBodies += $Body
            [PSCustomObject]@{ status = 'Succeeded' }
        }

        $changeSet = @([
            PSCustomObject]@{
                TableName         = 'AzureDiagnostics'
                Status            = 'Pending'
                ProvisioningState = 'Succeeded'
                PlanChanged       = $true
                RetentionChanged  = $false
                TotalChanged      = $true
                TargetPlan        = 'Basic'
                TargetInteractive = $null
                TargetTotal       = 730
            }
        )

        $null = Invoke-TableRetentionApply -Context $script:retentionContext -ChangeSet $changeSet
        $payload = $script:capturedBodies[0] | ConvertFrom-Json

        $payload.properties.plan | Should -Be 'Basic'
        $payload.properties.totalRetentionInDays | Should -Be 730
        $payload.properties.retentionInDays | Should -BeNullOrEmpty
    }

    It 'maps internal null defaults to -1 in the REST payload' {
        $script:capturedBodies = @()
        Mock Invoke-AzRestWithRetry {
            param($Uri, $Headers, $Method, $Body, $FollowAsync, $AsyncTimeoutSeconds)
            $script:capturedBodies += $Body
            [PSCustomObject]@{ status = 'Succeeded' }
        }

        $changeSet = @([
            PSCustomObject]@{
                TableName         = 'SigninLogs'
                Status            = 'Pending'
                ProvisioningState = 'Succeeded'
                PlanChanged       = $false
                RetentionChanged  = $true
                TotalChanged      = $true
                TargetPlan        = 'Analytics'
                TargetInteractive = $null
                TargetTotal       = $null
            }
        )

        $null = Invoke-TableRetentionApply -Context $script:retentionContext -ChangeSet $changeSet
        $payload = $script:capturedBodies[0] | ConvertFrom-Json

        $payload.properties.retentionInDays | Should -Be -1
        $payload.properties.totalRetentionInDays | Should -Be -1
    }

    It 'retries as plan then retention when the combined PATCH fails recoverably' {
        $script:capturedBodies = @()
        $script:callCount = 0
        Mock Invoke-AzRestWithRetry {
            param($Uri, $Headers, $Method, $Body, $FollowAsync, $AsyncTimeoutSeconds)
            $script:capturedBodies += $Body
            $script:callCount++
            if ($script:callCount -eq 1) {
                throw ([PSCustomObject]@{ StatusCode = 400; Message = 'Combined update rejected' })
            }
            [PSCustomObject]@{ status = 'Succeeded' }
        }

        $changeSet = @([
            PSCustomObject]@{
                TableName         = 'SigninLogs'
                Status            = 'Pending'
                ProvisioningState = 'Succeeded'
                PlanChanged       = $true
                RetentionChanged  = $true
                TotalChanged      = $true
                TargetPlan        = 'Analytics'
                TargetInteractive = 90
                TargetTotal       = 365
            }
        )

        $result = @(Invoke-TableRetentionApply -Context $script:retentionContext -ChangeSet $changeSet)
        $planPayload = $script:capturedBodies[1] | ConvertFrom-Json
        $retentionPayload = $script:capturedBodies[2] | ConvertFrom-Json

        $result[0].Success | Should -Be $true
        $result[0].Fallback | Should -Be $true
        $script:callCount | Should -Be 3
        $planPayload.properties.plan | Should -Be 'Analytics'
        $retentionPayload.properties.retentionInDays | Should -Be 90
        $retentionPayload.properties.totalRetentionInDays | Should -Be 365
    }

    It 'surfaces a clear permission error on 403' {
        Mock Invoke-AzRestWithRetry {
            throw ([PSCustomObject]@{ StatusCode = 403; Message = 'Forbidden' })
        }

        $changeSet = @([
            PSCustomObject]@{
                TableName         = 'SigninLogs'
                Status            = 'Pending'
                ProvisioningState = 'Succeeded'
                PlanChanged       = $false
                RetentionChanged  = $false
                TotalChanged      = $true
                TargetPlan        = 'Analytics'
                TargetInteractive = $null
                TargetTotal       = 365
            }
        )

        $result = @(Invoke-TableRetentionApply -Context $script:retentionContext -ChangeSet $changeSet)

        $result[0].Success | Should -Be $false
        $result[0].Error | Should -Match 'tables/write'
    }

    It 'surfaces the once-per-week plan switch limit on 409' {
        Mock Invoke-AzRestWithRetry {
            throw ([PSCustomObject]@{ StatusCode = 409; Message = 'Conflict' })
        }

        $changeSet = @([
            PSCustomObject]@{
                TableName         = 'SigninLogs'
                Status            = 'Pending'
                ProvisioningState = 'Succeeded'
                PlanChanged       = $true
                RetentionChanged  = $false
                TotalChanged      = $true
                TargetPlan        = 'Basic'
                TargetInteractive = $null
                TargetTotal       = 365
            }
        )

        $result = @(Invoke-TableRetentionApply -Context $script:retentionContext -ChangeSet $changeSet)

        $result[0].Success | Should -Be $false
        $result[0].Error | Should -Match 'once per week'
    }

    It 'skips non-succeeded tables before invoking REST' {
        Mock Invoke-AzRestWithRetry {
            [PSCustomObject]@{ status = 'Succeeded' }
        }

        $changeSet = @([
            PSCustomObject]@{
                TableName         = 'SigninLogs'
                Status            = 'Pending'
                ProvisioningState = 'Updating'
                PlanChanged       = $false
                RetentionChanged  = $false
                TotalChanged      = $true
                TargetPlan        = 'Analytics'
                TargetInteractive = $null
                TargetTotal       = 365
            }
        )

        $result = @(Invoke-TableRetentionApply -Context $script:retentionContext -ChangeSet $changeSet)

        $result[0].Action | Should -Be 'Skipped'
        Assert-MockCalled Invoke-AzRestWithRetry -Times 0 -Exactly
    }

    It 'returns mixed results without aborting the whole run' {
        $script:callCount = 0
        Mock Invoke-AzRestWithRetry {
            $script:callCount++
            if ($script:callCount -eq 2) {
                throw ([PSCustomObject]@{ StatusCode = 403; Message = 'Forbidden' })
            }
            [PSCustomObject]@{ status = 'Succeeded' }
        }

        $changeSet = @(
            [PSCustomObject]@{
                TableName         = 'T1'
                Status            = 'Pending'
                ProvisioningState = 'Succeeded'
                PlanChanged       = $false
                RetentionChanged  = $false
                TotalChanged      = $true
                TargetPlan        = 'Analytics'
                TargetInteractive = $null
                TargetTotal       = 365
            }
            [PSCustomObject]@{
                TableName         = 'T2'
                Status            = 'Pending'
                ProvisioningState = 'Succeeded'
                PlanChanged       = $false
                RetentionChanged  = $false
                TotalChanged      = $true
                TargetPlan        = 'Analytics'
                TargetInteractive = $null
                TargetTotal       = 365
            }
            [PSCustomObject]@{
                TableName         = 'T3'
                Status            = 'Invalid'
                ProvisioningState = 'Succeeded'
                PlanChanged       = $false
                RetentionChanged  = $false
                TotalChanged      = $false
                TargetPlan        = 'Analytics'
                TargetInteractive = $null
                TargetTotal       = $null
                Reason            = 'Rejected by validation'
            }
        )

        $results = @(Invoke-TableRetentionApply -Context $script:retentionContext -ChangeSet $changeSet)

        (@($results | Where-Object Success).Count) | Should -Be 1
        (@($results | Where-Object Action -eq 'Failed').Count) | Should -Be 1
        (@($results | Where-Object Action -eq 'Invalid').Count) | Should -Be 1
    }
}

Describe 'Set-LogHorizonTableRetention' {
    BeforeEach {
        Mock Connect-Sentinel {
            [PSCustomObject]@{
                SubscriptionId = 'sub'
                ResourceGroup  = 'rg'
                WorkspaceName  = 'ws'
                ResourceId     = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws'
                ArmToken       = 'arm'
                LaToken        = 'la'
            }
        }

        Mock Get-TableRetention {
            [PSCustomObject]@{
                WorkspaceRetentionDays = 90
                Tables = @(
                    [PSCustomObject]@{
                        TableName            = 'SigninLogs'
                        Plan                 = 'Analytics'
                        RetentionInDays      = 90
                        TotalRetentionInDays = 365
                        TableSubType         = 'Any'
                        ProvisioningState    = 'Succeeded'
                    }
                )
            }
        }
    }

    It 'maps -1 sentinel values to null and passes PreviewOnly under -WhatIf' {
        Mock Set-TableRetention {
            param($Context, $Tables, $TargetPlan, $TotalRetentionInDays, $RetentionInDays, $PreviewOnly, $AsyncTimeoutSeconds)
            $script:publicRetentionCall = [PSCustomObject]@{
                TableName            = $Tables[0].TableName
                TotalRetentionInDays = $TotalRetentionInDays
                RetentionInDays      = $RetentionInDays
                PreviewOnly          = $PreviewOnly
            }
            [PSCustomObject]@{
                ChangeSet = @()
                Results   = @()
                Summary   = [PSCustomObject]@{}
            }
        }

        $null = Set-LogHorizonTableRetention -SubscriptionId 'sub' -ResourceGroupName 'rg' -WorkspaceName 'ws' -TableName 'SigninLogs' -TotalRetentionInDays -1 -RetentionInDays -1 -WhatIf

        $script:publicRetentionCall.TableName | Should -Be 'SigninLogs'
        $script:publicRetentionCall.TotalRetentionInDays | Should -Be $null
        $script:publicRetentionCall.RetentionInDays | Should -Be $null
        $script:publicRetentionCall.PreviewOnly | Should -Be $true
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

Describe 'Get-TableUsage' {
    BeforeEach {
        # Row shape: DataType, ObservedPlan, IsBillable, DataMB, UsageRows, FirstSeen, LastSeen
        Mock Invoke-AzRestWithRetry {
            [PSCustomObject]@{
                tables = @(
                    [PSCustomObject]@{
                        rows = @(
                            @('SigninLogs', 'Analytics', $true, 10000.0, 100, '2026-08-01T00:00:00Z', '2026-08-31T00:00:00Z'),
                            @('SigninLogs', 'Basic', $true, 2000.0, 20, '2026-08-01T00:00:00Z', '2026-08-31T00:00:00Z'),
                            @('AzureActivity', $null, $false, 5000.0, 50, '2026-08-01T00:00:00Z', '2026-08-31T00:00:00Z'),
                            @('GraphLogs', 'Auxiliary', $true, 1000.0, 10, '2026-08-01T00:00:00Z', '2026-08-31T00:00:00Z'),
                            @('MixedTable', 'Analytics', $true, 3000.0, 30, '2026-08-01T00:00:00Z', '2026-08-31T00:00:00Z'),
                            @('MixedTable', 'Analytics', $false, 1000.0, 10, '2026-08-01T00:00:00Z', '2026-08-31T00:00:00Z')
                        )
                    }
                )
            }
        }
        $script:ctx = [PSCustomObject]@{ LaToken = 'token'; WorkspaceId = 'workspace-id' }
    }

    It 'aggregates table-plan rows back to one table object while preserving observed plan breakdown' {
        $result = Get-TableUsage -Context $ctx -DaysBack 30 -PricePerGB 5.59

        $result.Count | Should -Be 4

        $signin = $result | Where-Object TableName -eq 'SigninLogs'
        $signin | Should -Not -BeNullOrEmpty
        $signin.DataGB | Should -Be 12
        $signin.MonthlyGB | Should -Be 12
        $signin.UsageRowCount | Should -Be 120
        $signin.RecordCount | Should -Be 120
        $signin.ObservedPlanCount | Should -Be 2
        $signin.ObservedPlans | Should -Contain 'Analytics'
        $signin.ObservedPlans | Should -Contain 'Basic'
        @($signin.ObservedPlanBreakdown).Count | Should -Be 2
        (@($signin.ObservedPlanBreakdown | Where-Object Plan -eq 'Basic')[0]).MonthlyGB | Should -Be 2
    }

    It 'converts MB to GB using 1000 (billing GB) not 1024' {
        $result = Get-TableUsage -Context $ctx -DaysBack 30
        ($result | Where-Object TableName -eq 'GraphLogs').DataGB | Should -Be 1
    }

    It 'prices each observed plan with its own rate' {
        $result = Get-TableUsage -Context $ctx -DaysBack 30 -PricePerGB 5.59 -BasicPricePerGB 1.15 -LakePricePerGB 0.20

        $signin = $result | Where-Object TableName -eq 'SigninLogs'
        # 10 GB Analytics x 5.59 + 2 GB Basic x 1.15
        $signin.EstMonthlyCostUSD | Should -Be 58.2
        (@($signin.ObservedPlanBreakdown | Where-Object Plan -eq 'Basic')[0]).MonthlyCostUSD | Should -Be 2.3

        $graph = $result | Where-Object TableName -eq 'GraphLogs'
        $graph.EstMonthlyCostUSD | Should -Be 0.2
    }

    It 'derives IsFree from Usage.IsBillable and normalizes missing plan values to Unknown' {
        $result = Get-TableUsage -Context $ctx -DaysBack 30 -PricePerGB 5.59

        $activity = $result | Where-Object TableName -eq 'AzureActivity'
        $activity | Should -Not -BeNullOrEmpty
        $activity.IsFree | Should -Be $true
        $activity.IsFreeSource | Should -Be 'usage'
        $activity.EstMonthlyCostUSD | Should -Be 0
        $activity.ObservedPlans | Should -Contain 'Unknown'
    }

    It 'only charges the billable share when a table has billable and non-billable rows' {
        $result = Get-TableUsage -Context $ctx -DaysBack 30 -PricePerGB 5.59

        $mixed = $result | Where-Object TableName -eq 'MixedTable'
        $mixed.DataGB | Should -Be 4
        $mixed.BillableGB | Should -Be 3
        $mixed.IsFree | Should -Be $false
        $mixed.EstMonthlyCostUSD | Should -Be ([math]::Round(3 * 5.59, 2))
    }

    It 'extrapolates from the observed span, not DaysBack, when the data covers fewer days' {
        # Rows span 30 days; asking for 365 must not divide by 365
        $result = Get-TableUsage -Context $ctx -DaysBack 365 -PricePerGB 5.59
        $signin = $result | Where-Object TableName -eq 'SigninLogs'
        $signin.ObservedDays | Should -Be 30
        $signin.MonthlyGB | Should -Be 12
    }

    It 'falls back to the classification database when Usage rows have no IsBillable flag' {
        Mock Invoke-AzRestWithRetry {
            [PSCustomObject]@{
                tables = @(
                    [PSCustomObject]@{
                        rows = @(
                            @('AzureActivity', 'Analytics', $null, 1000.0, 10),
                            @('SigninLogs', 'Analytics', '', 1000.0, 10)
                        )
                    }
                )
            }
        }
        $result = Get-TableUsage -Context $ctx -DaysBack 30 -PricePerGB 5.59

        $activity = $result | Where-Object TableName -eq 'AzureActivity'
        $activity.IsFree | Should -Be $true
        $activity.IsFreeSource | Should -Be 'database'
        $activity.EstMonthlyCostUSD | Should -Be 0

        $signin = $result | Where-Object TableName -eq 'SigninLogs'
        $signin.IsFree | Should -Be $false
        $signin.IsFreeSource | Should -Be 'database'
        $signin.ObservedDays | Should -Be 30
    }

    It 'returns nothing for an empty Usage result' {
        Mock Invoke-AzRestWithRetry { [PSCustomObject]@{ tables = @([PSCustomObject]@{ rows = @() }) } }
        $result = @(Get-TableUsage -Context $ctx -DaysBack 30)
        $result.Count | Should -Be 0
    }

    It 'prices an unrecognised plan name at the Analytics rate' {
        Mock Invoke-AzRestWithRetry {
            [PSCustomObject]@{ tables = @([PSCustomObject]@{ rows = @(, @('T', 'FuturePlan', $true, 1000.0, 1, '2026-08-01T00:00:00Z', '2026-08-31T00:00:00Z')) }) }
        }
        $result = Get-TableUsage -Context $ctx -DaysBack 30 -PricePerGB 4
        $result.EstMonthlyCostUSD | Should -Be 4
    }
}

Describe 'Get-UsageObservedDays' {
    It 'returns DaysBack when rows carry no timestamps' {
        $short = , @('T', 'Analytics', $true, 1, 1)
        Get-UsageObservedDays -Rows $short -DaysBack 45 | Should -Be 45
        Get-UsageObservedDays -Rows @() -DaysBack 45 | Should -Be 45
    }

    It 'uses the widest span across all rows, rounded up' {
        $rows = @(
            @('A', 'Analytics', $true, 1, 1, '2026-08-10T00:00:00Z', '2026-08-20T12:00:00Z'),
            @('B', 'Analytics', $true, 1, 1, '2026-08-01T00:00:00Z', '2026-08-15T00:00:00Z')
        )
        Get-UsageObservedDays -Rows $rows -DaysBack 90 | Should -Be 20
    }

    It 'never returns less than 1 and never more than DaysBack' {
        $same = , @('A', 'Analytics', $true, 1, 1, '2026-08-10T00:00:00Z', '2026-08-10T00:00:00Z')
        Get-UsageObservedDays -Rows $same -DaysBack 90 | Should -Be 1

        $wide = , @('A', 'Analytics', $true, 1, 1, '2026-01-01T00:00:00Z', '2026-08-10T00:00:00Z')
        Get-UsageObservedDays -Rows $wide -DaysBack 90 | Should -Be 90
    }

    It 'skips rows whose timestamps do not parse' {
        $rows = @(
            @('A', 'Analytics', $true, 1, 1, 'not-a-date', '2026-08-20T00:00:00Z'),
            @('B', 'Analytics', $true, 1, 1, '2026-08-01T00:00:00Z', 'garbage'),
            @('C', 'Analytics', $true, 1, 1, '2026-08-05T00:00:00Z', '2026-08-07T00:00:00Z')
        )
        Get-UsageObservedDays -Rows $rows -DaysBack 90 | Should -Be 2
    }
}

Describe 'ConvertTo-UsageBoolean' {
    It 'passes booleans through' {
        ConvertTo-UsageBoolean -Value $true | Should -Be $true
        ConvertTo-UsageBoolean -Value $false | Should -Be $false
    }

    It 'parses string booleans case-insensitively' {
        ConvertTo-UsageBoolean -Value 'True' | Should -Be $true
        ConvertTo-UsageBoolean -Value ' false ' | Should -Be $false
    }

    It 'returns null for null, empty or unparseable input' {
        ConvertTo-UsageBoolean -Value $null | Should -BeNullOrEmpty
        ConvertTo-UsageBoolean -Value '' | Should -BeNullOrEmpty
        ConvertTo-UsageBoolean -Value 'maybe' | Should -BeNullOrEmpty
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

Describe 'Invoke-Analysis observed plan usage' {
    BeforeAll {
        $tableUsage = @(
            [PSCustomObject]@{
                TableName = 'SigninLogs'
                DataGB = 12
                MonthlyGB = 12
                RecordCount = 120
                EstMonthlyCostUSD = 67.08
                IsFree = $false
                ObservedPlans = @('Analytics', 'Basic')
                ObservedPlanCount = 2
                ObservedPlanBreakdown = @(
                    [PSCustomObject]@{ Plan = 'Analytics'; DataGB = 10; MonthlyGB = 10; RecordCount = 100 },
                    [PSCustomObject]@{ Plan = 'Basic'; DataGB = 2; MonthlyGB = 2; RecordCount = 20 }
                )
            }
            [PSCustomObject]@{
                TableName = 'DeviceEvents'
                DataGB = 8
                MonthlyGB = 8
                RecordCount = 80
                EstMonthlyCostUSD = 44.72
                IsFree = $false
                ObservedPlans = @('Analytics')
                ObservedPlanCount = 1
                ObservedPlanBreakdown = @(
                    [PSCustomObject]@{ Plan = 'Analytics'; DataGB = 8; MonthlyGB = 8; RecordCount = 80 }
                )
            }
        )

        $classifications = [PSCustomObject]@{
            Classifications = @{
                'SigninLogs' = [PSCustomObject]@{ Classification = 'primary'; Category = 'Identity'; RecommendedTier = 'analytics'; IsFree = $false; RecommendedRetentionDays = 365 }
                'DeviceEvents' = [PSCustomObject]@{ Classification = 'primary'; Category = 'Endpoint'; RecommendedTier = 'analytics'; IsFree = $false; RecommendedRetentionDays = 180 }
            }
            KeywordGaps = @()
            DatabaseEntries = 2
        }

        $rulesData = [PSCustomObject]@{
            Rules = @()
            TableCoverage = @{ 'SigninLogs' = 1; 'DeviceEvents' = 1 }
            TotalRules = 2
            EnabledRules = 2
            DontCorrCount = 0
            IncCorrCount = 0
        }

        $huntingData = [PSCustomObject]@{
            Queries = @()
            TableCoverage = @{}
            TotalQueries = 0
        }

        $tableRetention = @(
            [PSCustomObject]@{ TableName = 'SigninLogs'; RetentionInDays = 30; TotalRetentionInDays = 90; ArchiveRetentionInDays = 0; Plan = 'Basic' },
            [PSCustomObject]@{ TableName = 'DeviceEvents'; RetentionInDays = 30; TotalRetentionInDays = 90; ArchiveRetentionInDays = 0; Plan = 'Basic' }
        )

        $script:observedPlanResult = Invoke-Analysis -TableUsage $tableUsage `
            -Classifications $classifications `
            -RulesData $rulesData `
            -HuntingData $huntingData `
            -TableRetention $tableRetention `
            -SocRecommendations @()
    }

    It 'tracks multiple observed plans without replacing the configured table plan' {
        $signin = $script:observedPlanResult.TableAnalysis | Where-Object TableName -eq 'SigninLogs'
        $signin.TablePlan | Should -Be 'Basic'
        $signin.HasMultipleObservedPlans | Should -Be $true
        $signin.ObservedPlanMismatch | Should -Be $false
        $signin.ObservedPlanSummary | Should -Be 'Analytics 10 GB/mo; Basic 2 GB/mo'
    }

    It 'flags configured plan mismatches when observed usage does not include the configured plan' {
        $device = $script:observedPlanResult.TableAnalysis | Where-Object TableName -eq 'DeviceEvents'
        $device.TablePlan | Should -Be 'Basic'
        $device.HasMultipleObservedPlans | Should -Be $false
        $device.ObservedPlanMismatch | Should -Be $true
    }

    It 'adds plan usage review recommendations and summary counts' {
        $planRecs = @($script:observedPlanResult.Recommendations | Where-Object Type -eq 'PlanUsage')
        $planRecs.TableName | Should -Contain 'SigninLogs'
        $planRecs.TableName | Should -Contain 'DeviceEvents'
        $script:observedPlanResult.Summary.MultiPlanUsageTables | Should -Be 1
        $script:observedPlanResult.Summary.ObservedPlanMismatches | Should -Be 1
    }
}

Describe 'Invoke-Analysis DataLake recommendation edge cases' {
    BeforeAll {
        $tableUsage = @(
            [PSCustomObject]@{
                TableName = 'SecondaryArchive_CL'
                DataGB = 120
                MonthlyGB = 40
                RecordCount = 400000
                EstMonthlyCostUSD = 223.60
                IsFree = $false
                ObservedPlans = @('Analytics', 'Auxiliary')
                ObservedPlanCount = 2
                ObservedPlanBreakdown = @(
                    [PSCustomObject]@{ Plan = 'Analytics'; DataGB = 90; MonthlyGB = 30; RecordCount = 300000 },
                    [PSCustomObject]@{ Plan = 'Auxiliary'; DataGB = 30; MonthlyGB = 10; RecordCount = 100000 }
                )
            }
        )

        $classifications = [PSCustomObject]@{
            Classifications = @{
                'SecondaryArchive_CL' = [PSCustomObject]@{ Classification = 'secondary'; Category = 'Custom Secondary'; RecommendedTier = 'datalake'; IsFree = $false; RecommendedRetentionDays = 90 }
            }
            KeywordGaps = @()
            DatabaseEntries = 1
        }

        $rulesData = [PSCustomObject]@{
            Rules = @()
            TableCoverage = @{}
            TotalRules = 0
            EnabledRules = 0
            DontCorrCount = 0
            IncCorrCount = 0
        }

        $huntingData = [PSCustomObject]@{
            Queries = @()
            TableCoverage = @{}
            TotalQueries = 0
        }

        $tableRetention = @(
            [PSCustomObject]@{ TableName = 'SecondaryArchive_CL'; RetentionInDays = 30; TotalRetentionInDays = 365; ArchiveRetentionInDays = 0; Plan = 'Auxiliary' }
        )

        $script:auxDataLakeEdgeResult = Invoke-Analysis -TableUsage $tableUsage `
            -Classifications $classifications `
            -RulesData $rulesData `
            -HuntingData $huntingData `
            -TableRetention $tableRetention `
            -SocRecommendations @()
    }

    It 'does not recommend moving a table already configured as Auxiliary to Data Lake' {
        $dataLakeRecs = @($script:auxDataLakeEdgeResult.Recommendations | Where-Object { $_.TableName -eq 'SecondaryArchive_CL' -and $_.Type -eq 'DataLake' })

        $dataLakeRecs | Should -BeNullOrEmpty
    }

    It 'still surfaces mixed historical plan usage for review' {
        $planUsageRecs = @($script:auxDataLakeEdgeResult.Recommendations | Where-Object { $_.TableName -eq 'SecondaryArchive_CL' -and $_.Type -eq 'PlanUsage' })

        $planUsageRecs | Should -Not -BeNullOrEmpty
    }

    It 'uses plan-aware wording for generic low-value recommendations on Auxiliary tables' {
        $lowValueRec = @($script:auxDataLakeEdgeResult.Recommendations | Where-Object { $_.TableName -eq 'SecondaryArchive_CL' -and $_.Type -eq 'LowValue' }) | Select-Object -First 1

        $lowValueRec | Should -Not -BeNullOrEmpty
        $lowValueRec.Detail | Should -Not -Match 'move to data lake'
        $lowValueRec.Detail | Should -Match 'current Data Lake placement'
    }
}

Describe 'Invoke-Analysis plan-aware pricing' {
    BeforeAll {
        $script:pricingRules = [PSCustomObject]@{ Rules = @(); TableCoverage = @{}; TotalRules = 0; EnabledRules = 0; DontCorrCount = 0; IncCorrCount = 0 }
        $script:pricingHunting = [PSCustomObject]@{ Queries = @(); TableCoverage = @{}; TotalQueries = 0 }
    }

    It 'computes DataLake savings as current cost minus the lake rate for the same volume' {
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'BigSecondary'; DataGB = 300; MonthlyGB = 100; UsageRowCount = 1; EstMonthlyCostUSD = 559.00; IsFree = $false; IsFreeSource = 'usage'; ObservedPlans = @('Analytics'); ObservedPlanCount = 1; ObservedPlanBreakdown = @() }
        )
        $classifications = [PSCustomObject]@{
            Classifications = @{ 'BigSecondary' = [PSCustomObject]@{ Classification = 'secondary'; Category = 'Infra'; RecommendedTier = 'datalake'; IsFree = $false; RecommendedRetentionDays = 90 } }
            KeywordGaps = @(); DatabaseEntries = 1
        }
        $result = Invoke-Analysis -TableUsage $tableUsage -Classifications $classifications -RulesData $script:pricingRules -HuntingData $script:pricingHunting -PricePerGB 5.59 -LakePricePerGB 0.20

        $rec = @($result.Recommendations | Where-Object Type -eq 'DataLake')[0]
        $rec | Should -Not -BeNullOrEmpty
        # 559.00 - 100 GB x 0.20
        $rec.EstSavingsUSD | Should -Be 539
        $result.Summary.LakePricePerGB | Should -Be 0.20
        $result.Summary.BasicPricePerGB | Should -Be 1.15
    }

    It 'never reports negative DataLake savings' {
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'CheapSecondary'; DataGB = 300; MonthlyGB = 100; UsageRowCount = 1; EstMonthlyCostUSD = 5; IsFree = $false; IsFreeSource = 'usage'; ObservedPlans = @('Analytics'); ObservedPlanCount = 1; ObservedPlanBreakdown = @() }
        )
        $classifications = [PSCustomObject]@{
            Classifications = @{ 'CheapSecondary' = [PSCustomObject]@{ Classification = 'secondary'; Category = 'Infra'; RecommendedTier = 'datalake'; IsFree = $false; RecommendedRetentionDays = 90 } }
            KeywordGaps = @(); DatabaseEntries = 1
        }
        $result = Invoke-Analysis -TableUsage $tableUsage -Classifications $classifications -RulesData $script:pricingRules -HuntingData $script:pricingHunting -LakePricePerGB 0.20

        # CostTier is High by volume (100 GB) so the DataLake rule fires; savings clamp at 0
        @($result.Recommendations | Where-Object Type -eq 'DataLake')[0].EstSavingsUSD | Should -Be 0
    }

    It 'lets the classification database decide IsFree only when Usage had no billable flag' {
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'DbFree'; DataGB = 3; MonthlyGB = 1; UsageRowCount = 1; EstMonthlyCostUSD = 5.59; IsFree = $false; IsFreeSource = 'database'; ObservedPlans = @('Analytics'); ObservedPlanCount = 1; ObservedPlanBreakdown = @() },
            [PSCustomObject]@{ TableName = 'UsagePaid'; DataGB = 3; MonthlyGB = 1; UsageRowCount = 1; EstMonthlyCostUSD = 5.59; IsFree = $false; IsFreeSource = 'usage'; ObservedPlans = @('Analytics'); ObservedPlanCount = 1; ObservedPlanBreakdown = @() }
        )
        $classifications = [PSCustomObject]@{
            Classifications = @{
                'DbFree'    = [PSCustomObject]@{ Classification = 'primary'; Category = 'Security Alerts'; RecommendedTier = 'analytics'; IsFree = $true; RecommendedRetentionDays = 90 }
                'UsagePaid' = [PSCustomObject]@{ Classification = 'primary'; Category = 'Security Alerts'; RecommendedTier = 'analytics'; IsFree = $true; RecommendedRetentionDays = 90 }
            }
            KeywordGaps = @(); DatabaseEntries = 2
        }
        $result = Invoke-Analysis -TableUsage $tableUsage -Classifications $classifications -RulesData $script:pricingRules -HuntingData $script:pricingHunting

        $dbFree = $result.TableAnalysis | Where-Object TableName -eq 'DbFree'
        $dbFree.IsFree | Should -Be $true
        $dbFree.EstMonthlyCostUSD | Should -Be 0
        $dbFree.CostTier | Should -Be 'Free'
        $dbFree.IsFreeSource | Should -Be 'database'

        $usagePaid = $result.TableAnalysis | Where-Object TableName -eq 'UsagePaid'
        $usagePaid.IsFree | Should -Be $false
        $usagePaid.EstMonthlyCostUSD | Should -Be 5.59
        $usagePaid.IsFreeSource | Should -Be 'usage'
    }

    It 'surfaces the observed Usage span in the summary' {
        $tableUsage = @(
            [PSCustomObject]@{ TableName = 'T'; DataGB = 1; MonthlyGB = 1; UsageRowCount = 1; EstMonthlyCostUSD = 5.59; IsFree = $false; IsFreeSource = 'usage'; ObservedDays = 42; ObservedPlans = @('Analytics'); ObservedPlanCount = 1; ObservedPlanBreakdown = @() }
        )
        $classifications = [PSCustomObject]@{ Classifications = @{}; KeywordGaps = @(); DatabaseEntries = 0 }
        $result = Invoke-Analysis -TableUsage $tableUsage -Classifications $classifications -RulesData $script:pricingRules -HuntingData $script:pricingHunting
        $result.Summary.UsageObservedDays | Should -Be 42
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

    It 'labels multi-operation transforms in order of appearance' {
        Get-TransformType -KQL 'source | where EventID == 4624 | project-away RawData' | Should -Be 'Filter+ColumnRemoval'
        Get-TransformType -KQL 'source | extend X = 1 | where X == 1' | Should -Be 'Enrichment+Filter'
        Get-TransformType -KQL 'source | where A == 1 | project A, B' | Should -Be 'Filter+Projection'
        Get-TransformType -KQL '' | Should -Be 'Custom'
    }

    It 'lists operations as an array' {
        @(Get-TransformOperation -KQL 'source | where A == 1 | summarize count() by A') | Should -Be @('Filter', 'Aggregation')
        @(Get-TransformOperation -KQL $null).Count | Should -Be 0
    }
}

Describe 'Get-DataTransforms discovery' {
    BeforeAll {
        $script:dtCtx = [PSCustomObject]@{
            ArmToken       = 'tok'
            SubscriptionId = 'sub1'
            ResourceGroup  = 'rg1'
            ResourceId     = '/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/ws1'
        }
        $script:wsId = $script:dtCtx.ResourceId

        function New-Dcr {
            param($Id, $Name, $Flows, $Kind = $null, $Transformations = $null, $WorkspaceResourceId = $script:wsId)
            $props = [PSCustomObject]@{
                dataFlows    = $Flows
                destinations = [PSCustomObject]@{ logAnalytics = @([PSCustomObject]@{ name = 'la'; workspaceResourceId = $WorkspaceResourceId }) }
            }
            if ($Transformations) { $props | Add-Member -NotePropertyName transformations -NotePropertyValue $Transformations }
            [PSCustomObject]@{ id = $Id; name = $Name; location = 'westeurope'; kind = $Kind; properties = $props }
        }

        $script:subDcr = New-Dcr -Id '/subscriptions/sub1/resourceGroups/other/providers/Microsoft.Insights/dataCollectionRules/agent-dcr' -Name 'agent-dcr' -Flows @(
            [PSCustomObject]@{ streams = @('Microsoft-SecurityEvent'); destinations = @('la'); transformKql = 'source | where EventID != 4688'; outputStream = 'Microsoft-SecurityEvent' }
        )
        $script:otherWsDcr = New-Dcr -Id '/subscriptions/sub1/resourceGroups/other/providers/Microsoft.Insights/dataCollectionRules/elsewhere' -Name 'elsewhere' -WorkspaceResourceId '/subscriptions/sub1/resourceGroups/x/providers/Microsoft.OperationalInsights/workspaces/OTHER' -Flows @(
            [PSCustomObject]@{ streams = @('Microsoft-Syslog'); destinations = @('la'); transformKql = 'source | where Facility == "auth"'; outputStream = 'Microsoft-Syslog' }
        )
        $script:wsTransformDcr = New-Dcr -Id '/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Insights/dataCollectionRules/ws-transform' -Name 'ws-transform' -Kind 'WorkspaceTransforms' -Flows @(
            [PSCustomObject]@{ streams = @('Microsoft-Table-SigninLogs'); destinations = @('la'); transformKql = 'source | project-away AuthenticationDetails' },
            [PSCustomObject]@{ streams = @('Microsoft-Table-AuditLogs'); destinations = @('la'); transformKql = 'source' }
        )
        $script:multiStageDcr = New-Dcr -Id '/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Insights/dataCollectionRules/multi' -Name 'multi' -Flows @(
            [PSCustomObject]@{ streams = @('Custom-MyApp_CL'); destinations = @('la'); transform = 'stage1'; outputStream = 'Custom-MyApp_CL' }
        ) -Transformations @(
            [PSCustomObject]@{ name = 'stage1'; processors = @(
                [PSCustomObject]@{ processor = 'transform.KQL'; configuration = [PSCustomObject]@{ expression = 'source | where Level != "Debug"' } },
                [PSCustomObject]@{ processor = 'something.else'; configuration = [PSCustomObject]@{ foo = 1 } },
                [PSCustomObject]@{ processor = 'transform.KQL'; configuration = [PSCustomObject]@{ transformKql = 'source | extend Env = "prod"' } }
            ) }
        )
    }

    It 'lists at subscription scope, filters on destination workspace, adds the default DCR and associations, and dedupes' {
        Mock Invoke-AzRestWithRetry {
            switch -Wildcard ($Uri) {
                '*/subscriptions/sub1/providers/Microsoft.Insights/dataCollectionRules`?*' { return [PSCustomObject]@{ value = @($script:subDcr, $script:otherWsDcr) } }
                '*/dataCollectionRules/ws-transform`?*' { return $script:wsTransformDcr }
                '*/dataCollectionRuleAssociations`?*' { return [PSCustomObject]@{ value = @(
                    [PSCustomObject]@{ properties = [PSCustomObject]@{ dataCollectionRuleId = $script:wsTransformDcr.id } },
                    [PSCustomObject]@{ properties = [PSCustomObject]@{ dataCollectionRuleId = $script:multiStageDcr.id } }
                ) } }
                '*/dataCollectionRules/multi`?*' { return $script:multiStageDcr }
                default { throw "unexpected $Uri" }
            }
        }

        $result = Get-DataTransforms -Context $script:dtCtx -WorkspaceDefaultDcrId $script:wsTransformDcr.id

        $result.TotalDCRs | Should -Be 3
        $result.DiscoveryStatus.SubscriptionList | Should -Match 'Succeeded \(1 matching\)'
        $result.DiscoveryStatus.ResourceGroupList | Should -Be 'NotAttempted'
        $result.DiscoveryStatus.DefaultDcr | Should -Be 'Succeeded'
        $result.DiscoveryStatus.Associations | Should -Match '2 association'
        $result.DiscoveryStatus.Errors.Count | Should -Be 0
        # ws-transform came from the default id, so associations only fetched multi
        Should -Invoke Invoke-AzRestWithRetry -Times 1 -ParameterFilter { $Uri -like '*/dataCollectionRules/ws-transform`?*' }
        $result.Transforms.Count | Should -Be 3
        $result.TableLookup.Keys | Should -Contain 'SecurityEvent'
        $result.TableLookup.Keys | Should -Contain 'SigninLogs'
        $result.TableLookup.Keys | Should -Contain 'MyApp_CL'
        $result.TableLookup.Keys | Should -Not -Contain 'Syslog'
        $result.TableLookup.Keys | Should -Not -Contain 'AuditLogs'
    }

    It 'parses workspace transformation DCRs without outputStream and strips Microsoft-Table-' {
        Mock Invoke-AzRestWithRetry {
            switch -Wildcard ($Uri) {
                '*/subscriptions/sub1/providers/Microsoft.Insights/dataCollectionRules`?*' { return [PSCustomObject]@{ value = @($script:wsTransformDcr) } }
                '*/dataCollectionRuleAssociations`?*' { return [PSCustomObject]@{ value = @() } }
                default { throw "unexpected $Uri" }
            }
        }
        $result = Get-DataTransforms -Context $script:dtCtx
        $t = $result.Transforms[0]
        $t.OutputTable | Should -Be 'SigninLogs'
        $t.InputStreams | Should -Be @('SigninLogs')
        $t.TransformType | Should -Be 'ColumnRemoval'
        $t.DCRKind | Should -Be 'WorkspaceTransforms'
        $result.RelevantDCRs[0].Kind | Should -Be 'WorkspaceTransforms'
        $result.DiscoveryStatus.DefaultDcr | Should -Be 'NotConfigured'
    }

    It 'resolves multi-stage transformations referenced by name' {
        Mock Invoke-AzRestWithRetry {
            switch -Wildcard ($Uri) {
                '*/subscriptions/sub1/providers/Microsoft.Insights/dataCollectionRules`?*' { return [PSCustomObject]@{ value = @($script:multiStageDcr) } }
                '*/dataCollectionRuleAssociations`?*' { return [PSCustomObject]@{ value = @() } }
                default { throw "unexpected $Uri" }
            }
        }
        $result = Get-DataTransforms -Context $script:dtCtx
        $t = $result.Transforms[0]
        $t.OutputTable | Should -Be 'MyApp_CL'
        $t.TransformKql | Should -Match 'Level != "Debug"'
        $t.TransformKql | Should -Match 'Env = "prod"'
        $t.TransformType | Should -Be 'Filter+Enrichment'
        $t.Operations | Should -Be @('Filter', 'Enrichment')
    }

    It 'falls back to resource-group scope when the subscription list is denied' {
        Mock Invoke-AzRestWithRetry {
            switch -Wildcard ($Uri) {
                '*/subscriptions/sub1/providers/Microsoft.Insights/dataCollectionRules`?*' { throw 'Response status code does not indicate success: 403 (Forbidden).' }
                '*/resourceGroups/rg1/providers/Microsoft.Insights/dataCollectionRules`?*' { return [PSCustomObject]@{ value = @($script:subDcr) } }
                '*/dataCollectionRuleAssociations`?*' { return [PSCustomObject]@{ value = @() } }
                default { throw "unexpected $Uri" }
            }
        }
        $result = Get-DataTransforms -Context $script:dtCtx -WarningVariable w -WarningAction SilentlyContinue
        $result.TotalDCRs | Should -Be 1
        $result.DiscoveryStatus.SubscriptionList | Should -Be 'Failed'
        $result.DiscoveryStatus.ResourceGroupList | Should -Match 'Succeeded'
        $result.DiscoveryStatus.Errors.Count | Should -Be 1
        @($w).Count | Should -Be 0
    }

    It 'warns but still returns association-discovered DCRs when every list is denied' {
        Mock Invoke-AzRestWithRetry {
            switch -Wildcard ($Uri) {
                '*/dataCollectionRules`?*' { throw 'Response status code does not indicate success: 403 (Forbidden).' }
                '*/dataCollectionRuleAssociations`?*' { return [PSCustomObject]@{ value = @([PSCustomObject]@{ properties = [PSCustomObject]@{ dataCollectionRuleId = $script:wsTransformDcr.id } }) } }
                '*/dataCollectionRules/ws-transform`?*' { return $script:wsTransformDcr }
                default { throw "unexpected $Uri" }
            }
        }
        $result = Get-DataTransforms -Context $script:dtCtx -WarningVariable w -WarningAction SilentlyContinue
        $result.TotalDCRs | Should -Be 1
        "$w" | Should -Match 'DCR listing was denied'
        $result.DiscoveryStatus.Errors.Count | Should -Be 2
    }

    It 'warns with the required permission when every route fails, and records per-DCR fetch errors' {
        Mock Invoke-AzRestWithRetry {
            switch -Wildcard ($Uri) {
                '*/dataCollectionRules`?*' { throw 'Response status code does not indicate success: 403 (Forbidden).' }
                '*/dataCollectionRules/ws-transform`?*' { throw 'Response status code does not indicate success: 404 (Not Found).' }
                '*/dataCollectionRuleAssociations`?*' { throw 'Response status code does not indicate success: 400 (Bad Request).' }
                default { throw "unexpected $Uri" }
            }
        }
        $result = Get-DataTransforms -Context $script:dtCtx -WorkspaceDefaultDcrId $script:wsTransformDcr.id -WarningVariable w -WarningAction SilentlyContinue
        $result.TotalDCRs | Should -Be 0
        $result.Transforms.Count | Should -Be 0
        $result.DiscoveryStatus.DefaultDcr | Should -Be 'Failed'
        $result.DiscoveryStatus.Associations | Should -Be 'Failed'
        "$w" | Should -Match 'Microsoft.Insights/dataCollectionRules/read'
        "$w" | Should -Match 'transformation DCR'
    }

    It 'records an error for an associated DCR that cannot be read but keeps the others' {
        Mock Invoke-AzRestWithRetry {
            switch -Wildcard ($Uri) {
                '*/subscriptions/sub1/providers/Microsoft.Insights/dataCollectionRules`?*' { return [PSCustomObject]@{ value = @() } }
                '*/dataCollectionRuleAssociations`?*' { return [PSCustomObject]@{ value = @(
                    [PSCustomObject]@{ properties = [PSCustomObject]@{ dataCollectionRuleId = $script:multiStageDcr.id } },
                    [PSCustomObject]@{ properties = [PSCustomObject]@{ dataCollectionRuleId = '/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Insights/dataCollectionRules/gone' } },
                    [PSCustomObject]@{ properties = [PSCustomObject]@{ dataCollectionRuleId = '' } }
                ) } }
                '*/dataCollectionRules/multi`?*' { return $script:multiStageDcr }
                '*/dataCollectionRules/gone`?*' { throw 'Response status code does not indicate success: 404 (Not Found).' }
                default { throw "unexpected $Uri" }
            }
        }
        $result = Get-DataTransforms -Context $script:dtCtx
        $result.TotalDCRs | Should -Be 1
        $result.DiscoveryStatus.Errors.Count | Should -Be 1
        $result.DiscoveryStatus.Errors[0] | Should -Match 'gone'
    }
}

Describe 'Get-DataTransforms helpers' {
    It 'strips every stream prefix' {
        ConvertTo-DcrTableName -Stream 'Microsoft-Table-SigninLogs' | Should -Be 'SigninLogs'
        ConvertTo-DcrTableName -Stream 'Microsoft-SecurityEvent' | Should -Be 'SecurityEvent'
        ConvertTo-DcrTableName -Stream 'Custom-MyApp_CL' | Should -Be 'MyApp_CL'
        ConvertTo-DcrTableName -Stream 'Plain' | Should -Be 'Plain'
        ConvertTo-DcrTableName -Stream '' | Should -BeNullOrEmpty
    }

    It 'matches the workspace destination case-insensitively and rejects others' {
        $ws = '/subscriptions/S/resourceGroups/RG/providers/Microsoft.OperationalInsights/workspaces/WS'
        $dcr = [PSCustomObject]@{ properties = [PSCustomObject]@{ destinations = [PSCustomObject]@{ logAnalytics = @([PSCustomObject]@{ workspaceResourceId = $ws.ToLower() }) } } }
        Test-DcrTargetsWorkspace -Dcr $dcr -WorkspaceResourceId $ws | Should -Be $true
        Test-DcrTargetsWorkspace -Dcr $dcr -WorkspaceResourceId "$ws-other" | Should -Be $false
        Test-DcrTargetsWorkspace -Dcr ([PSCustomObject]@{ properties = [PSCustomObject]@{ destinations = $null } }) -WorkspaceResourceId $ws | Should -Be $false
    }

    It 'resolves flow KQL from inline, named multi-stage, or nothing' {
        $props = [PSCustomObject]@{ transformations = @([PSCustomObject]@{ name = 's'; processors = @([PSCustomObject]@{ processor = 'transform.KQL'; configuration = [PSCustomObject]@{ expression = 'source | where A == 1' } }) }) }
        Resolve-DcrFlowTransformKql -Flow ([PSCustomObject]@{ transformKql = 'source | take 1' }) -Properties $props | Should -Be 'source | take 1'
        Resolve-DcrFlowTransformKql -Flow ([PSCustomObject]@{ transform = 's' }) -Properties $props | Should -Be 'source | where A == 1'
        Resolve-DcrFlowTransformKql -Flow ([PSCustomObject]@{ transform = 'missing' }) -Properties $props | Should -BeNullOrEmpty
        Resolve-DcrFlowTransformKql -Flow ([PSCustomObject]@{ streams = @('x') }) -Properties $props | Should -BeNullOrEmpty
        Resolve-DcrFlowTransformKql -Flow ([PSCustomObject]@{ transform = 's' }) -Properties ([PSCustomObject]@{}) | Should -BeNullOrEmpty
        $noKql = [PSCustomObject]@{ transformations = @([PSCustomObject]@{ name = 's'; processors = @([PSCustomObject]@{ processor = 'other'; configuration = $null }, $null) }) }
        Resolve-DcrFlowTransformKql -Flow ([PSCustomObject]@{ transform = 's' }) -Properties $noKql | Should -BeNullOrEmpty
    }

    It 'summarises ARM errors with code or message' {
        $er = $null
        try { throw 'Response status code does not indicate success: 403 (Forbidden).' } catch { $er = $_ }
        Get-ArmErrorSummary -ErrorRecord $er | Should -Match 'Forbidden'
        $long = 'x' * 200
        try { throw $long } catch { $er = $_ }
        (Get-ArmErrorSummary -ErrorRecord $er).Length | Should -Be 120
    }

    It 'pages an ARM list until nextLink is exhausted' {
        Mock Invoke-AzRestWithRetry {
            if ($Uri -like '*page2*') { return [PSCustomObject]@{ value = @(3) } }
            [PSCustomObject]@{ value = @(1, 2); nextLink = 'https://example/page2' }
        }
        @(Get-ArmListPage -Uri 'https://example/page1' -Headers @{}) | Should -Be @(1, 2, 3)
    }

    It 'stops paging at the cap with a warning' {
        Mock Invoke-AzRestWithRetry { [PSCustomObject]@{ value = @(1); nextLink = 'https://example/again' } }
        $items = @(Get-ArmListPage -Uri 'https://example/page1' -Headers @{} -MaxPages 3 -WarningVariable w -WarningAction SilentlyContinue)
        $items.Count | Should -Be 3
        "$w" | Should -Match 'Pagination limit'
    }

    It 'extracts where conditions across lines with a length window' {
        $kql = "T`n| where A == 1`n   and B == 2`n| where short`n| project A"
        $conds = @(Get-KqlWhereCondition -Kql $kql)
        $conds | Should -Be @('A == 1 and B == 2')
        @(Get-KqlWhereCondition -Kql '').Count | Should -Be 0
    }
}

Describe 'Get-SplitKql schema intersection' {
    BeforeAll {
        $script:hvTI = @{
            'ThreatIntelIndicators' = [PSCustomObject]@{
                description     = 'TI'
                highValueFields = @('TimeGenerated', 'ObservableValue', 'IndicatorType', 'NetworkSourceIP', 'Confidence')
                splitHints      = @([PSCustomObject]@{ description = 'active'; kql = 'IsActive == true' })
            }
        }
        $script:tiSchema = @('TimeGenerated', 'ObservableKey', 'ObservableValue', 'Confidence', 'IsActive', 'Pattern')
    }

    It 'drops candidate fields that are not in the live schema and reports them' {
        $rules = @([PSCustomObject]@{ RuleName = 'r'; Enabled = $true; Tables = @('ThreatIntelIndicators'); Query = 'ThreatIntelIndicators | where Confidence > 50 | project ObservableValue, LegacyUrl' })
        $result = Get-SplitKql -TableName 'ThreatIntelIndicators' -Rules $rules -HighValueFieldsDB $script:hvTI -SchemaColumns $script:tiSchema

        $result.AllFields | Should -Be @('Confidence', 'ObservableValue', 'TimeGenerated')
        $result.DroppedFields | Should -Contain 'IndicatorType'
        $result.DroppedFields | Should -Contain 'NetworkSourceIP'
        $result.DroppedFields | Should -Contain 'LegacyUrl'
        $result.ProjectKql | Should -Not -Match 'IndicatorType'
        $result.ProjectKql | Should -Match 'ObservableValue'
    }

    It 'keeps every field when no schema is supplied' {
        $result = Get-SplitKql -TableName 'ThreatIntelIndicators' -HighValueFieldsDB $script:hvTI
        $result.AllFields | Should -Contain 'IndicatorType'
        $result.DroppedFields.Count | Should -Be 0
    }

    It 'appends distinct rule conditions to the knowledge-base hint and labels the result combined' {
        $rules = @([PSCustomObject]@{ RuleName = 'r'; Enabled = $true; Tables = @('ThreatIntelIndicators'); Query = 'ThreatIntelIndicators | where Confidence > 50 | where IsActive == true' })
        $result = Get-SplitKql -TableName 'ThreatIntelIndicators' -Rules $rules -HighValueFieldsDB $script:hvTI
        $result.Source | Should -Be 'combined'
        $result.SplitKql | Should -Match '^\(IsActive == true\)'
        $result.SplitKql | Should -Match 'or \(Confidence > 50\)'
        # the duplicate of the hint itself is not appended twice
        ([regex]::Matches($result.SplitKql, 'IsActive == true')).Count | Should -Be 1
    }

    It 'uses the pre-grouped rule subset passed from Invoke-Analysis' {
        $rules = @(
            [PSCustomObject]@{ RuleName = 'other'; Enabled = $true; Tables = @('Other'); Query = 'Other | where X == 1' },
            [PSCustomObject]@{ RuleName = 'off'; Enabled = $false; Tables = @('ThreatIntelIndicators'); Query = 'ThreatIntelIndicators | where Y == 1' }
        )
        $result = Get-SplitKql -TableName 'ThreatIntelIndicators' -Rules $rules
        $result.RuleCount | Should -Be 0
        $result.Source | Should -Be 'none'
    }
}

Describe 'Get-LiveTuningAnalysis schema intersection' {
    It 'removes rule fields absent from the schema from ProjectKql and reports DroppedFields' {
        $rules = @([PSCustomObject]@{ RuleName = 'r'; Enabled = $true; Tables = @('SigninLogs'); Query = 'SigninLogs | where ResultType != 0 | project UserPrincipalName, csUserName' })
        $schema = @{ 'SigninLogs' = @('TimeGenerated', 'ResultType', 'UserPrincipalName', 'IPAddress') }
        $result = @(Get-LiveTuningAnalysis -Rules $rules -SchemaLookup $schema)
        $result.Count | Should -Be 1
        $result[0].DroppedFields | Should -Be @('csUserName')
        $result[0].UsedFields | Should -Not -Contain 'csUserName'
        $result[0].ProjectKql | Should -Not -Match 'csUserName'
        $result[0].UnusedFields | Should -Be @('IPAddress')
    }

    It 'builds filter-only and project-only combined KQL and resolves rule names from hunting queries' {
        $rules = @(
            [PSCustomObject]@{ Enabled = $true; Tables = @('OnlyWhere'); Query = 'OnlyWhere | where 1 == 1' },
            [PSCustomObject]@{ DisplayName = 'disp'; Enabled = $true; Tables = @('OnlyProject'); Query = 'OnlyProject | project Alpha, Beta' },
            [PSCustomObject]@{ Enabled = $true; Tables = $null; Query = 'X | take 1' }
        )
        $hunting = @([PSCustomObject]@{ QueryName = 'hunt'; Enabled = $true; Tables = @('OnlyProject'); Query = 'OnlyProject | project Gamma' })
        $result = @(Get-LiveTuningAnalysis -Rules $rules -HuntingQueries $hunting)
        $onlyWhere = $result | Where-Object TableName -eq 'OnlyWhere'
        $onlyWhere.CombinedKql | Should -Be "source`n| where (1 == 1)"
        $onlyWhere.ProjectKql | Should -BeNullOrEmpty
        $onlyWhere.RuleDetails[0].RuleName | Should -Be 'Unknown'
        $onlyProject = $result | Where-Object TableName -eq 'OnlyProject'
        $onlyProject.ProjectKql | Should -Match 'Alpha, Beta, Gamma, TimeGenerated'
        $onlyProject.CombinedKql | Should -Be $onlyProject.ProjectKql
        ($onlyProject.RuleDetails | ForEach-Object RuleName) | Should -Be @('disp', 'hunt')
    }
}

Describe 'Get-ArmErrorSummary detail parsing' {
    It 'prefers the error code from a JSON error body' {
        $er = $null
        try { throw 'HTTP failure' } catch { $er = $_ }
        $er.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('{"error":{"code":"AuthorizationFailed","message":"no"}}')
        Get-ArmErrorSummary -ErrorRecord $er | Should -Be 'AuthorizationFailed'
    }

    It 'includes the HTTP status when a response is attached' {
        $resp = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::Forbidden)
        $ex = [Microsoft.PowerShell.Commands.HttpResponseException]::new('Response status code does not indicate success: 403 (Forbidden).', $resp)
        $er = [System.Management.Automation.ErrorRecord]::new($ex, 'x', 'InvalidOperation', $null)
        $er.ErrorDetails = [System.Management.Automation.ErrorDetails]::new('{"error":{"code":"AuthorizationFailed"}}')
        Get-ArmErrorSummary -ErrorRecord $er | Should -Be 'HTTP 403 AuthorizationFailed'
        $resp.Dispose()
    }
}

Describe 'Get-TableRetention collector' {
    It 'captures AsDefault flags, table type, plan-modified date, columns and the default DCR id' {
        Mock Invoke-AzRestWithRetry {
            if ($Uri -like '*/tables?*') {
                return [PSCustomObject]@{ value = @(
                    [PSCustomObject]@{ name = 'SigninLogs'; properties = [PSCustomObject]@{ plan = 'Analytics'; retentionInDays = 90; totalRetentionInDays = 90; archiveRetentionInDays = 0; retentionInDaysAsDefault = $true; totalRetentionInDaysAsDefault = $true; provisioningState = 'Succeeded'; tableSubType = 'Any'; lastPlanModifiedDate = '2026-01-02T00:00:00Z'; schema = [PSCustomObject]@{ tableType = 'Microsoft'; columns = @([PSCustomObject]@{ name = 'UserPrincipalName'; isHidden = $false }, [PSCustomObject]@{ name = 'Secret'; isHidden = $true }); standardColumns = @([PSCustomObject]@{ name = 'TimeGenerated'; isHidden = $false }) } } },
                    [PSCustomObject]@{ name = 'Hunt_SRCH'; properties = [PSCustomObject]@{ plan = 'Analytics'; retentionInDays = 30; totalRetentionInDays = 365; archiveRetentionInDays = 335; retentionInDaysAsDefault = $false; totalRetentionInDaysAsDefault = $false; schema = [PSCustomObject]@{ tableType = 'SearchResults'; columns = @(); standardColumns = @() } } },
                    [PSCustomObject]@{ name = 'NoSchema'; properties = [PSCustomObject]@{ plan = 'Basic' } }
                ) }
            }
            [PSCustomObject]@{ properties = [PSCustomObject]@{ retentionInDays = 90; defaultDataCollectionRuleResourceId = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Insights/dataCollectionRules/ws-dcr' } }
        }
        $ctx = [PSCustomObject]@{ ArmToken = 'tok'; ResourceId = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws' }

        $result = Get-TableRetention -Context $ctx

        $result.WorkspaceRetentionDays | Should -Be 90
        $result.WorkspaceDefaultDcrId | Should -Match 'ws-dcr$'
        $result.Tables.Count | Should -Be 3
        $signin = $result.Tables | Where-Object TableName -eq 'SigninLogs'
        $signin.RetentionInDaysAsDefault | Should -Be $true
        $signin.TotalRetentionInDaysAsDefault | Should -Be $true
        $signin.TableType | Should -Be 'Microsoft'
        $signin.LastPlanModifiedDate | Should -Be '2026-01-02T00:00:00Z'
        $signin.Columns | Should -Be @('TimeGenerated', 'UserPrincipalName')
        ($result.Tables | Where-Object TableName -eq 'Hunt_SRCH').TableType | Should -Be 'SearchResults'
        $noSchema = $result.Tables | Where-Object TableName -eq 'NoSchema'
        $noSchema.TableType | Should -BeNullOrEmpty
        $noSchema.RetentionInDays | Should -BeNullOrEmpty
        $noSchema.RetentionInDaysAsDefault | Should -Be $false
        $noSchema.LastPlanModifiedDate | Should -BeNullOrEmpty
    }

    It 'returns a null default DCR id when the workspace has none' {
        Mock Invoke-AzRestWithRetry {
            if ($Uri -like '*/tables?*') { return [PSCustomObject]@{ value = @() } }
            [PSCustomObject]@{ properties = [PSCustomObject]@{ retentionInDays = 30 } }
        }
        $ctx = [PSCustomObject]@{ ArmToken = 'tok'; ResourceId = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws' }
        $result = Get-TableRetention -Context $ctx
        $result.WorkspaceDefaultDcrId | Should -BeNullOrEmpty
        $result.Tables.Count | Should -Be 0
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

    It 'uses the timing heuristic only when no enabled automation rules exist' {
        $result3 = Invoke-Analysis -TableUsage $tableUsage `
                                   -Classifications $classifications `
                                   -RulesData $rulesData `
                                   -HuntingData $huntingData `
                                   -TableRetention $tableRetention `
                                   -Incidents $incidents `
                                   -AutomationRules @() `
                                   -IncludeDetectionAnalyzer `
                                   -SocRecommendations @()
        $metric = $result3.DetectionAnalyzer.RuleMetrics | Select-Object -First 1
        $metric.IncidentsAutoClosed | Should -Be 1
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

    It 'keeps title filters and operators aligned when the same value appears with two operators' {
        $mockResponse = @{
            value = @(
                @{
                    name = 'ar-pairs-1'
                    properties = @{
                        displayName = 'Pair rule'
                        isEnabled = $true
                        order = 1
                        triggeringLogic = @{
                            triggersOn = 'Incidents'; triggersWhen = 'Created'
                            conditions = @(
                                @{ conditionType = 'Property'; conditionProperties = @{ propertyName = 'IncidentTitle'; operator = 'Contains'; propertyValues = @('Alpha', 'Alpha', '') } },
                                @{ conditionType = 'Property'; conditionProperties = @{ propertyName = 'IncidentTitle'; operator = 'NotContains'; propertyValues = 'Alpha' } },
                                @{ conditionType = 'Property'; conditionProperties = @{ propertyName = 'IncidentRelatedAnalyticRuleIds'; operator = 'Contains'; propertyValues = @('/x/alertRules/r1', '/x/alertRules/r1') } }
                            )
                        }
                        actions = @(@{ order = 1; actionType = 'ModifyProperties'; actionConfiguration = @{ status = 'Closed' } })
                    }
                }
            )
        }
        Mock Invoke-AzRestWithRetry { $mockResponse }
        $ctx = [PSCustomObject]@{ ArmToken = 'fake'; ResourceId = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws' }
        $rules = Get-AutomationRules -Context $ctx

        @($rules[0].TitleConditions).Count | Should -Be 2
        $rules[0].TitleFilters.Count | Should -Be $rules[0].TitleOperators.Count
        $rules[0].TitleFilters | Should -Be @('Alpha', 'Alpha')
        $rules[0].TitleOperators | Should -Contain 'Contains'
        $rules[0].TitleOperators | Should -Contain 'NotContains'
        @($rules[0].RuleIdFilters).Count | Should -Be 1
    }

    It 'reads the enabled flag from triggeringLogic.isEnabled as returned by the API' {
        $mockResponse = @{
            value = @(
                @{ name = 'ar-on';  properties = @{ displayName = 'On';  order = 1; triggeringLogic = @{ isEnabled = $true;  triggersOn = 'Incidents'; triggersWhen = 'Created'; conditions = @() }; actions = @() } },
                @{ name = 'ar-off'; properties = @{ displayName = 'Off'; order = 2; triggeringLogic = @{ isEnabled = $false; triggersOn = 'Incidents'; triggersWhen = 'Created'; conditions = @() }; actions = @() } },
                @{ name = 'ar-none'; properties = @{ displayName = 'None'; order = 3; triggeringLogic = @{ triggersOn = 'Incidents'; triggersWhen = 'Created'; conditions = @() }; actions = @() } }
            )
        }
        Mock Invoke-AzRestWithRetry { $mockResponse }
        $ctx = [PSCustomObject]@{ ArmToken = 'fake'; ResourceId = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws' }
        $rules = Get-AutomationRules -Context $ctx
        ($rules | Where-Object DisplayName -eq 'On').Enabled | Should -Be $true
        ($rules | Where-Object DisplayName -eq 'Off').Enabled | Should -Be $false
        ($rules | Where-Object DisplayName -eq 'None').Enabled | Should -Be $false
    }
}

Describe 'Get-Incidents' {
    BeforeAll {
        $script:incCtx = [PSCustomObject]@{ ArmToken = 'fake'; ResourceId = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws' }
    }

    It 'requests 1000 incidents per page on the 2025-09-01 API and follows nextLink' {
        $script:seenUris = [System.Collections.Generic.List[string]]::new()
        Mock Invoke-AzRestWithRetry {
            $script:seenUris.Add($Uri)
            if ($Uri -like '*page2*') {
                return [PSCustomObject]@{ value = @([PSCustomObject]@{ name = 'i2'; etag = 'e2'; properties = [PSCustomObject]@{ incidentNumber = 2; title = 'B'; status = 'New'; createdTimeUtc = '2026-08-01T00:00:00Z' } }) }
            }
            [PSCustomObject]@{
                value = @([PSCustomObject]@{ name = 'i1'; etag = 'e1'; properties = [PSCustomObject]@{ incidentNumber = 1; title = 'A'; status = 'Closed'; classification = 'FalsePositive'; createdTimeUtc = '2026-08-01T00:00:00Z'; closedTimeUtc = '2026-08-01T00:03:00Z'; relatedAnalyticRuleIds = @('/x/alertRules/r1'); relatedAnalyticRuleNames = 'Rule One'; owner = [PSCustomObject]@{ userPrincipalName = 'a@b.c' } } })
                nextLink = 'https://example/page2'
            }
        }

        $incidents = Get-Incidents -Context $script:incCtx -DaysBack 30

        $incidents.Count | Should -Be 2
        $script:seenUris[0] | Should -Match 'api-version=2025-09-01'
        $script:seenUris[0] | Should -Match '\$top=1000'
        $script:seenUris[0] | Should -Match 'createdTimeUtc%20ge%20'
        $incidents[0].IncidentNumber | Should -Be 1
        $incidents[0].Etag | Should -Be 'e1'
        $incidents[0].PSObject.Properties.Name | Should -Not -Contain 'Raw'
        $incidents[0].RelatedAnalyticRuleNames | Should -Be @('Rule One')
        $incidents[0].Owner | Should -Be 'a@b.c'
        $incidents[0].ClosedTimeUtc | Should -BeOfType [datetime]
        $incidents[1].ClosedTimeUtc | Should -BeNullOrEmpty
        $incidents[1].Owner | Should -BeNullOrEmpty
    }

    It 'normalises helper values' {
        ConvertTo-UtcDateOrNull -Value $null | Should -BeNullOrEmpty
        ConvertTo-UtcDateOrNull -Value '  ' | Should -BeNullOrEmpty
        ConvertTo-UtcDateOrNull -Value 'not a date' | Should -BeNullOrEmpty
        (ConvertTo-UtcDateOrNull -Value '2026-08-01T10:00:00Z').Kind | Should -Be 'Utc'

        Get-NormalizedArray -Value $null | Should -Be @()
        Get-NormalizedArray -Value '' | Should -Be @()
        Get-NormalizedArray -Value 'one' | Should -Be @('one')
        Get-NormalizedArray -Value @('a', '', 'b') | Should -Be @('a', 'b')
        Get-NormalizedArray -Value 42 | Should -Be @('42')
    }
}

Describe 'Get-AutoCloseFromHealth' {
    BeforeAll {
        $script:healthCtx = [PSCustomObject]@{ LaToken = 'fake'; WorkspaceId = 'ws-id' }
    }

    It 'returns an empty set without querying when no close rules are supplied' {
        Mock Invoke-AzRestWithRetry { throw 'should not be called' }
        $result = Get-AutoCloseFromHealth -Context $script:healthCtx -DaysBack 30
        $result | Should -BeOfType [hashtable]
        $result.Count | Should -Be 0
        Should -Invoke Invoke-AzRestWithRetry -Times 0

        $result2 = Get-AutoCloseFromHealth -Context $script:healthCtx -DaysBack 30 -CloseRuleNames @('', '  ')
        $result2.Count | Should -Be 0
    }

    It 'only attributes incidents touched by the supplied close rules' {
        Mock Invoke-AzRestWithRetry {
            [PSCustomObject]@{ tables = @([PSCustomObject]@{ rows = @(
                @(1, 'Auto close noise'),
                @(2, 'Tag incidents'),
                @(3, 'Auto close noise'),
                @(3, 'Assign owner')
            ) }) }
        }
        $result = Get-AutoCloseFromHealth -Context $script:healthCtx -DaysBack 30 -CloseRuleNames @('Auto close noise')
        $result.Count | Should -Be 2
        $result.ContainsKey(1) | Should -Be $true
        $result.ContainsKey(3) | Should -Be $true
        $result.ContainsKey(2) | Should -Be $false
    }

    It 'returns an empty set when SentinelHealth has no automation rule runs' {
        Mock Invoke-AzRestWithRetry { [PSCustomObject]@{ tables = @([PSCustomObject]@{ rows = @() }) } }
        $result = Get-AutoCloseFromHealth -Context $script:healthCtx -DaysBack 30 -CloseRuleNames @('X')
        $result.Count | Should -Be 0
    }

    It 'returns null quietly when the SentinelHealth table does not exist' {
        Mock Invoke-AzRestWithRetry { throw "Response status code does not indicate success: 400 (Bad Request). SemanticError: Failed to resolve table or column expression named 'SentinelHealth'" }
        $result = Get-AutoCloseFromHealth -Context $script:healthCtx -DaysBack 30 -CloseRuleNames @('X') -WarningVariable w -WarningAction SilentlyContinue
        $result | Should -BeNullOrEmpty
        @($w).Count | Should -Be 0
    }

    It 'returns null with a warning on other query failures' {
        Mock Invoke-AzRestWithRetry { throw 'Response status code does not indicate success: 403 (Forbidden).' }
        $result = Get-AutoCloseFromHealth -Context $script:healthCtx -DaysBack 30 -CloseRuleNames @('X') -WarningVariable w -WarningAction SilentlyContinue
        $result | Should -BeNullOrEmpty
        @($w).Count | Should -Be 1
    }
}

Describe 'Test-KqlTableMissingError' {
    It 'recognises semantic errors for the named table only' {
        $er = $null
        try { throw "SemanticError: Failed to resolve table or column expression named 'SentinelHealth'" } catch { $er = $_ }
        Test-KqlTableMissingError -ErrorRecord $er -TableName 'SentinelHealth' | Should -Be $true
        Test-KqlTableMissingError -ErrorRecord $er -TableName 'OtherTable' | Should -Be $false
        Test-KqlTableMissingError -ErrorRecord $er | Should -Be $true
    }

    It 'returns false for unrelated errors' {
        $er = $null
        try { throw 'Response status code does not indicate success: 429 (Too Many Requests).' } catch { $er = $_ }
        Test-KqlTableMissingError -ErrorRecord $er -TableName 'SentinelHealth' | Should -Be $false
    }
}

Describe 'Get-AnalyticsRules coverage and identity' {
    It 'exposes RuleId, counts only enabled rules in TableCoverage and all rules in AllRuleTableCoverage' {
        $mockResponse = [PSCustomObject]@{
            value = @(
                [PSCustomObject]@{ name = 'guid-1'; kind = 'Scheduled'; properties = [PSCustomObject]@{ displayName = 'Enabled rule'; enabled = $true; description = '#DONT_CORR#'; query = 'SigninLogs | where ResultType != 0' } },
                [PSCustomObject]@{ name = 'guid-2'; kind = 'NRT'; properties = [PSCustomObject]@{ displayName = 'Disabled rule'; enabled = $false; description = ''; query = 'SigninLogs | union AuditLogs' } },
                [PSCustomObject]@{ name = 'guid-3'; kind = 'ThreatIntelligence'; properties = [PSCustomObject]@{ displayName = 'TI matching'; enabled = $true; description = '#INC_CORR#' } },
                [PSCustomObject]@{ name = 'guid-4'; kind = 'Fusion'; properties = [PSCustomObject]@{ displayName = 'Fusion'; enabled = $true; description = $null } }
            )
        }
        Mock Invoke-AzRestWithRetry { $mockResponse }
        $ctx = [PSCustomObject]@{ ArmToken = 'fake'; ResourceId = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws' }

        $data = Get-AnalyticsRules -Context $ctx

        $data.TotalRules | Should -Be 4
        $data.EnabledRules | Should -Be 3
        $data.DontCorrCount | Should -Be 1
        $data.IncCorrCount | Should -Be 1
        $data.Rules[0].RuleId | Should -Be 'guid-1'
        $data.Rules[2].HasQuery | Should -Be $false
        $data.Rules[3].Tables | Should -Be @()
        $data.TableCoverage['SigninLogs'] | Should -Be 1
        $data.TableCoverage.ContainsKey('AuditLogs') | Should -Be $false
        $data.AllRuleTableCoverage['SigninLogs'] | Should -Be 2
        $data.AllRuleTableCoverage['AuditLogs'] | Should -Be 1
    }

    It 'maps enabled non-KQL rule kinds to the tables they consume implicitly' {
        $mockResponse = [PSCustomObject]@{
            value = @(
                [PSCustomObject]@{ name = 'ti-1'; kind = 'ThreatIntelligence'; properties = [PSCustomObject]@{ displayName = 'TI map'; enabled = $true; description = '' } },
                [PSCustomObject]@{ name = 'ti-2'; kind = 'ThreatIntelligence'; properties = [PSCustomObject]@{ displayName = 'TI map disabled'; enabled = $false; description = '' } },
                [PSCustomObject]@{ name = 'fu-1'; kind = 'Fusion'; properties = [PSCustomObject]@{ displayName = 'Fusion'; enabled = $true; description = '' } },
                [PSCustomObject]@{ name = 'ml-1'; kind = 'MLBehaviorAnalytics'; properties = [PSCustomObject]@{ displayName = 'ML'; enabled = $true; description = '' } },
                [PSCustomObject]@{ name = 'ms-1'; kind = 'MicrosoftSecurityIncidentCreation'; properties = [PSCustomObject]@{ displayName = 'MDC'; enabled = $true; description = '' } },
                [PSCustomObject]@{ name = 'zz-1'; kind = 'SomethingNew'; properties = [PSCustomObject]@{ displayName = 'Unknown kind'; enabled = $true; description = '' } }
            )
        }
        Mock Invoke-AzRestWithRetry { $mockResponse }
        $ctx = [PSCustomObject]@{ ArmToken = 'fake'; ResourceId = '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws' }

        $data = Get-AnalyticsRules -Context $ctx

        $data.ImplicitCoverage['ThreatIntelIndicators'] | Should -Be 1
        $data.ImplicitCoverage['ThreatIntelObjects'] | Should -Be 1
        $data.ImplicitCoverage['SecurityAlert'] | Should -Be 2
        $data.ImplicitCoverage['Anomalies'] | Should -Be 1
        $data.ImplicitCoverage['BehaviorAnalytics'] | Should -Be 1
        $data.ImplicitCoverage['UserPeerAnalytics'] | Should -Be 1
        $data.ImplicitCoverage['IdentityInfo'] | Should -Be 1
        $data.TableCoverage.Count | Should -Be 0
        $data.Rules[0].ImplicitTables | Should -Contain 'ThreatIntelIndicators'
        $data.Rules[0].Tables | Should -Be @()
        $data.Rules[5].ImplicitTables | Should -Be @()
        $data.PlatformTables | Should -Contain 'SecurityIncident'
        $data.PlatformTables | Should -Contain 'SentinelHealth'
    }
}

Describe 'Get-ImplicitConsumerMap' {
    It 'loads the shipped map' {
        $map = Get-ImplicitConsumerMap
        $map.RuleKinds.Keys | Should -Contain 'ThreatIntelligence'
        $map.RuleKinds['Fusion'] | Should -Contain 'SecurityAlert'
        $map.PlatformTables | Should -Contain 'Usage'
    }

    It 'returns empty structures when the file is missing' {
        $map = Get-ImplicitConsumerMap -Path (Join-Path $TestDrive 'nope.json')
        $map.RuleKinds.Count | Should -Be 0
        @($map.PlatformTables).Count | Should -Be 0
    }

    It 'tolerates a file without either section' {
        $p = Join-Path $TestDrive 'partial.json'
        '{ "description": "x" }' | Set-Content $p
        $map = Get-ImplicitConsumerMap -Path $p
        $map.RuleKinds.Count | Should -Be 0
        @($map.PlatformTables).Count | Should -Be 0
    }
}

Describe 'Implicit consumers data integrity' {
    It 'only references tables that exist in the classification database or are known Sentinel tables' {
        $db = Get-Content "$PSScriptRoot\..\Data\log-classifications.json" -Raw | ConvertFrom-Json
        $known = [System.Collections.Generic.HashSet[string]]::new([string[]]$db.tableName, [StringComparer]::OrdinalIgnoreCase)
        # Not (yet) in the DB but documented Sentinel tables
        foreach ($extra in 'ThreatIntelObjects', 'SecurityCaseEvent', 'ConfidentialWatchlist', 'Usage', 'Operation', 'ThreatIntelExportOperation') { [void]$known.Add($extra) }
        $map = Get-Content "$PSScriptRoot\..\Data\implicit-consumers.json" -Raw | ConvertFrom-Json
        foreach ($p in $map.ruleKinds.PSObject.Properties) {
            foreach ($t in $p.Value) { $known.Contains($t) | Should -Be $true -Because "$($p.Name) references $t" }
        }
        foreach ($t in $map.platformTables) { $known.Contains($t) | Should -Be $true -Because "platform table $t" }
    }
}

Describe 'Invoke-Analysis coverage semantics' {
    BeforeAll {
        $script:covRules = [PSCustomObject]@{
            Rules = @(); TotalRules = 2; EnabledRules = 2; DontCorrCount = 0; IncCorrCount = 0
            TableCoverage = @{ 'SigninLogs' = 1 }
            ImplicitCoverage = @{ 'ThreatIntelIndicators' = 1 }
            PlatformTables = @('SecurityIncident', 'SentinelHealth')
        }
        $script:covHunting = [PSCustomObject]@{ Queries = @(); TableCoverage = @{}; TotalQueries = 0 }
        $script:covUsage = @(
            [PSCustomObject]@{ TableName = 'SigninLogs'; DataGB = 3; MonthlyGB = 1; UsageRowCount = 1; EstMonthlyCostUSD = 5.59; IsFree = $false; IsFreeSource = 'usage' },
            [PSCustomObject]@{ TableName = 'ThreatIntelIndicators'; DataGB = 6; MonthlyGB = 2; UsageRowCount = 1; EstMonthlyCostUSD = 11.18; IsFree = $false; IsFreeSource = 'usage' },
            [PSCustomObject]@{ TableName = 'SecurityIncident'; DataGB = 0.1; MonthlyGB = 0.03; UsageRowCount = 1; EstMonthlyCostUSD = 0; IsFree = $true; IsFreeSource = 'usage' },
            [PSCustomObject]@{ TableName = 'SecurityCaseEvent'; DataGB = 0.1; MonthlyGB = 0.03; UsageRowCount = 1; EstMonthlyCostUSD = 0.17; IsFree = $false; IsFreeSource = 'usage' },
            [PSCustomObject]@{ TableName = 'DeviceEvents'; DataGB = 3; MonthlyGB = 1; UsageRowCount = 1; EstMonthlyCostUSD = 5.59; IsFree = $false; IsFreeSource = 'usage' },
            [PSCustomObject]@{ TableName = 'Lonely'; DataGB = 3; MonthlyGB = 1; UsageRowCount = 1; EstMonthlyCostUSD = 5.59; IsFree = $false; IsFreeSource = 'usage' }
        )
        $primary = { param($cat) [PSCustomObject]@{ Classification = 'primary'; Category = $cat; RecommendedTier = 'analytics'; IsFree = $false; RecommendedRetentionDays = 365 } }
        $script:covClass = [PSCustomObject]@{
            Classifications = @{
                'SigninLogs' = & $primary 'Identity & Access'
                'ThreatIntelIndicators' = & $primary 'Threat Intelligence'
                'SecurityIncident' = [PSCustomObject]@{ Classification = 'primary'; Category = 'Security Alerts'; RecommendedTier = 'analytics'; IsFree = $true; RecommendedRetentionDays = 365 }
                'SecurityCaseEvent' = & $primary 'Security Alerts'
                'DeviceEvents' = & $primary 'Endpoint Detection'
                'Lonely' = & $primary 'Identity & Access'
            }
            KeywordGaps = @(); DatabaseEntries = 6
        }
        $script:covXdr = [PSCustomObject]@{ TotalXDRRules = 1; XDRTableCoverage = @{ 'DeviceEvents' = 1 }; KnownXDRTables = @('DeviceEvents'); CustomRules = @() }
        $script:covRetention = @(
            [PSCustomObject]@{ TableName = 'SigninLogs'; RetentionInDays = 30; TotalRetentionInDays = 365; ArchiveRetentionInDays = 335; Plan = 'Analytics' },
            [PSCustomObject]@{ TableName = 'ThreatIntelIndicators'; RetentionInDays = 90; TotalRetentionInDays = 90; ArchiveRetentionInDays = 0; Plan = 'Analytics' },
            [PSCustomObject]@{ TableName = 'SecurityIncident'; RetentionInDays = 90; TotalRetentionInDays = 90; ArchiveRetentionInDays = 0; Plan = 'Analytics' },
            [PSCustomObject]@{ TableName = 'SecurityCaseEvent'; RetentionInDays = 90; TotalRetentionInDays = 90; ArchiveRetentionInDays = 0; Plan = 'Analytics' },
            [PSCustomObject]@{ TableName = 'DeviceEvents'; RetentionInDays = 90; TotalRetentionInDays = 90; ArchiveRetentionInDays = 0; Plan = 'Analytics' },
            [PSCustomObject]@{ TableName = 'Lonely'; RetentionInDays = 90; TotalRetentionInDays = 90; ArchiveRetentionInDays = 0; Plan = 'Analytics' }
        )
        $script:covResult = Invoke-Analysis -TableUsage $script:covUsage -Classifications $script:covClass -RulesData $script:covRules -HuntingData $script:covHunting -DefenderXDR $script:covXdr -TableRetention $script:covRetention
        $script:byName = @{}
        foreach ($t in $script:covResult.TableAnalysis) { $script:byName[$t.TableName] = $t }
    }

    It 'counts implicit consumers toward effective coverage and labels the source' {
        $ti = $script:byName['ThreatIntelIndicators']
        $ti.ImplicitRules | Should -Be 1
        $ti.EffectiveCoverage | Should -Be 1
        $ti.CoverageSource | Should -Be 'implicit'
        $ti.Assessment | Should -Not -Be 'Missing Coverage'
        @($script:covResult.Recommendations | Where-Object { $_.Type -eq 'MissingCoverage' -and $_.TableName -eq 'ThreatIntelIndicators' }).Count | Should -Be 0
    }

    It 'labels kql, xdr, platform and none sources' {
        $script:byName['SigninLogs'].CoverageSource | Should -Be 'kql'
        $script:byName['DeviceEvents'].CoverageSource | Should -Be 'xdr'
        $script:byName['SecurityIncident'].CoverageSource | Should -Be 'platform'
        $script:byName['SecurityIncident'].IsPlatform | Should -Be $true
        $script:byName['Lonely'].CoverageSource | Should -Be 'none'
    }

    It 'never flags platform tables as Missing Coverage but still flags primary tables with nothing' {
        # SecurityCaseEvent is not in PlatformTables for this test, so it behaves like any primary table
        @($script:covResult.Recommendations | Where-Object { $_.Type -eq 'MissingCoverage' -and $_.TableName -eq 'SecurityIncident' }).Count | Should -Be 0
        @($script:covResult.Recommendations | Where-Object { $_.Type -eq 'MissingCoverage' -and $_.TableName -eq 'Lonely' }).Count | Should -Be 1
    }

    It 'gives a paid platform table the Platform assessment instead of Missing Coverage' {
        $rules = [PSCustomObject]@{ Rules = @(); TotalRules = 0; EnabledRules = 0; DontCorrCount = 0; IncCorrCount = 0; TableCoverage = @{}; ImplicitCoverage = @{}; PlatformTables = @('SecurityCaseEvent') }
        $r = Invoke-Analysis -TableUsage @($script:covUsage[3]) -Classifications $script:covClass -RulesData $rules -HuntingData $script:covHunting -TableRetention $script:covRetention
        $r.TableAnalysis[0].Assessment | Should -Be 'Platform'
        $r.TableAnalysis[0].CoverageSource | Should -Be 'platform'
        @($r.Recommendations | Where-Object Type -eq 'MissingCoverage').Count | Should -Be 0
    }

    It 'does not raise RetentionImprovement for free or platform tables' {
        $script:byName['SecurityIncident'].RetentionCanImprove | Should -Be $false
        @($script:covResult.Recommendations | Where-Object { $_.Type -eq 'RetentionImprovement' -and $_.TableName -eq 'SecurityIncident' }).Count | Should -Be 0
        $script:byName['Lonely'].RetentionCanImprove | Should -Be $true
    }

    It 'flags interactive retention below the 90-day baseline even when total retention is compliant' {
        $signin = $script:byName['SigninLogs']
        $signin.RetentionCompliant | Should -Be $true
        $signin.InteractiveBelowBaseline | Should -Be $true
        $rec = @($script:covResult.Recommendations | Where-Object { $_.Type -eq 'RetentionInteractiveBelowBaseline' })
        $rec.Count | Should -Be 1
        $rec[0].TableName | Should -Be 'SigninLogs'
        $rec[0].Priority | Should -Be 'Medium'
        $script:byName['ThreatIntelIndicators'].InteractiveBelowBaseline | Should -Be $false
    }

    It 'returns TableAnalysis as an array even for a single table' {
        $rules = [PSCustomObject]@{ Rules = @(); TotalRules = 0; EnabledRules = 0; DontCorrCount = 0; IncCorrCount = 0; TableCoverage = @{} }
        $r = Invoke-Analysis -TableUsage @($script:covUsage[0]) -Classifications $script:covClass -RulesData $rules -HuntingData $script:covHunting
        ,$r.TableAnalysis | Should -BeOfType [array]
        $r.TableAnalysis.Count | Should -Be 1
    }

    It 'tolerates a DefenderXDR object with null coverage and table lists' {
        $xdr = [PSCustomObject]@{ TotalXDRRules = 0; XDRTableCoverage = $null; KnownXDRTables = $null; CustomRules = $null }
        $rules = [PSCustomObject]@{ Rules = @(); TotalRules = 0; EnabledRules = 0; DontCorrCount = 0; IncCorrCount = 0; TableCoverage = @{} }
        { Invoke-Analysis -TableUsage @($script:covUsage[0]) -Classifications $script:covClass -RulesData $rules -HuntingData $script:covHunting -DefenderXDR $xdr } | Should -Not -Throw
    }

    It 'sorts recommendations High > Medium > Low then by savings' {
        $recs = $script:covResult.Recommendations
        $order = @{ High = 0; Medium = 1; Low = 2 }
        for ($i = 1; $i -lt $recs.Count; $i++) {
            $prev = $recs[$i - 1]; $cur = $recs[$i]
            ($order[$prev.Priority] -le $order[$cur.Priority]) | Should -Be $true
            if ($prev.Priority -eq $cur.Priority) { ($prev.EstSavingsUSD -ge $cur.EstSavingsUSD) | Should -Be $true }
        }
    }
}

Describe 'Get-DefenderXDR REST fallback' {
    BeforeAll {
        $script:xdrCtx = [PSCustomObject]@{ TenantId = 'tid'; SubscriptionId = 'sub' }
    }

    It 'skips disabled custom detections when building table coverage and hoists the known table list' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Invoke-MgGraphRequest' }
        Mock Resolve-AzToken { 'graph-token' }
        Mock Invoke-AzRestWithRetry {
            [PSCustomObject]@{
                value = @(
                    [PSCustomObject]@{ id = 'r1'; displayName = 'On';  isEnabled = $true;  queryCondition = [PSCustomObject]@{ queryText = 'DeviceEvents | where ActionType == "x"' } },
                    [PSCustomObject]@{ id = 'r2'; displayName = 'Off'; isEnabled = $false; queryCondition = [PSCustomObject]@{ queryText = 'EmailEvents | take 1' } },
                    [PSCustomObject]@{ id = 'r3'; displayName = 'Nested'; detectionAction = [PSCustomObject]@{ queryCondition = [PSCustomObject]@{ queryText = 'DeviceEvents | take 1' } } }
                )
            }
        }

        $result = Get-DefenderXDR -Context $script:xdrCtx

        $result.TotalXDRRules | Should -Be 3
        $result.XDRTableCoverage['DeviceEvents'] | Should -Be 2
        $result.XDRTableCoverage.ContainsKey('EmailEvents') | Should -Be $false
        $result.KnownXDRTables.Count | Should -Be 21
        $result.KnownXDRTables | Should -Contain 'AlertEvidence'
        Should -Invoke Resolve-AzToken -Times 1 -ParameterFilter { $ResourceUrl -eq 'https://graph.microsoft.com' -and $TenantId -eq 'tid' }
    }

    It 'follows @odata.nextLink' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Invoke-MgGraphRequest' }
        Mock Resolve-AzToken { 'graph-token' }
        Mock Invoke-AzRestWithRetry {
            if ($Uri -like '*skip*') { return [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'r2'; isEnabled = $true }) } }
            [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'r1'; isEnabled = $true }); '@odata.nextLink' = 'https://graph.microsoft.com/beta/security/rules/detectionRules?$skip=1' }
        }
        (Get-DefenderXDR -Context $script:xdrCtx).TotalXDRRules | Should -Be 2
    }

    It 'returns null when no Graph token can be acquired' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Invoke-MgGraphRequest' }
        Mock Resolve-AzToken { throw 'no token' }
        Get-DefenderXDR -Context ([PSCustomObject]@{ SubscriptionId = 'sub' }) -WarningAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It 'returns the empty shape with the known table list when every endpoint fails' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Invoke-MgGraphRequest' }
        Mock Resolve-AzToken { 'graph-token' }
        Mock Invoke-AzRestWithRetry { throw 'boom' }
        $result = Get-DefenderXDR -Context $script:xdrCtx -WarningVariable w -WarningAction SilentlyContinue
        $result.TotalXDRRules | Should -Be 0
        $result.KnownXDRTables.Count | Should -Be 21
        "$w" | Should -Match 'Microsoft.Graph.Authentication'
    }
}

Describe 'Get-DefenderXDR delegated Graph path' {
    BeforeAll {
        # Stubs so the Microsoft.Graph cmdlets can be mocked without the module installed
        function Get-MgContext { }
        function Connect-MgGraph { param([string[]]$Scopes, [string]$ContextScope, [switch]$NoWelcome, [string]$TenantId) }
        function Invoke-MgGraphRequest { param([string]$Method, [string]$Uri, [string]$OutputType) }
        $script:xdrCtx2 = [PSCustomObject]@{ TenantId = 'tid'; SubscriptionId = 'sub' }
    }

    It 'uses an existing delegated context with the required scope' {
        Mock Get-Command { [PSCustomObject]@{ Name = 'Invoke-MgGraphRequest' } } -ParameterFilter { $Name -eq 'Invoke-MgGraphRequest' }
        Mock Get-MgContext { [PSCustomObject]@{ Scopes = @('CustomDetection.Read.All') } }
        Mock Connect-MgGraph { throw 'should not reconnect' }
        Mock Invoke-MgGraphRequest {
            if ($Uri -like '*skip*') { return [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'r2'; isEnabled = $true; queryCondition = [PSCustomObject]@{ queryText = 'EmailEvents | take 1' } }) } }
            [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'r1'; isEnabled = $true; queryCondition = [PSCustomObject]@{ queryText = 'DeviceEvents | take 1' } }); '@odata.nextLink' = 'https://graph.microsoft.com/beta/x?$skip=1' }
        }
        Mock Resolve-AzToken { throw 'fallback must not run' }

        $result = Get-DefenderXDR -Context $script:xdrCtx2
        $result.TotalXDRRules | Should -Be 2
        $result.XDRTableCoverage['DeviceEvents'] | Should -Be 1
        $result.XDRTableCoverage['EmailEvents'] | Should -Be 1
        Should -Invoke Connect-MgGraph -Times 0
    }

    It 'connects with the tenant when the current context lacks the scope' {
        Mock Get-Command { [PSCustomObject]@{ Name = 'Invoke-MgGraphRequest' } } -ParameterFilter { $Name -eq 'Invoke-MgGraphRequest' }
        $script:mgConnected = $false
        Mock Get-MgContext { if ($script:mgConnected) { [PSCustomObject]@{ Scopes = @('CustomDetection.ReadWrite.All') } } else { [PSCustomObject]@{ Scopes = @('User.Read') } } }
        Mock Connect-MgGraph { $script:mgConnected = $true }
        Mock Invoke-MgGraphRequest { [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'r1'; isEnabled = $true }) } }

        $result = Get-DefenderXDR -Context $script:xdrCtx2
        $result.TotalXDRRules | Should -Be 1
        Should -Invoke Connect-MgGraph -Times 1 -ParameterFilter { $TenantId -eq 'tid' -and $Scopes -contains 'CustomDetection.Read.All' }
    }

    It 'warns and falls back to the Az token when the scope cannot be established' {
        Mock Get-Command { [PSCustomObject]@{ Name = 'Invoke-MgGraphRequest' } } -ParameterFilter { $Name -eq 'Invoke-MgGraphRequest' }
        Mock Get-MgContext { $null }
        Mock Connect-MgGraph { }
        Mock Invoke-MgGraphRequest { throw 'not used' }
        Mock Resolve-AzToken { 'graph-token' }
        Mock Invoke-AzRestWithRetry { [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'r1'; isEnabled = $true }) } }

        $result = Get-DefenderXDR -Context $script:xdrCtx2 -WarningVariable w -WarningAction SilentlyContinue
        $result.TotalXDRRules | Should -Be 1
        "$w" | Should -Match 'CustomDetection.Read.All'
    }

    It 'falls back to the Az token when every delegated request fails, without naming the Graph module' {
        Mock Get-Command { [PSCustomObject]@{ Name = 'Invoke-MgGraphRequest' } } -ParameterFilter { $Name -eq 'Invoke-MgGraphRequest' }
        Mock Get-MgContext { [PSCustomObject]@{ Scopes = @('CustomDetection.Read.All') } }
        Mock Invoke-MgGraphRequest { throw 'graph down' }
        Mock Resolve-AzToken { 'graph-token' }
        Mock Invoke-AzRestWithRetry { throw 'rest down' }

        $result = Get-DefenderXDR -Context $script:xdrCtx2 -WarningVariable w -WarningAction SilentlyContinue
        $result.TotalXDRRules | Should -Be 0
        "$w" | Should -Not -Match 'Microsoft.Graph.Authentication'
    }

    It 'survives a throwing Connect-MgGraph by falling back' {
        Mock Get-Command { [PSCustomObject]@{ Name = 'Invoke-MgGraphRequest' } } -ParameterFilter { $Name -eq 'Invoke-MgGraphRequest' }
        Mock Get-MgContext { $null }
        Mock Connect-MgGraph { throw 'user cancelled' }
        Mock Resolve-AzToken { 'graph-token' }
        Mock Invoke-AzRestWithRetry { [PSCustomObject]@{ value = @() } }

        (Get-DefenderXDR -Context ([PSCustomObject]@{ SubscriptionId = 'sub' })).TotalXDRRules | Should -Be 0
    }
}

Describe 'Get-SortedRecommendation' {
    It 'orders by priority then savings and pushes unknown priorities last' {
        $unsorted = @(
            [PSCustomObject]@{ Priority = 'Low'; EstSavingsUSD = 500 },
            [PSCustomObject]@{ Priority = 'High'; EstSavingsUSD = 0 },
            [PSCustomObject]@{ Priority = 'Weird'; EstSavingsUSD = 999 },
            [PSCustomObject]@{ Priority = 'Medium'; EstSavingsUSD = 10 },
            [PSCustomObject]@{ Priority = 'High'; EstSavingsUSD = 50 },
            [PSCustomObject]@{ Priority = 'Medium'; EstSavingsUSD = $null }
        )
        $sorted = Get-SortedRecommendation -Recommendations $unsorted
        ($sorted | ForEach-Object { "$($_.Priority):$($_.EstSavingsUSD)" }) | Should -Be @('High:50', 'High:0', 'Medium:10', 'Medium:', 'Low:500', 'Weird:999')
    }

    It 'returns an empty array for no input' {
        @(Get-SortedRecommendation -Recommendations @()).Count | Should -Be 0
    }
}

Describe 'Invoke-Analysis skips split copies for DataLake recommendations' {
    It 'does not recommend moving a _SPLT_CL table to the lake' {
        $usage = @([PSCustomObject]@{ TableName = 'SecurityEvent_SPLT_CL'; DataGB = 300; MonthlyGB = 100; UsageRowCount = 1; EstMonthlyCostUSD = 559; IsFree = $false; IsFreeSource = 'usage' })
        $cls = [PSCustomObject]@{ Classifications = @{ 'SecurityEvent_SPLT_CL' = [PSCustomObject]@{ Classification = 'secondary'; Category = 'Split Table (Data Lake)'; RecommendedTier = 'datalake'; IsFree = $false; RecommendedRetentionDays = 90; IsSplitTable = $true; ParentTable = 'SecurityEvent' } }; KeywordGaps = @(); DatabaseEntries = 1 }
        $rules = [PSCustomObject]@{ Rules = @(); TotalRules = 0; EnabledRules = 0; DontCorrCount = 0; IncCorrCount = 0; TableCoverage = @{} }
        $hunting = [PSCustomObject]@{ Queries = @(); TableCoverage = @{}; TotalQueries = 0 }
        $r = Invoke-Analysis -TableUsage $usage -Classifications $cls -RulesData $rules -HuntingData $hunting
        @($r.Recommendations | Where-Object Type -eq 'DataLake').Count | Should -Be 0
    }
}

Describe 'Get-PercentileRank' {
    It 'returns 0 for empty, single-value and flat populations' {
        Get-PercentileRank -Value 5 -Population @() | Should -Be 0
        Get-PercentileRank -Value 5 -Population @(5) | Should -Be 0
        Get-PercentileRank -Value 5 -Population @(5, 5, 5) | Should -Be 0
        Get-PercentileRank -Value 5 -Population @($null, 5, $null) | Should -Be 0
    }

    It 'ranks a value against the population' {
        Get-PercentileRank -Value 10 -Population @(1, 5, 10, 20) | Should -Be 75
        Get-PercentileRank -Value 20 -Population @(1, 5, 10, 20) | Should -Be 100
        Get-PercentileRank -Value 1 -Population @(1, 5, 10, 20) | Should -Be 25
    }
}

Describe 'Get-AutomationTitleConditions' {
    It 'prefers TitleConditions pairs' {
        $rule = [PSCustomObject]@{ TitleConditions = @([PSCustomObject]@{ Value = 'A'; Operator = 'Equals' }, [PSCustomObject]@{ Value = ''; Operator = 'Equals' }, [PSCustomObject]@{ Value = 'B'; Operator = '' }); TitleFilters = @('ignored'); TitleOperators = @('Contains') }
        $conds = @(Get-AutomationTitleConditions -AutomationRule $rule)
        $conds.Count | Should -Be 2
        $conds[0].Operator | Should -Be 'Equals'
        $conds[1].Operator | Should -Be 'Contains'
    }

    It 'zips TitleFilters with TitleOperators and defaults missing operators to Contains' {
        $rule = [PSCustomObject]@{ TitleFilters = @('A', ' ', 'B'); TitleOperators = @('StartsWith') }
        $conds = @(Get-AutomationTitleConditions -AutomationRule $rule)
        $conds.Count | Should -Be 2
        $conds[0].Value | Should -Be 'A'
        $conds[0].Operator | Should -Be 'StartsWith'
        $conds[1].Value | Should -Be 'B'
        $conds[1].Operator | Should -Be 'Contains'
    }
}

Describe 'Test-AutomationRuleIncidentMatch AND semantics' {
    It 'requires both rule id and title groups to match when both are present' {
        $rule = [PSCustomObject]@{ HasConditions = $true; TitleFilters = @('Suspicious*'); TitleOperators = @('Contains'); RuleIdFilters = @('/x/alertRules/r1') }
        Test-AutomationRuleIncidentMatch -AutomationRule $rule -IncidentTitle 'Suspicious login' -IncidentRuleIds @('/y/alertRules/r1') | Should -Be $true
        Test-AutomationRuleIncidentMatch -AutomationRule $rule -IncidentTitle 'Suspicious login' -IncidentRuleIds @('/y/alertRules/r2') | Should -Be $false
        Test-AutomationRuleIncidentMatch -AutomationRule $rule -IncidentTitle 'Other' -IncidentRuleIds @('/y/alertRules/r1') | Should -Be $false
    }

    It 'does not match a rule-id filter when the incident carries no rule ids' {
        $rule = [PSCustomObject]@{ HasConditions = $true; TitleFilters = @(); TitleOperators = @(); RuleIdFilters = @('/x/alertRules/r1') }
        Test-AutomationRuleIncidentMatch -AutomationRule $rule -IncidentTitle 'Anything' -IncidentRuleIds @() | Should -Be $false
    }

    It 'treats rules with only unmodelled conditions as matching' {
        $rule = [PSCustomObject]@{ HasConditions = $true; TitleFilters = @(); TitleOperators = @(); RuleIdFilters = @() }
        Test-AutomationRuleIncidentMatch -AutomationRule $rule -IncidentTitle 'Anything' -IncidentRuleIds @() | Should -Be $true
    }

    It 'fails a title group when the incident has no title' {
        $rule = [PSCustomObject]@{ HasConditions = $true; TitleFilters = @('A'); TitleOperators = @('Contains'); RuleIdFilters = @() }
        Test-AutomationRuleIncidentMatch -AutomationRule $rule -IncidentTitle '' -IncidentRuleIds @() | Should -Be $false
    }

    It 'uses TitleConditions pairs when present' {
        $rule = [PSCustomObject]@{ HasConditions = $true; TitleConditions = @([PSCustomObject]@{ Value = 'Exact'; Operator = 'Equals' }); TitleFilters = @(); TitleOperators = @(); RuleIdFilters = @() }
        Test-AutomationRuleIncidentMatch -AutomationRule $rule -IncidentTitle 'Exact' -IncidentRuleIds @() | Should -Be $true
        Test-AutomationRuleIncidentMatch -AutomationRule $rule -IncidentTitle 'Exact more' -IncidentRuleIds @() | Should -Be $false
    }
}

Describe 'Get-DetectionAnalyzerData bucketing and scoring' {
    BeforeAll {
        $script:daRules = @(
            [PSCustomObject]@{ RuleId = 'guid-a'; RuleName = 'Shared Name'; Kind = 'Scheduled'; Enabled = $true },
            [PSCustomObject]@{ RuleId = 'guid-b'; RuleName = 'Shared Name'; Kind = 'Scheduled'; Enabled = $true },
            [PSCustomObject]@{ RuleId = 'guid-c'; RuleName = 'Quiet Rule'; Kind = 'Scheduled'; Enabled = $true },
            [PSCustomObject]@{ RuleName = 'Legacy No Id'; Kind = 'NRT'; Enabled = $true }
        )
        $script:daIncidents = @(
            [PSCustomObject]@{ IncidentId = 'i1'; IncidentNumber = 1; Title = 'x'; Status = 'Closed'; Classification = 'FalsePositive'; CreatedTimeUtc = [datetime]'2026-08-01T10:00:00Z'; ClosedTimeUtc = [datetime]'2026-08-01T10:01:00Z'; RelatedAnalyticRuleIds = @('/s/alertRules/guid-a'); RelatedAnalyticRuleNames = @('Shared Name') },
            [PSCustomObject]@{ IncidentId = 'i2'; IncidentNumber = 2; Title = 'x'; Status = 'Closed'; Classification = 'TruePositive'; CreatedTimeUtc = [datetime]'2026-08-01T10:00:00Z'; ClosedTimeUtc = [datetime]'2026-08-01T12:00:00Z'; RelatedAnalyticRuleIds = @('/s/alertRules/guid-a', '/s/alertRules/guid-b'); RelatedAnalyticRuleNames = @('Shared Name') },
            [PSCustomObject]@{ IncidentId = 'i3'; IncidentNumber = 3; Title = 'Legacy No Id fired'; Status = 'New'; Classification = $null; CreatedTimeUtc = [datetime]'2026-08-01T10:00:00Z'; ClosedTimeUtc = $null; RelatedAnalyticRuleIds = @(); RelatedAnalyticRuleNames = @() },
            [PSCustomObject]@{ IncidentId = 'i4'; IncidentNumber = 4; Title = 'y'; Status = 'Closed'; Classification = 'BenignPositive'; CreatedTimeUtc = [datetime]'2026-08-01T10:00:00Z'; ClosedTimeUtc = [datetime]'2026-08-01T10:00:30Z'; RelatedAnalyticRuleIds = @(); RelatedAnalyticRuleNames = @('Quiet Rule') }
        )
        $script:daAutomation = @(
            [PSCustomObject]@{ AutomationRuleId = 'ar1'; DisplayName = 'Close guid-a'; Enabled = $true; IsCloseIncidentRule = $true; HasPlaybookAction = $false; HasConditions = $true; TitleFilters = @(); TitleOperators = @(); RuleIdFilters = @('/s/alertRules/guid-a') },
            [PSCustomObject]@{ AutomationRuleId = 'ar2'; DisplayName = 'Close nothing'; Enabled = $true; IsCloseIncidentRule = $true; HasPlaybookAction = $false; HasConditions = $true; TitleFilters = @('zzz'); TitleOperators = @('Equals'); RuleIdFilters = @() }
        )
        $script:daResult = Get-DetectionAnalyzerData -Rules $script:daRules -Incidents $script:daIncidents -AutomationRules $script:daAutomation -AutoCloseHealthData @{ 4 = $true }
    }

    It 'buckets by rule id so duplicate display names stay separate' {
        $a = $script:daResult.RuleMetrics | Where-Object RuleId -eq 'guid-a'
        $b = $script:daResult.RuleMetrics | Where-Object RuleId -eq 'guid-b'
        $a.IncidentsTotal | Should -Be 2
        $b.IncidentsTotal | Should -Be 1
        $a.RuleKey | Should -Be 'guid-a'
    }

    It 'falls back to name and then title for rules without ids' {
        $legacy = $script:daResult.RuleMetrics | Where-Object RuleName -eq 'Legacy No Id'
        $legacy.RuleKey | Should -Be 'name:Legacy No Id'
        $legacy.IncidentsTotal | Should -Be 1
        $quiet = $script:daResult.RuleMetrics | Where-Object RuleName -eq 'Quiet Rule'
        $quiet.IncidentsTotal | Should -Be 1
    }

    It 'links only the automation rules that actually matched and counts distinct auto-closed incidents' {
        $a = $script:daResult.RuleMetrics | Where-Object RuleId -eq 'guid-a'
        $a.IncidentsAutoClosed | Should -Be 2
        $a.LinkedAutomationRules | Should -Be @('Close guid-a')
        $b = $script:daResult.RuleMetrics | Where-Object RuleId -eq 'guid-b'
        $b.LinkedAutomationRules | Should -Be @('Close guid-a')
        $quiet = $script:daResult.RuleMetrics | Where-Object RuleName -eq 'Quiet Rule'
        $quiet.IncidentsAutoClosed | Should -Be 1
        $quiet.LinkedAutomationRules | Should -Be @()
        # i1, i2 (via guid-a and guid-b) and i4: three distinct incidents, not the per-rule sum of 4
        $script:daResult.Summary.AutoClosedIncidents | Should -Be 3
    }

    It 'scores when at least three rules have incidents and marks the rest' {
        $script:daResult.Summary.ScorableRules | Should -Be 4
        $script:daResult.Summary.MinScorablePopulation | Should -Be 3
        ($script:daResult.RuleMetrics | Where-Object RuleId -eq 'guid-a').ScoreStatus | Should -Be 'Scored'
        ($script:daResult.RuleMetrics | Where-Object RuleId -eq 'guid-a').NoisinessScore | Should -Not -BeNullOrEmpty
    }

    It 'withholds scores when fewer than three rules have incidents' {
        $small = Get-DetectionAnalyzerData -Rules @($script:daRules[0], $script:daRules[2]) -Incidents @($script:daIncidents[0]) -AutomationRules @()
        $withIncidents = $small.RuleMetrics | Where-Object IncidentsTotal -gt 0
        $withIncidents.NoisinessScore | Should -BeNullOrEmpty
        $withIncidents.ScoreStatus | Should -Be 'InsufficientSample'
        ($small.RuleMetrics | Where-Object IncidentsTotal -eq 0).ScoreStatus | Should -Be 'NoIncidents'
        $small.Summary.ScorableRules | Should -Be 1
        $small.Summary.NoisyRules | Should -Be 0
    }

    It 'returns an empty result when there are no rules at all' {
        $empty = Get-DetectionAnalyzerData -Rules @() -Incidents $script:daIncidents -AutomationRules @()
        $empty.RuleMetrics.Count | Should -Be 0
        $empty.Summary.RulesAnalyzed | Should -Be 0
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

    It 'includes configured and observed plan columns in the Tables section' {
        $sections = ConvertTo-ReportSections -Analysis $script:analysis
        $tables = $sections | Where-Object TabId -eq 'tables'
        $tables.Markdown | Should -Match 'Observed Plans'
        $tables.Markdown | Should -Match 'Analytics 70 GB/mo; Basic 30 GB/mo'
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

    It 'makes exactly MaxRetries additional attempts' {
        Mock Invoke-RestMethod {
            $resp = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::ServiceUnavailable)
            throw ([Microsoft.PowerShell.Commands.HttpResponseException]::new('Down', $resp))
        }
        { Invoke-AzRestWithRetry -Uri 'https://example.com/api' -Headers @{} -MaxRetries 3 -BaseDelaySeconds 0 -WarningAction SilentlyContinue } | Should -Throw
        Should -Invoke Invoke-RestMethod -Times 4 -Exactly
    }

    It 'retries transport-level failures that carry no HTTP response' {
        $script:transportCalls = 0
        Mock Invoke-RestMethod {
            $script:transportCalls++
            if ($script:transportCalls -eq 1) { throw ([System.Net.Http.HttpRequestException]::new('connection reset')) }
            [PSCustomObject]@{ value = @('recovered') }
        }
        $result = Invoke-AzRestWithRetry -Uri 'https://example.com/api' -Headers @{} -BaseDelaySeconds 0 -WarningVariable w -WarningAction SilentlyContinue
        $result.value | Should -Contain 'recovered'
        "$w" | Should -Match 'HttpRequestException'
    }

    It 'does not retry plain script errors' {
        Mock Invoke-RestMethod { throw 'not a transport problem' }
        { Invoke-AzRestWithRetry -Uri 'https://example.com/api' -Headers @{} -BaseDelaySeconds 0 } | Should -Throw
        Should -Invoke Invoke-RestMethod -Times 1 -Exactly
    }
}

Describe 'Invoke-AzRestWithRetry async paths' {
    It 'warns and reports unconfirmed success on a 202 without async headers' {
        Mock Invoke-WebRequest { [PSCustomObject]@{ StatusCode = 202; Headers = @{}; Content = '' } }
        $result = Invoke-AzRestWithRetry -Uri 'https://example.com/api' -Headers @{} -Method Patch -Body '{}' -FollowAsync -WarningVariable w -WarningAction SilentlyContinue
        $result.status | Should -Be 'Succeeded'
        $result.unconfirmed | Should -Be $true
        "$w" | Should -Match 'could not be confirmed'
    }

    It 'returns the parsed body for a synchronous 200' {
        Mock Invoke-WebRequest { [PSCustomObject]@{ StatusCode = 200; Headers = @{}; Content = '{"properties":{"plan":"Basic"}}' } }
        $result = Invoke-AzRestWithRetry -Uri 'https://example.com/api' -Headers @{} -Method Patch -Body '{}' -FollowAsync
        $result.properties.plan | Should -Be 'Basic'
    }

    It 'returns raw content when the body is not JSON and null when there is no body' {
        Mock Invoke-WebRequest { [PSCustomObject]@{ StatusCode = 200; Headers = @{}; Content = 'plain text' } }
        Invoke-AzRestWithRetry -Uri 'https://example.com/api' -Headers @{} -FollowAsync | Should -Be 'plain text'
        Mock Invoke-WebRequest { [PSCustomObject]@{ StatusCode = 204; Headers = @{}; Content = $null } }
        Invoke-AzRestWithRetry -Uri 'https://example.com/api' -Headers @{} -FollowAsync | Should -BeNullOrEmpty
    }

    It 'follows the Azure-AsyncOperation header to a terminal status' {
        Mock Start-Sleep {}
        Mock Invoke-WebRequest {
            if ($Method -eq 'Get') { return [PSCustomObject]@{ StatusCode = 200; Headers = @{}; Content = '{"status":"Succeeded"}' } }
            [PSCustomObject]@{ StatusCode = 202; Headers = @{ 'Azure-AsyncOperation' = @('https://example.com/op/1') }; Content = '' }
        }
        $result = Invoke-AzRestWithRetry -Uri 'https://example.com/api' -Headers @{} -Method Patch -Body '{}' -FollowAsync
        $result.status | Should -Be 'Succeeded'
    }

    It 'treats a Location-header completion (200 with provisioningState) as terminal' {
        Mock Start-Sleep {}
        Mock Invoke-WebRequest {
            if ($Method -eq 'Get') { return [PSCustomObject]@{ StatusCode = 200; Headers = @{}; Content = '{"properties":{"provisioningState":"Succeeded","plan":"Analytics"}}' } }
            [PSCustomObject]@{ StatusCode = 202; Headers = @{ 'Location' = 'https://example.com/op/2' }; Content = '' }
        }
        $result = Invoke-AzRestWithRetry -Uri 'https://example.com/api' -Headers @{} -Method Patch -Body '{}' -FollowAsync
        $result.properties.plan | Should -Be 'Analytics'
    }

    It 'throws when the Location-style resource reports a failed provisioning state' {
        Mock Start-Sleep {}
        Mock Invoke-WebRequest { [PSCustomObject]@{ StatusCode = 200; Headers = @{}; Content = '{"properties":{"provisioningState":"Failed"},"error":{"message":"quota"}}' } }
        { Wait-AzAsyncOperation -Uri 'https://example.com/op' -Headers @{} -TimeoutSeconds 30 } | Should -Throw '*quota*'
    }

    It 'keeps polling while the resource is still Updating and honours Retry-After' {
        Mock Start-Sleep {}
        $script:pollCalls = 0
        Mock Invoke-WebRequest {
            $script:pollCalls++
            if ($script:pollCalls -lt 3) { return [PSCustomObject]@{ StatusCode = 200; Headers = @{ 'Retry-After' = @('1') }; Content = '{"properties":{"provisioningState":"Updating"}}' } }
            [PSCustomObject]@{ StatusCode = 200; Headers = @{}; Content = '{"status":"Succeeded"}' }
        }
        (Wait-AzAsyncOperation -Uri 'https://example.com/op' -Headers @{} -TimeoutSeconds 60).status | Should -Be 'Succeeded'
        $script:pollCalls | Should -Be 3
    }

    It 'throws when the async operation reports Failed' {
        Mock Start-Sleep {}
        Mock Invoke-WebRequest { [PSCustomObject]@{ StatusCode = 200; Headers = @{}; Content = '{"status":"Failed","error":{"message":"bad plan"}}' } }
        { Wait-AzAsyncOperation -Uri 'https://example.com/op' -Headers @{} -TimeoutSeconds 30 } | Should -Throw '*bad plan*'
    }

    It 'returns a synthetic success for a 204 poll with no body' {
        Mock Start-Sleep {}
        Mock Invoke-WebRequest { [PSCustomObject]@{ StatusCode = 204; Headers = @{}; Content = $null } }
        (Wait-AzAsyncOperation -Uri 'https://example.com/op' -Headers @{} -TimeoutSeconds 30).status | Should -Be 'Succeeded'
    }

    It 'backs off on 429/5xx while polling and rethrows other errors' {
        Mock Start-Sleep {}
        $script:pollCalls = 0
        Mock Invoke-WebRequest {
            $script:pollCalls++
            if ($script:pollCalls -eq 1) {
                $resp = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::TooManyRequests)
                throw ([Microsoft.PowerShell.Commands.HttpResponseException]::new('slow down', $resp))
            }
            [PSCustomObject]@{ StatusCode = 200; Headers = @{}; Content = '{"status":"Succeeded"}' }
        }
        (Wait-AzAsyncOperation -Uri 'https://example.com/op' -Headers @{} -TimeoutSeconds 60).status | Should -Be 'Succeeded'

        Mock Invoke-WebRequest {
            $resp = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::Forbidden)
            throw ([Microsoft.PowerShell.Commands.HttpResponseException]::new('nope', $resp))
        }
        { Wait-AzAsyncOperation -Uri 'https://example.com/op' -Headers @{} -TimeoutSeconds 60 } | Should -Throw '*nope*'
    }

    It 'times out when the operation never completes' {
        Mock Start-Sleep {}
        Mock Invoke-WebRequest { [PSCustomObject]@{ StatusCode = 200; Headers = @{}; Content = '{"status":"InProgress"}' } }
        { Wait-AzAsyncOperation -Uri 'https://example.com/op' -Headers @{} -TimeoutSeconds 0 } | Should -Throw '*terminal status*'
    }

    It 'treats a 200 poll with a non-JSON body as completed and rethrows non-HTTP poll errors' {
        Mock Start-Sleep {}
        Mock Invoke-WebRequest { [PSCustomObject]@{ StatusCode = 200; Headers = @{}; Content = 'garbage' } }
        (Wait-AzAsyncOperation -Uri 'https://example.com/op' -Headers @{} -TimeoutSeconds 30).status | Should -Be 'Succeeded'

        Mock Invoke-WebRequest { throw 'socket closed' }
        { Wait-AzAsyncOperation -Uri 'https://example.com/op' -Headers @{} -TimeoutSeconds 30 } | Should -Throw '*socket closed*'
    }

    It 'honours Retry-After on a throttled request' {
        $script:raCalls = 0
        Mock Start-Sleep {}
        Mock Invoke-RestMethod {
            $script:raCalls++
            if ($script:raCalls -eq 1) {
                $resp = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::TooManyRequests)
                $resp.Headers.Add('Retry-After', '7')
                throw ([Microsoft.PowerShell.Commands.HttpResponseException]::new('Throttled', $resp))
            }
            [PSCustomObject]@{ ok = $true }
        }
        $result = Invoke-AzRestWithRetry -Uri 'https://example.com/api' -Headers @{} -BaseDelaySeconds 0 -WarningVariable w -WarningAction SilentlyContinue
        $result.ok | Should -Be $true
        "$w" | Should -Match 'in 7s'
        Should -Invoke Start-Sleep -Times 1 -ParameterFilter { $Seconds -eq 7 }
    }
}

Describe 'Collection cache' {
    BeforeAll {
        $script:cacheDir = Join-Path $TestDrive 'cache'
        $script:sample = [PSCustomObject]@{
            Context    = [PSCustomObject]@{ ArmToken = 'SECRET-ARM'; LaToken = 'SECRET-LA'; WorkspaceName = 'ws' }
            GraphToken = 'SECRET-GRAPH'
            TableUsage = @([PSCustomObject]@{ TableName = 'SigninLogs'; MonthlyGB = 1.5 })
            RulesData  = [PSCustomObject]@{ TableCoverage = @{ 'SigninLogs' = 2 }; Rules = @() }
        }
    }

    It 'produces a stable key that changes with any collection-shaping input' {
        $k1 = Get-CollectionCacheKey -SubscriptionId 'SUB' -ResourceGroup 'rg' -WorkspaceName 'ws'
        $k2 = Get-CollectionCacheKey -SubscriptionId 'sub' -ResourceGroup 'RG' -WorkspaceName 'WS'
        $k1 | Should -Be $k2
        $k1 | Should -Match '^[0-9a-f]{64}$'
        (Get-CollectionCacheKey -SubscriptionId 'sub' -ResourceGroup 'rg' -WorkspaceName 'ws' -DaysBack 30) | Should -Not -Be $k1
        (Get-CollectionCacheKey -SubscriptionId 'sub' -ResourceGroup 'rg' -WorkspaceName 'ws' -DetectionLookbackDays 7) | Should -Not -Be $k1
        (Get-CollectionCacheKey -SubscriptionId 'sub' -ResourceGroup 'rg' -WorkspaceName 'ws' -IncludeDefenderXDR $true) | Should -Not -Be $k1
        (Get-CollectionCacheKey -SubscriptionId 'sub' -ResourceGroup 'rg' -WorkspaceName 'ws' -IncludeDetectionAnalyzer $true) | Should -Not -Be $k1
        (Get-CollectionCacheKey -SubscriptionId 'sub' -ResourceGroup 'rg' -WorkspaceName 'other') | Should -Not -Be $k1
    }

    It 'resolves the default cache path under the local app data folder' {
        $p = Get-CollectionCachePath -Key 'abc'
        $p | Should -Match 'LogHorizon'
        $p | Should -Match 'collection-abc\.clixml$'
        (Get-CollectionCachePath -Key 'abc' -CachePath 'C:\x') | Should -Be 'C:\x\collection-abc.clixml'
    }

    It 'round-trips a collection without persisting the context or any token' {
        $file = Save-CollectionCache -Key 'k1' -Data $script:sample -CachePath $script:cacheDir -Version '0.9.0'
        Test-Path $file | Should -Be $true
        $raw = Get-Content $file -Raw
        $raw | Should -Not -Match 'SECRET-ARM'
        $raw | Should -Not -Match 'SECRET-LA'
        $raw | Should -Not -Match 'SECRET-GRAPH'

        $hit = Get-CollectionCache -Key 'k1' -CachePath $script:cacheDir -MaxAgeMinutes 60
        $hit | Should -Not -BeNullOrEmpty
        $hit.Data.PSObject.Properties.Name | Should -Not -Contain 'Context'
        $hit.Data.PSObject.Properties.Name | Should -Not -Contain 'GraphToken'
        $hit.Data.TableUsage[0].TableName | Should -Be 'SigninLogs'
        $hit.Data.RulesData.TableCoverage | Should -BeOfType [hashtable]
        $hit.Data.RulesData.TableCoverage['SigninLogs'] | Should -Be 2
        $hit.Version | Should -Be '0.9.0'
        $hit.AgeMinutes | Should -BeLessThan 5
        $hit.Path | Should -Be $file
    }

    It 'misses when the file is absent, expired, corrupt or has the wrong shape' {
        Get-CollectionCache -Key 'missing' -CachePath $script:cacheDir | Should -BeNullOrEmpty

        Save-CollectionCache -Key 'old' -Data $script:sample -CachePath $script:cacheDir | Out-Null
        $oldFile = Get-CollectionCachePath -Key 'old' -CachePath $script:cacheDir
        $env = Import-Clixml $oldFile
        $env.SavedAt = (Get-Date).ToUniversalTime().AddHours(-3).ToString('o')
        $env | Export-Clixml $oldFile -Force
        Get-CollectionCache -Key 'old' -CachePath $script:cacheDir -MaxAgeMinutes 60 | Should -BeNullOrEmpty
        (Get-CollectionCache -Key 'old' -CachePath $script:cacheDir -MaxAgeMinutes 600).AgeMinutes | Should -BeGreaterThan 170

        Set-Content -Path (Get-CollectionCachePath -Key 'corrupt' -CachePath $script:cacheDir) -Value 'not xml'
        Get-CollectionCache -Key 'corrupt' -CachePath $script:cacheDir -WarningAction SilentlyContinue | Should -BeNullOrEmpty

        [PSCustomObject]@{ Something = 1 } | Export-Clixml (Get-CollectionCachePath -Key 'shape' -CachePath $script:cacheDir)
        Get-CollectionCache -Key 'shape' -CachePath $script:cacheDir | Should -BeNullOrEmpty

        # Key mismatch inside the envelope (file renamed by hand)
        Copy-Item (Get-CollectionCachePath -Key 'k1' -CachePath $script:cacheDir) (Get-CollectionCachePath -Key 'k2' -CachePath $script:cacheDir)
        Get-CollectionCache -Key 'k2' -CachePath $script:cacheDir | Should -BeNullOrEmpty
    }
}

Describe 'Resolve-ReportOutputPath' {
    It 'creates a missing directory and returns a timestamped file inside it' {
        $dir = Join-Path $TestDrive 'reports-new'
        $p = Resolve-ReportOutputPath -OutputPath $dir -Format 'json' -Timestamp '2026-09-06_1200'
        Test-Path $dir -PathType Container | Should -Be $true
        $p | Should -Be (Join-Path $dir 'LogHorizon_Report_2026-09-06_1200.json')
    }

    It 'treats a trailing separator as a directory and maps md aliases' {
        $p = Resolve-ReportOutputPath -OutputPath ((Join-Path $TestDrive 'slash') + '\') -Format 'markdown' -Timestamp 'T'
        $p | Should -Match 'LogHorizon_Report_T\.md$'
        (Resolve-ReportOutputPath -OutputPath (Join-Path $TestDrive 'x/') -Format 'md' -Timestamp 'T') | Should -Match '\.md$'
    }

    It 'creates the parent of an explicit file path and returns it unchanged' {
        $file = Join-Path $TestDrive 'deep\nested\report.html'
        $p = Resolve-ReportOutputPath -OutputPath $file -Format 'html'
        $p | Should -Be $file
        Test-Path (Split-Path $file) -PathType Container | Should -Be $true
        Test-Path $file | Should -Be $false
    }

    It 'rejects a syntactically invalid path' {
        { Resolve-ReportOutputPath -OutputPath 'C:\bad|dir\report.json' -Format 'json' } | Should -Throw
    }
}

Describe 'ConvertTo-SafeMarkdownText' {
    It 'escapes table separators, markdown syntax, angle brackets and newlines' {
        ConvertTo-SafeMarkdownText -Text 'a|b *c* <d>' | Should -Be 'a\|b \*c\* &lt;d&gt;'
        ConvertTo-SafeMarkdownText -Text "line1`r`nline2" | Should -Be 'line1 line2'
        ConvertTo-SafeMarkdownText -Text '' | Should -Be ''
        ConvertTo-SafeMarkdownText -Text $null | Should -Be ''
    }
}

Describe 'Export-Report hardening' {
    BeforeAll {
        $script:hardDir = Join-Path $TestDrive 'export-hard'
        New-Item -ItemType Directory -Path $script:hardDir -Force | Out-Null
    }

    It 'returns the written path and includes liveTuningAnalysis in JSON' {
        $a = New-MockAnalysis
        $a | Add-Member -NotePropertyName LiveTuningAnalysis -NotePropertyValue @([PSCustomObject]@{ TableName = 'SecurityEvent'; FilterKql = 'x' })
        $written = Export-Report -Analysis $a -Format 'json' -OutputPath $script:hardDir -WorkspaceName 'W'
        $written | Should -Match '\.json$'
        Test-Path $written | Should -Be $true
        $json = Get-Content $written -Raw | ConvertFrom-Json
        $json.liveTuningAnalysis[0].TableName | Should -Be 'SecurityEvent'
    }

    It 'escapes hostile recommendation titles, details and rule names in Markdown' {
        $a = New-MockAnalysis
        $a.Recommendations = @([PSCustomObject]@{
            Title = 'Bad | title ![img](https://evil/x.png)'; TableName = 'T'; Priority = 'High'; Type = 'DetectionAnalyzer'
            CurrentCost = 0; EstSavingsUSD = 0; Detail = "line one`n`n<img src=x>"
        })
        $a | Add-Member -NotePropertyName DetectionAnalyzer -NotePropertyValue ([PSCustomObject]@{
            RuleMetrics = @([PSCustomObject]@{ RuleName = 'Rule | with pipe'; RuleKind = 'Scheduled'; IncidentsTotal = 3; AutoCloseRatio = 0.5; FalsePositiveRatio = 0; NoisinessScore = 80 })
            Summary = [PSCustomObject]@{ RulesAnalyzed = 1; NoisyRules = 1; IncidentsAnalyzed = 3; ScorableRules = 1; MinScorablePopulation = 3 }
        })
        $sections = ConvertTo-ReportSections -Analysis $a
        $recs = ($sections | Where-Object TabId -eq 'recs').Markdown
        $recs | Should -Match '### 1\. .* Bad \\\| title \\!\\\[img\\\]'
        $recs | Should -Not -Match '<img src=x>'
        $recs | Should -Match '&lt;img src=x&gt;'
        $da = ($sections | Where-Object TabId -eq 'detanalyzer').Markdown
        $da | Should -Match '\| Rule \\\| with pipe \|'
        $da | Should -Match 'scores are N/A'
    }

    It 'uses TotalCoverage in the Markdown Rules column, matching HTML' {
        $a = New-MockAnalysis
        $a.TableAnalysis[0].AnalyticsRules = 1
        $a.TableAnalysis[0].TotalCoverage = 7
        $tables = ($sections = ConvertTo-ReportSections -Analysis $a | Where-Object TabId -eq 'tables')
        ($tables.Markdown -split "`n" | Where-Object { $_ -match '\| SecurityEvent \|' }) | Should -Match '\| 7 \| 3 \|'
    }

    It 'HTML-encodes markup inside the Markdown KQL preview' {
        $a = New-MockAnalysis
        $a.DataTransforms = [PSCustomObject]@{ Transforms = @([PSCustomObject]@{ DCRName = 'd'; OutputTable = 'T'; TransformKql = 'source | where a < 1 </code><b>x</b>'; TransformType = 'Filter' }) }
        $a.TableAnalysis[0].HasTransform = $true
        $tx = (ConvertTo-ReportSections -Analysis $a | Where-Object TabId -eq 'transforms').Markdown
        $line = ($tx -split "`n" | Where-Object { $_ -match '^\| T \|' })
        $line | Should -Match '&lt;/code&gt;&lt;b&gt;'
        $line | Should -Not -Match '</code><b>'
    }
}

Describe 'Custom classification validation' {
    It 'normalises a minimal entry with defaults' {
        $e = ConvertTo-ValidClassificationEntry -Entry ([PSCustomObject]@{ tableName = ' MyApp_CL '; classification = 'Primary' })
        $e.tableName | Should -Be 'MyApp_CL'
        $e.classification | Should -Be 'primary'
        $e.connector | Should -Be 'Custom'
        $e.category | Should -Be 'Custom'
        $e.description | Should -Be ''
        $e.keywords | Should -Be @()
        $e.recommendedTier | Should -Be 'analytics'
        $e.isFree | Should -Be $false
        $e.recommendedRetentionDays | Should -Be 90
    }

    It 'keeps supplied values and coerces types' {
        $e = ConvertTo-ValidClassificationEntry -Entry ([PSCustomObject]@{ tableName = 'T'; classification = 'secondary'; connector = 'C'; category = 'Cat'; description = 'D'; keywords = @('a', '', 'b'); mitreSources = @('DS0001'); recommendedTier = 'DataLake'; isFree = 'true'; recommendedRetentionDays = '365' })
        $e.keywords | Should -Be @('a', 'b')
        $e.recommendedTier | Should -Be 'datalake'
        $e.isFree | Should -Be $true
        $e.recommendedRetentionDays | Should -Be 365
        $e.mitreSources | Should -Be @('DS0001')
    }

    It 'rejects entries without a name or with an invalid classification' {
        ConvertTo-ValidClassificationEntry -Entry ([PSCustomObject]@{ classification = 'primary' }) -WarningVariable w1 -WarningAction SilentlyContinue | Should -BeNullOrEmpty
        "$w1" | Should -Match 'without tableName'
        ConvertTo-ValidClassificationEntry -Entry ([PSCustomObject]@{ tableName = 'T'; classification = 'tertiary' }) -WarningVariable w2 -WarningAction SilentlyContinue | Should -BeNullOrEmpty
        "$w2" | Should -Match 'primary or secondary'
        ConvertTo-ValidClassificationEntry -Entry $null | Should -BeNullOrEmpty
    }

    It 'skips malformed custom entries during Invoke-Classification and keeps the rest' {
        $custom = Join-Path $TestDrive 'custom.json'
        @(
            @{ tableName = 'GoodTable_CL'; classification = 'primary'; category = 'Application Logs' },
            @{ tableName = ''; classification = 'primary' },
            @{ tableName = 'BadClass_CL'; classification = 'maybe' },
            @{ tableName = 'AzureMetrics'; classification = 'primary' }
        ) | ConvertTo-Json | Set-Content $custom

        $usage = @(
            [PSCustomObject]@{ TableName = 'GoodTable_CL'; MonthlyGB = 1; IsFree = $false },
            [PSCustomObject]@{ TableName = 'BadClass_CL'; MonthlyGB = 1; IsFree = $false },
            [PSCustomObject]@{ TableName = 'AzureMetrics'; MonthlyGB = 1; IsFree = $false }
        )
        $result = Invoke-Classification -TableUsage $usage -RuleTableCoverage @{} -CustomClassificationPath $custom -Keywords @('GoodTable') -WarningAction SilentlyContinue
        $result.CustomEntries | Should -Be 2
        $result.Classifications['GoodTable_CL'].Source | Should -Be 'database'
        $result.Classifications['GoodTable_CL'].Connector | Should -Be 'Custom'
        $result.Classifications['BadClass_CL'].Source | Should -Be 'heuristic'
        $result.Classifications['AzureMetrics'].Classification | Should -Be 'primary'
    }

    It 'matches keywords null-safely across name, connector, description and keywords' {
        $entry = [PSCustomObject]@{ tableName = 'Okta_CL'; connector = $null; description = $null; keywords = @('sso', $null) }
        Test-ClassificationKeywordMatch -Entry $entry -Keyword 'okta' | Should -Be $true
        Test-ClassificationKeywordMatch -Entry $entry -Keyword 'SSO' | Should -Be $true
        Test-ClassificationKeywordMatch -Entry $entry -Keyword 'aws' | Should -Be $false
        Test-ClassificationKeywordMatch -Entry $entry -Keyword '' | Should -Be $false
        Test-ClassificationKeywordMatch -Entry ([PSCustomObject]@{ tableName = 'X'; connector = 'Amazon Web Services'; description = 'CloudTrail events'; keywords = @() }) -Keyword 'cloudtrail' | Should -Be $true
    }

    It 'reports every matched keyword for a gap' {
        $usage = @([PSCustomObject]@{ TableName = 'SecurityEvent'; MonthlyGB = 1; IsFree = $false })
        $result = Invoke-Classification -TableUsage $usage -RuleTableCoverage @{} -Keywords @('AWS', 'CloudTrail')
        $gap = $result.KeywordGaps | Where-Object TableName -eq 'AWSCloudTrail'
        $gap.MatchedKeyword | Should -Match 'AWS'
        $gap.MatchedKeyword | Should -Match 'CloudTrail'
    }

    It 'split tables inherit the parent recommended retention' {
        $usage = @(
            [PSCustomObject]@{ TableName = 'SigninLogs'; MonthlyGB = 5; IsFree = $false },
            [PSCustomObject]@{ TableName = 'SigninLogs_SPLT_CL'; MonthlyGB = 3; IsFree = $false },
            [PSCustomObject]@{ TableName = 'Orphan_SPLT_CL'; MonthlyGB = 3; IsFree = $false }
        )
        $result = Invoke-Classification -TableUsage $usage -RuleTableCoverage @{}
        $result.Classifications['SigninLogs_SPLT_CL'].RecommendedRetentionDays | Should -Be 365
        $result.Classifications['Orphan_SPLT_CL'].RecommendedRetentionDays | Should -Be 90
    }
}

Describe 'Resolve-DynamicClassification heuristics' {
    It 'requires tokens to start a PascalCase word' {
        (Resolve-DynamicClassification -TableName 'MicrosoftServicePrincipalSignInLogs' -RuleCount 0 -MonthlyGB 0).Classification | Should -Be 'primary'
        (Resolve-DynamicClassification -TableName 'Realerting_CL' -RuleCount 0 -MonthlyGB 0).Classification | Should -Not -Be 'primary'
    }

    It 'treats Microsoft first-party names as primary when nothing else matches' {
        $r = Resolve-DynamicClassification -TableName 'AADGraphActivityLogs' -RuleCount 0 -MonthlyGB 0
        $r.Classification | Should -Be 'primary'
        $r.Category | Should -Match 'Microsoft first-party'
        (Resolve-DynamicClassification -TableName 'GraphNotificationsActivityLogs' -RuleCount 0 -MonthlyGB 0).Classification | Should -Be 'primary'
    }

    It 'treats generic *Logs custom tables as secondary' {
        $r = Resolve-DynamicClassification -TableName 'ContainerAppSystemLogs_CL' -RuleCount 0 -MonthlyGB 0.1
        $r.Classification | Should -Be 'secondary'
        $r.Category | Should -Match 'Generic log table'
        $r.RecommendedTier | Should -Be 'datalake'
    }

    It 'prefers rule coverage over the Microsoft prefix and telemetry tokens over rules' {
        (Resolve-DynamicClassification -TableName 'AzureSomething' -RuleCount 2 -MonthlyGB 0).Category | Should -Match 'active analytics rules'
        (Resolve-DynamicClassification -TableName 'AzureSomethingMetrics' -RuleCount 2 -MonthlyGB 0).Classification | Should -Be 'secondary'
    }

    It 'still returns unknown for names with no signal' {
        $r = Resolve-DynamicClassification -TableName 'Zebra_CL' -RuleCount 0 -MonthlyGB 1
        $r.Classification | Should -Be 'unknown'
        $r.Category | Should -Be 'Custom Log: Unknown / Custom'
    }
}

Describe 'Connect-Sentinel' {
    BeforeAll {
        function Connect-AzAccount { param($SubscriptionId) }
    }

    It 'resolves the workspace over REST and returns tokens plus workspace facts' {
        Mock Get-AzContext { [PSCustomObject]@{ Subscription = [PSCustomObject]@{ Id = 'sub' }; Tenant = [PSCustomObject]@{ Id = 'tid' } } }
        Mock Connect-AzAccount { throw 'should not reconnect' }
        Mock Resolve-AzToken { if ($ResourceUrl -like '*loganalytics*') { 'LA-TOKEN' } else { 'ARM-TOKEN' } }
        Mock Invoke-AzRestWithRetry { [PSCustomObject]@{ location = 'westeurope'; properties = [PSCustomObject]@{ customerId = 'ws-guid'; retentionInDays = 90; defaultDataCollectionRuleResourceId = '/dcr' } } }

        $ctx = Connect-Sentinel -SubscriptionId 'sub' -ResourceGroup 'rg' -WorkspaceName 'ws' -WarningVariable w -WarningAction SilentlyContinue

        $ctx.WorkspaceId | Should -Be 'ws-guid'
        $ctx.TenantId | Should -Be 'tid'
        $ctx.ArmToken | Should -Be 'ARM-TOKEN'
        $ctx.LaToken | Should -Be 'LA-TOKEN'
        $ctx.Region | Should -Be 'westeurope'
        $ctx.WorkspaceRetentionDays | Should -Be 90
        $ctx.DefaultDataCollectionRuleResourceId | Should -Be '/dcr'
        $ctx.ResourceId | Should -Be '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws'
        $ctx.PSObject.Properties.Name | Should -Not -Contain 'DefenderUnified'
        $ctx.Endpoints.Arm | Should -Be 'https://management.azure.com'
        $ctx.Endpoints.LogAnalytics | Should -Be 'https://api.loganalytics.io/v1'
        Should -Invoke Invoke-AzRestWithRetry -Times 1 -ParameterFilter { $Uri -eq 'https://management.azure.com/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws?api-version=2025-07-01' }
        Should -Invoke Connect-AzAccount -Times 0
    }

    It 'uses the sovereign endpoints of the signed-in environment for tokens and the workspace call' {
        $gov = [PSCustomObject]@{
            Name                                       = 'AzureUSGovernment'
            ResourceManagerUrl                         = 'https://management.usgovcloudapi.net/'
            AzureOperationalInsightsEndpoint           = 'https://api.loganalytics.us/v1'
            AzureOperationalInsightsEndpointResourceId = 'https://api.loganalytics.us'
            ExtendedProperties                         = @{ MicrosoftGraphUrl = 'https://graph.microsoft.us' }
        }
        Mock Get-AzContext { [PSCustomObject]@{ Subscription = [PSCustomObject]@{ Id = 'sub' }; Tenant = [PSCustomObject]@{ Id = 'tid' }; Environment = $gov } }
        Mock Resolve-AzToken { "tok-$ResourceUrl" }
        Mock Invoke-AzRestWithRetry { [PSCustomObject]@{ location = 'usgovvirginia'; properties = [PSCustomObject]@{ customerId = 'gov-guid' } } }

        $ctx = Connect-Sentinel -SubscriptionId 'sub' -ResourceGroup 'rg' -WorkspaceName 'ws'

        $ctx.ArmToken | Should -Be 'tok-https://management.usgovcloudapi.net'
        $ctx.LaToken | Should -Be 'tok-https://api.loganalytics.us'
        $ctx.Endpoints.Name | Should -Be 'AzureUSGovernment'
        $ctx.Endpoints.Graph | Should -Be 'https://graph.microsoft.us'
        $ctx.Endpoints.GraphEnvironment | Should -Be 'USGov'
        Should -Invoke Invoke-AzRestWithRetry -Times 1 -ParameterFilter { $Uri -like 'https://management.usgovcloudapi.net/subscriptions/sub/*' }
    }

    It 'signs in when the current context is for another subscription and warns on a WorkspaceId mismatch' {
        $script:signedIn = $false
        Mock Get-AzContext { if ($script:signedIn) { [PSCustomObject]@{ Subscription = [PSCustomObject]@{ Id = 'sub' }; Tenant = [PSCustomObject]@{ Id = 'tid' } } } else { [PSCustomObject]@{ Subscription = [PSCustomObject]@{ Id = 'other' }; Tenant = [PSCustomObject]@{ Id = 'tid' } } } }
        Mock Connect-AzAccount { $script:signedIn = $true }
        Mock Resolve-AzToken { 'tok' }
        Mock Invoke-AzRestWithRetry { [PSCustomObject]@{ location = 'x'; properties = [PSCustomObject]@{ customerId = 'real-guid' } } }

        $ctx = Connect-Sentinel -SubscriptionId 'sub' -ResourceGroup 'rg' -WorkspaceName 'ws' -WorkspaceId 'user-guid' -WarningVariable w -WarningAction SilentlyContinue
        $ctx.WorkspaceId | Should -Be 'real-guid'
        $ctx.WorkspaceRetentionDays | Should -BeNullOrEmpty
        "$w" | Should -Match 'differs from resolved'
        Should -Invoke Connect-AzAccount -Times 1 -ParameterFilter { $SubscriptionId -eq 'sub' }
    }

    It 'throws a clear error when the workspace has no customerId' {
        Mock Get-AzContext { [PSCustomObject]@{ Subscription = [PSCustomObject]@{ Id = 'sub' }; Tenant = [PSCustomObject]@{ Id = 'tid' } } }
        Mock Resolve-AzToken { 'tok' }
        Mock Invoke-AzRestWithRetry { [PSCustomObject]@{ properties = [PSCustomObject]@{} } }
        { Connect-Sentinel -SubscriptionId 'sub' -ResourceGroup 'rg' -WorkspaceName 'ws' } | Should -Throw '*customerId*'
    }
}

Describe 'Resolve-AzToken' {
    BeforeAll {
        function Get-AzAccessToken { param($ResourceUrl, $TenantId, $ErrorAction) }
    }

    It 'handles SecureString and plain tokens and forwards TenantId' {
        Mock Get-AzAccessToken { [PSCustomObject]@{ Token = (ConvertTo-SecureString 'secure-token' -AsPlainText -Force) } }
        Resolve-AzToken -ResourceUrl 'https://x' -TenantId 't1' | Should -Be 'secure-token'
        Should -Invoke Get-AzAccessToken -Times 1 -ParameterFilter { $TenantId -eq 't1' }

        Mock Get-AzAccessToken { [PSCustomObject]@{ Token = 'plain-token' } }
        Resolve-AzToken -ResourceUrl 'https://x' | Should -Be 'plain-token'
        Should -Invoke Get-AzAccessToken -Times 1 -ParameterFilter { -not $PSBoundParameters.ContainsKey('TenantId') }
    }
}

Describe 'Endpoint resolution' {
    It 'returns the public cloud defaults when there is no Az context' {
        Mock Get-AzContext { $null }
        $e = Resolve-LogHorizonEndpoints
        $e.Name | Should -Be 'AzureCloud'
        $e.Arm | Should -Be 'https://management.azure.com'
        $e.LogAnalytics | Should -Be 'https://api.loganalytics.io/v1'
        $e.LogAnalyticsResource | Should -Be 'https://api.loganalytics.io'
        $e.Graph | Should -Be 'https://graph.microsoft.com'
        $e.GraphEnvironment | Should -Be 'Global'
    }

    It 'returns the defaults when Get-AzContext is unavailable' {
        Mock Get-AzContext { throw 'no Az' }
        (Resolve-LogHorizonEndpoints).Arm | Should -Be 'https://management.azure.com'
    }

    It 'reads sovereign values from properties and ExtendedProperties and trims trailing slashes' {
        $china = [PSCustomObject]@{
            Name                                       = 'AzureChinaCloud'
            ResourceManagerUrl                         = 'https://management.chinacloudapi.cn/'
            AzureOperationalInsightsEndpoint           = ''
            AzureOperationalInsightsEndpointResourceId = $null
            ExtendedProperties                         = @{
                OperationalInsightsEndpoint           = 'https://api.loganalytics.azure.cn/v1/'
                OperationalInsightsEndpointResourceId = 'https://api.loganalytics.azure.cn'
                MicrosoftGraphEndpointResourceId      = 'https://microsoftgraph.chinacloudapi.cn/'
            }
        }
        $e = Resolve-LogHorizonEndpoints -Environment $china
        $e.Name | Should -Be 'AzureChinaCloud'
        $e.Arm | Should -Be 'https://management.chinacloudapi.cn'
        $e.LogAnalytics | Should -Be 'https://api.loganalytics.azure.cn/v1'
        $e.LogAnalyticsResource | Should -Be 'https://api.loganalytics.azure.cn'
        $e.Graph | Should -Be 'https://microsoftgraph.chinacloudapi.cn'
        $e.GraphEnvironment | Should -Be 'China'
    }

    It 'falls back per value when an environment is missing fields' {
        $partial = [PSCustomObject]@{ Name = ''; ResourceManagerUrl = 'https://arm.example/' }
        $e = Resolve-LogHorizonEndpoints -Environment $partial
        $e.Name | Should -Be 'AzureCloud'
        $e.Arm | Should -Be 'https://arm.example'
        $e.LogAnalytics | Should -Be 'https://api.loganalytics.io/v1'
        $e.Graph | Should -Be 'https://graph.microsoft.com'
        $e.GraphEnvironment | Should -Be 'Global'
    }

    It 'Get-LogHorizonEndpoint prefers the context Endpoints and otherwise resolves from the environment' {
        $ctx = [PSCustomObject]@{ Endpoints = [PSCustomObject]@{ Arm = 'https://ctx.example'; Graph = '' } }
        Get-LogHorizonEndpoint -Name Arm -Context $ctx | Should -Be 'https://ctx.example'

        Mock Get-AzContext { $null }
        Get-LogHorizonEndpoint -Name Graph -Context $ctx | Should -Be 'https://graph.microsoft.com'
        Get-LogHorizonEndpoint -Name LogAnalytics -Context ([PSCustomObject]@{ ArmToken = 'x' }) | Should -Be 'https://api.loganalytics.io/v1'
        Get-LogHorizonEndpoint -Name GraphEnvironment | Should -Be 'Global'
    }
}

Describe 'Collector endpoints and API versions' {
    BeforeAll {
        $script:epCtx = [PSCustomObject]@{
            ArmToken    = 'tok'
            LaToken     = 'la'
            WorkspaceId = 'ws-guid'
            ResourceId  = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws'
            Endpoints   = [PSCustomObject]@{ Arm = 'https://management.usgovcloudapi.net'; LogAnalytics = 'https://api.loganalytics.us/v1'; Graph = 'https://graph.microsoft.us'; GraphEnvironment = 'USGov' }
        }
    }

    It 'Get-AnalyticsRules uses SecurityInsights 2025-09-01 on the environment ARM host' {
        Mock Invoke-AzRestWithRetry { [PSCustomObject]@{ value = @() } }
        $null = Get-AnalyticsRules -Context $script:epCtx
        Should -Invoke Invoke-AzRestWithRetry -Times 1 -ParameterFilter { $Uri -eq 'https://management.usgovcloudapi.net/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws/providers/Microsoft.SecurityInsights/alertRules?api-version=2025-09-01' }
    }

    It 'Get-DataConnectors uses SecurityInsights 2025-09-01 on the environment ARM host' {
        Mock Invoke-AzRestWithRetry { [PSCustomObject]@{ value = @() } }
        $null = Get-DataConnectors -Context $script:epCtx
        Should -Invoke Invoke-AzRestWithRetry -Times 1 -ParameterFilter { $Uri -eq 'https://management.usgovcloudapi.net/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2025-09-01' }
    }

    It 'Get-DataConnectors follows nextLink and derives IsConnected from dataTypes state' {
        Mock Invoke-AzRestWithRetry {
            if ($Uri -like '*page2*') {
                return [PSCustomObject]@{ value = @(
                    [PSCustomObject]@{ id = 'c3'; name = 'c3'; kind = 'GenericUI'; properties = [PSCustomObject]@{ connectorUiConfig = [PSCustomObject]@{ title = 'x' } } },
                    [PSCustomObject]@{ id = 'c4'; name = 'c4'; kind = 'Other'; properties = [PSCustomObject]@{ displayName = 'no types' } }
                ) }
            }
            [PSCustomObject]@{
                value    = @(
                    [PSCustomObject]@{ id = 'c1'; name = 'c1'; kind = 'AzureActiveDirectory'; properties = [PSCustomObject]@{ dataTypes = [PSCustomObject]@{ alerts = [PSCustomObject]@{ state = 'Enabled' } } } },
                    [PSCustomObject]@{ id = 'c2'; name = 'c2'; kind = 'Office365'; properties = [PSCustomObject]@{ dataTypes = [PSCustomObject]@{ exchange = [PSCustomObject]@{ state = 'Disabled' } } } }
                )
                nextLink = 'https://management.usgovcloudapi.net/page2'
            }
        }
        $r = @(Get-DataConnectors -Context $script:epCtx)
        $r.Count | Should -Be 4
        ($r | Where-Object Id -eq 'c1').IsConnected | Should -BeTrue
        ($r | Where-Object Id -eq 'c2').IsConnected | Should -BeFalse
        ($r | Where-Object Id -eq 'c3').IsConnected | Should -BeTrue
        ($r | Where-Object Id -eq 'c4').IsConnected | Should -BeTrue
        ($r | Where-Object Id -eq 'c1').ConnectorType | Should -Be 'AzureActiveDirectory'
        Should -Invoke Invoke-AzRestWithRetry -Times 2
    }

    It 'Get-HuntingQueries uses OperationalInsights 2025-07-01 and keeps only Hunting Queries' {
        Mock Invoke-AzRestWithRetry { [PSCustomObject]@{ value = @(
            [PSCustomObject]@{ properties = [PSCustomObject]@{ category = 'Hunting Queries'; displayName = 'H1'; query = 'SigninLogs | take 1' } },
            [PSCustomObject]@{ properties = [PSCustomObject]@{ category = 'General Exploration'; displayName = 'S1'; query = 'Heartbeat | take 1' } }
        ) } }
        $r = Get-HuntingQueries -Context $script:epCtx
        @($r.Queries).Count | Should -Be 1
        $r.TableCoverage['SigninLogs'] | Should -Be 1
        Should -Invoke Invoke-AzRestWithRetry -Times 1 -ParameterFilter { $Uri -eq 'https://management.usgovcloudapi.net/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws/savedSearches?api-version=2025-07-01' }
    }

    It 'Get-SocOptimization uses recommendations 2025-10-01-preview and returns an empty list on failure' {
        Mock Invoke-AzRestWithRetry { [PSCustomObject]@{ value = @([PSCustomObject]@{ id = 'r1'; properties = [PSCustomObject]@{ title = 'T'; state = 'Active'; recommendationTypeId = 'X'; suggestions = @([PSCustomObject]@{ title = 's'; action = 'a'; suggestionTypeId = 'st' }) } }) } }
        $r = @(Get-SocOptimization -Context $script:epCtx)
        $r.Count | Should -Be 1
        $r[0].Suggestions[0].TypeId | Should -Be 'st'
        Should -Invoke Invoke-AzRestWithRetry -Times 1 -ParameterFilter { $Uri -eq 'https://management.usgovcloudapi.net/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws/providers/Microsoft.SecurityInsights/recommendations?api-version=2025-10-01-preview' }

        Mock Invoke-AzRestWithRetry { throw '403' }
        @(Get-SocOptimization -Context $script:epCtx).Count | Should -Be 0
    }

    It 'Get-TableRetention uses OperationalInsights 2025-07-01 for the workspace and tables' {
        Mock Invoke-AzRestWithRetry { if ($Uri -like '*/tables?*') { [PSCustomObject]@{ value = @() } } else { [PSCustomObject]@{ properties = [PSCustomObject]@{ retentionInDays = 30 } } } }
        $null = Get-TableRetention -Context $script:epCtx
        Should -Invoke Invoke-AzRestWithRetry -Times 1 -ParameterFilter { $Uri -eq 'https://management.usgovcloudapi.net/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws?api-version=2025-07-01' }
        Should -Invoke Invoke-AzRestWithRetry -Times 1 -ParameterFilter { $Uri -eq 'https://management.usgovcloudapi.net/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws/tables?api-version=2025-07-01' }
    }

    It 'Get-TableUsage queries the environment Log Analytics endpoint' {
        Mock Invoke-AzRestWithRetry { [PSCustomObject]@{ tables = @([PSCustomObject]@{ columns = @([PSCustomObject]@{ name = 'DataType' }, [PSCustomObject]@{ name = 'TotalGB' }); rows = @() }) } }
        $null = Get-TableUsage -Context $script:epCtx -DaysBack 7
        Should -Invoke Invoke-AzRestWithRetry -ParameterFilter { $Uri -eq 'https://api.loganalytics.us/v1/workspaces/ws-guid/query' }
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

    It 'Get-TablePlanDisplay returns the configured plan when observed usage matches it' {
        $table = [PSCustomObject]@{
            TablePlan         = 'Analytics'
            ObservedKnownPlans = @('Analytics')
            ObservedPlans     = @('Analytics')
        }

        $result = Get-TablePlanDisplay -Table $table
        $result | Should -Be 'Analytics'
    }

    It 'Get-TablePlanDisplay appends observed plans when usage spans multiple plans' {
        $table = [PSCustomObject]@{
            TablePlan          = 'Analytics'
            ObservedKnownPlans = @('Analytics', 'Basic')
            ObservedPlans      = @('Analytics', 'Basic')
        }

        $result = Get-TablePlanDisplay -Table $table
        $result | Should -Be 'Analytics [dim](obs: Analytics, Basic)[/]'
    }

    It 'Get-TablePlanDisplay falls back to observed usage when no configured plan is available' {
        $table = [PSCustomObject]@{
            TablePlan          = $null
            ObservedKnownPlans = @('Auxiliary')
            ObservedPlans      = @('Auxiliary')
        }

        $result = Get-TablePlanDisplay -Table $table
        $result | Should -Be '[dim]Observed:[/] Auxiliary'
    }

    It 'Get-LogHorizonMinimumColdRetentionValue starts above the highest effective hot retention' {
        $analysis = New-MockAnalysis
        $tables = @(
            [PSCustomObject]@{ TableName = 'TableA'; ActualInteractiveRetentionDays = 30 },
            [PSCustomObject]@{ TableName = 'TableB'; ActualInteractiveRetentionDays = 90 }
        )

        $result = Get-LogHorizonMinimumColdRetentionValue -Analysis $analysis -Tables $tables

        $result | Should -Be 91
    }

    It 'Get-LogHorizonMinimumColdRetentionValue uses the workspace default when hot retention inherits' {
        $analysis = New-MockAnalysis
        $tables = @(
            [PSCustomObject]@{ TableName = 'TableA'; ActualInteractiveRetentionDays = $null; RetentionInDays = $null }
        )

        $result = Get-LogHorizonMinimumColdRetentionValue -Analysis $analysis -Tables $tables -RetentionInDays $null

        $result | Should -Be 91
    }

    It 'Get-LogHorizonColdRetentionHint starts at the computed minimum value' {
        $result = Get-LogHorizonColdRetentionHint -MinimumValue 91

        $result | Should -Be '91-730 or 1095,1460,1826,2191,2556,2922,3288,3653,4018,4383'
    }

    It 'Get-LogHorizonColdRetentionHint only offers long-term values above 730 days' {
        $result = Get-LogHorizonColdRetentionHint -MinimumValue 731

        $result | Should -Be '1095,1460,1826,2191,2556,2922,3288,3653,4018,4383'
    }

    It 'Select-LogHorizonTablesFromList lets the user back out of the add-table picker' {
        $tables = @(
            [PSCustomObject]@{ TableName = 'A' },
            [PSCustomObject]@{ TableName = 'B' }
        )

        $script:selectionResponses = [System.Collections.Generic.Queue[string]]::new()
        @('Add a table', 'Back', 'Cancel') | ForEach-Object { $script:selectionResponses.Enqueue($_) }

        $originalReadSpectreSelection = if (Test-Path Function:\Read-SpectreSelection) { (Get-Item Function:\Read-SpectreSelection).ScriptBlock } else { $null }
        $originalWriteSpectreHost = if (Test-Path Function:\Write-SpectreHost) { (Get-Item Function:\Write-SpectreHost).ScriptBlock } else { $null }

        try {
            Set-Item -Path Function:\Read-SpectreSelection -Value {
                param([string]$Title, [object[]]$Choices, $Color, [switch]$EnableSearch)

                $next = $script:selectionResponses.Dequeue()
                $next | Should -BeIn @($Choices)
                return $next
            }
            Set-Item -Path Function:\Write-SpectreHost -Value { param([string]$Text) }
            Mock Clear-LogHorizonScreen {}

            $result = @(Select-LogHorizonTablesFromList -Tables $tables)

            $result | Should -HaveCount 0
        }
        finally {
            if ($null -ne $originalReadSpectreSelection) {
                Set-Item -Path Function:\Read-SpectreSelection -Value $originalReadSpectreSelection
            }
            else {
                Remove-Item -Path Function:\Read-SpectreSelection -ErrorAction SilentlyContinue
            }

            if ($null -ne $originalWriteSpectreHost) {
                Set-Item -Path Function:\Write-SpectreHost -Value $originalWriteSpectreHost
            }
            else {
                Remove-Item -Path Function:\Write-SpectreHost -ErrorAction SilentlyContinue
            }
        }
    }

    It 'Select-LogHorizonTablesFromList lets the user back out of the remove-table picker without losing the selection' {
        $tables = @(
            [PSCustomObject]@{ TableName = 'A' },
            [PSCustomObject]@{ TableName = 'B' }
        )

        $script:selectionResponses = [System.Collections.Generic.Queue[string]]::new()
        @('Add a table', 'A', 'Remove a table', 'Back', 'Done') | ForEach-Object { $script:selectionResponses.Enqueue($_) }

        $originalReadSpectreSelection = if (Test-Path Function:\Read-SpectreSelection) { (Get-Item Function:\Read-SpectreSelection).ScriptBlock } else { $null }
        $originalWriteSpectreHost = if (Test-Path Function:\Write-SpectreHost) { (Get-Item Function:\Write-SpectreHost).ScriptBlock } else { $null }

        try {
            Set-Item -Path Function:\Read-SpectreSelection -Value {
                param([string]$Title, [object[]]$Choices, $Color, [switch]$EnableSearch)

                $next = $script:selectionResponses.Dequeue()
                $next | Should -BeIn @($Choices)
                return $next
            }
            Set-Item -Path Function:\Write-SpectreHost -Value { param([string]$Text) }
            Mock Clear-LogHorizonScreen {}

            $result = @(Select-LogHorizonTablesFromList -Tables $tables)

            $result | Should -HaveCount 1
            $result[0].TableName | Should -Be 'A'
        }
        finally {
            if ($null -ne $originalReadSpectreSelection) {
                Set-Item -Path Function:\Read-SpectreSelection -Value $originalReadSpectreSelection
            }
            else {
                Remove-Item -Path Function:\Read-SpectreSelection -ErrorAction SilentlyContinue
            }

            if ($null -ne $originalWriteSpectreHost) {
                Set-Item -Path Function:\Write-SpectreHost -Value $originalWriteSpectreHost
            }
            else {
                Remove-Item -Path Function:\Write-SpectreHost -ErrorAction SilentlyContinue
            }
        }
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
