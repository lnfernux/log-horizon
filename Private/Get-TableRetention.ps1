function Get-TableRetention {
    <#
    .SYNOPSIS
        Fetches workspace default retention and per-table retention/plan
        configuration from the Log Analytics APIs.
    .OUTPUTS
        PSCustomObject with WorkspaceRetentionDays (int) and Tables (array of
        PSCustomObjects with TableName, Plan, RetentionInDays,
        TotalRetentionInDays, ArchiveRetentionInDays).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Context
    )

    $headers = @{ Authorization = "Bearer $($Context.ArmToken)" }
    $arm = Get-LogHorizonEndpoint -Name Arm -Context $Context

    # Workspace-level default retention and the workspace transformation DCR. Connect-Sentinel already
    # read the workspace resource; only fetch it again when the context does not carry those facts.
    if ($Context.PSObject.Properties.Name -contains 'WorkspaceRetentionDays' -and $null -ne $Context.WorkspaceRetentionDays) {
        $workspaceRetention = [int]$Context.WorkspaceRetentionDays
        $defaultDcrId = if ($Context.PSObject.Properties.Name -contains 'DefaultDataCollectionRuleResourceId') { $Context.DefaultDataCollectionRuleResourceId } else { $null }
    }
    else {
        $wsUri = "$arm$($Context.ResourceId)?api-version=2025-07-01"
        $wsResponse = Invoke-AzRestWithRetry -Uri $wsUri -Headers $headers
        $workspaceRetention = [int]$wsResponse.properties.retentionInDays
        $defaultDcrId = if ($wsResponse.properties.PSObject.Properties.Name -contains 'defaultDataCollectionRuleResourceId') { $wsResponse.properties.defaultDataCollectionRuleResourceId } else { $null }
    }

    # Per-table retention and plan. retentionInDays / totalRetentionInDays are always the
    # effective values; the *AsDefault booleans say whether they are inherited.
    $uri = "$arm$($Context.ResourceId)/tables?api-version=2025-07-01"
    $response = Invoke-AzRestWithRetry -Uri $uri -Headers $headers

    $tables = foreach ($table in $response.value) {
        $props = $table.properties

        # Extract column names from schema (columns + standardColumns), excluding hidden
        $allCols = @()
        if ($props.schema) {
            $schemaCols    = @($props.schema.columns         | Where-Object { -not $_.isHidden } | ForEach-Object { $_.name })
            $standardCols  = @($props.schema.standardColumns | Where-Object { -not $_.isHidden } | ForEach-Object { $_.name })
            $allCols = @($schemaCols + $standardCols | Sort-Object -Unique)
        }

        [PSCustomObject]@{
            TableName              = $table.name
            Plan                   = $props.plan                        # Analytics | Basic | Auxiliary
            RetentionInDays        = if ($null -ne $props.retentionInDays) { [int]$props.retentionInDays } else { $null }        # interactive/hot
            TotalRetentionInDays   = if ($null -ne $props.totalRetentionInDays) { [int]$props.totalRetentionInDays } else { $null }   # hot + archive
            ArchiveRetentionInDays = if ($null -ne $props.archiveRetentionInDays) { [int]$props.archiveRetentionInDays } else { $null } # total - retention
            ProvisioningState      = $props.provisioningState           # Succeeded | Updating | ...
            TableSubType           = $props.tableSubType                # Any | Classic | DataCollectionRuleBased
            TableType              = if ($props.schema) { $props.schema.tableType } else { $null }   # Microsoft | CustomLog | RestoredLogs | SearchResults
            RetentionInDaysAsDefault      = [bool]$props.retentionInDaysAsDefault
            TotalRetentionInDaysAsDefault = [bool]$props.totalRetentionInDaysAsDefault
            LastPlanModifiedDate   = if ($props.lastPlanModifiedDate) { $props.lastPlanModifiedDate } else { $null }
            Columns                = $allCols                           # string[] of visible column names
        }
    }

    [PSCustomObject]@{
        WorkspaceRetentionDays = $workspaceRetention
        WorkspaceDefaultDcrId  = $defaultDcrId
        Tables                 = @($tables)
    }
}
