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

    # Workspace-level default retention
    $wsUri = "https://management.azure.com$($Context.ResourceId)?api-version=2023-09-01"
    $wsResponse = Invoke-AzRestWithRetry -Uri $wsUri -Headers $headers
    $workspaceRetention = [int]$wsResponse.properties.retentionInDays

    # Per-table retention and plan
    $uri = "https://management.azure.com$($Context.ResourceId)/tables?api-version=2025-07-01"
    $response = Invoke-AzRestWithRetry -Uri $uri -Headers $headers

    $tables = foreach ($table in $response.value) {
        $props = $table.properties
        [PSCustomObject]@{
            TableName              = $table.name
            Plan                   = $props.plan                        # Analytics | Basic | Auxiliary
            RetentionInDays        = [int]$props.retentionInDays        # interactive/hot
            TotalRetentionInDays   = [int]$props.totalRetentionInDays   # hot + archive
            ArchiveRetentionInDays = [int]$props.archiveRetentionInDays # total - retention
            TableSubType           = $props.tableSubType                # Any | Classic | DataCollectionRuleBased
        }
    }

    [PSCustomObject]@{
        WorkspaceRetentionDays = $workspaceRetention
        Tables                 = @($tables)
    }
}
