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
    $wsResponse = Invoke-RestMethod -Uri $wsUri -Headers $headers -ErrorAction Stop
    $workspaceRetention = [int]$wsResponse.properties.retentionInDays

    # Per-table retention
    $uri = "https://management.azure.com$($Context.ResourceId)/tables?api-version=2023-09-01"
    $response = Invoke-RestMethod -Uri $uri -Headers $headers -ErrorAction Stop

    $tables = foreach ($table in $response.value) {
        $props = $table.properties
        [PSCustomObject]@{
            TableName              = $table.name
            Plan                   = $props.plan                        # Analytics | Basic
            RetentionInDays        = [int]$props.retentionInDays        # interactive/hot
            TotalRetentionInDays   = [int]$props.totalRetentionInDays   # hot + archive
            ArchiveRetentionInDays = [int]$props.archiveRetentionInDays # total - retention
        }
    }

    [PSCustomObject]@{
        WorkspaceRetentionDays = $workspaceRetention
        Tables                 = @($tables)
    }
}
