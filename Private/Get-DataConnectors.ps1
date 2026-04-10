function Get-DataConnectors {
    <#
    .SYNOPSIS
        Fetches Sentinel data connector status.
    .OUTPUTS
        Array of PSCustomObjects with connector metadata.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Context
    )

    $headers = @{ Authorization = "Bearer $($Context.ArmToken)" }
    $uri = "https://management.azure.com$($Context.ResourceId)" +
           "/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2024-03-01"

    $allConnectors = [System.Collections.Generic.List[object]]::new()
    $maxPages = 1000
    $pageCount = 0

    do {
        $pageCount++
        $response = Invoke-AzRestWithRetry -Uri $uri -Headers $headers
        foreach ($c in $response.value) { $allConnectors.Add($c) }
        $uri = $response.nextLink
        if ($pageCount -ge $maxPages) {
            Write-Warning "Pagination limit reached fetching Data Connectors. Terminating to avoid infinite loop."
            break
        }
    } while ($uri)

    $connectors = foreach ($c in $allConnectors) {
        # Determine connection status from known connector state properties
        $connected = $false
        $props = $c.properties
        if ($props) {
            if ($null -ne $props.dataTypes) {
                # Check if any dataType has a non-null/non-disconnected state
                $connected = $props.dataTypes.PSObject.Properties.Value |
                    Where-Object { $_.state -and $_.state -ne 'Disabled' } |
                    Select-Object -First 1
                $connected = [bool]$connected
            } elseif ($null -ne $props.connectorUiConfig) {
                $connected = $true
            } else {
                $connected = $true
            }
        }

        [PSCustomObject]@{
            Id            = $c.id
            Name          = $c.name
            Kind          = $c.kind
            DisplayName   = $props.displayName
            ConnectorType = $c.kind
            IsConnected   = $connected
        }
    }

    $connectors
}
