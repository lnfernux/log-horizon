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

    do {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -ErrorAction Stop
        foreach ($c in $response.value) { $allConnectors.Add($c) }
        $uri = $response.nextLink
    } while ($uri)

    $connectors = foreach ($c in $allConnectors) {
        [PSCustomObject]@{
            Id            = $c.id
            Name          = $c.name
            Kind          = $c.kind
            DisplayName   = $c.properties.displayName
            ConnectorType = $c.kind
            IsConnected   = ($null -ne $c.properties)
        }
    }

    $connectors
}
