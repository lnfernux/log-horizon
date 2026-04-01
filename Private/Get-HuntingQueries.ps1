function Get-HuntingQueries {
    <#
    .SYNOPSIS
        Fetches Sentinel hunting queries (saved searches) and maps referenced tables.
    .OUTPUTS
        PSCustomObject with Queries (array) and TableCoverage (hashtable of table -> query count).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Context
    )

    $headers = @{ Authorization = "Bearer $($Context.ArmToken)" }
    $uri = "https://management.azure.com$($Context.ResourceId)/savedSearches?api-version=2020-08-01"

    $response = Invoke-RestMethod -Uri $uri -Headers $headers -ErrorAction Stop

    $tableCoverage = @{}
    $huntingQueries = foreach ($ss in $response.value) {
        $cat = $ss.properties.category
        # Hunting queries have category "Hunting Queries" in Sentinel
        if ($cat -ne 'Hunting Queries') { continue }

        $query = $ss.properties.query
        $displayName = $ss.properties.displayName

        $tables = @()
        if ($query) {
            $tables = Get-TablesFromKql -Kql $query
        }

        foreach ($t in $tables) {
            if (-not $tableCoverage.ContainsKey($t)) { $tableCoverage[$t] = 0 }
            $tableCoverage[$t]++
        }

        [PSCustomObject]@{
            QueryName = $displayName
            Tables    = $tables
        }
    }

    [PSCustomObject]@{
        Queries       = @($huntingQueries)
        TableCoverage = $tableCoverage
        TotalQueries  = @($huntingQueries).Count
    }
}
