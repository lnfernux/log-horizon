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

    $allSavedSearches = [System.Collections.Generic.List[object]]::new()
    $maxPages = 1000
    $pageCount = 0

    do {
        $pageCount++
        $response = Invoke-AzRestWithRetry -Uri $uri -Headers $headers
        foreach ($ss in $response.value) { $allSavedSearches.Add($ss) }
        $uri = $response.nextLink
        if ($pageCount -ge $maxPages) {
            Write-Warning "Pagination limit reached fetching Hunting Queries. Terminating to avoid infinite loop."
            break
        }
    } while ($uri)

    Write-Verbose "Fetched $($allSavedSearches.Count) saved search(es) across $pageCount page(s)."

    $tableCoverage = @{}
    $huntingQueries = foreach ($ss in $allSavedSearches) {
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
            Query     = $query
            Enabled   = $true
        }
    }

    [PSCustomObject]@{
        Queries       = @($huntingQueries)
        TableCoverage = $tableCoverage
        TotalQueries  = @($huntingQueries).Count
    }
}
