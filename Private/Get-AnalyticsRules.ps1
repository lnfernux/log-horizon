function Get-AnalyticsRules {
    <#
    .SYNOPSIS
        Fetches active Sentinel analytics rules and maps referenced tables.
    .OUTPUTS
        PSCustomObject with Rules (array) and TableCoverage (hashtable of table -> rule count).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Context
    )

    $headers = @{ Authorization = "Bearer $($Context.ArmToken)" }
    $uri = "https://management.azure.com$($Context.ResourceId)" +
           "/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01"

    $allRules = [System.Collections.Generic.List[object]]::new()

    # handle paging
    do {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -ErrorAction Stop
        foreach ($r in $response.value) { $allRules.Add($r) }
        $uri = $response.nextLink
    } while ($uri)

    $tableCoverage = @{}
    $rules = foreach ($rule in $allRules) {
        $kind = $rule.kind
        $query = $null
        $displayName = $rule.properties.displayName
        $enabled = $rule.properties.enabled
        $description = $rule.properties.description

        # Parse Defender correlation tags from description
        $dontCorr = $description -match '(?i)#DONT_CORR#'
        $incCorr  = $description -match '(?i)#INC_CORR#'

        switch ($kind) {
            'Scheduled'           { $query = $rule.properties.query }
            'NRT'                 { $query = $rule.properties.query }
            'MicrosoftSecurityIncidentCreation' {
                $query = $null
            }
            'Fusion' { $query = $null }
        }

        $tables = @()
        if ($query) {
            $tables = Get-TablesFromKql -Kql $query
        }

        foreach ($t in $tables) {
            if (-not $tableCoverage.ContainsKey($t)) { $tableCoverage[$t] = 0 }
            $tableCoverage[$t]++
        }

        [PSCustomObject]@{
            RuleName                = $displayName
            Kind                    = $kind
            Enabled                 = $enabled
            Tables                  = $tables
            HasQuery                = [bool]$query
            Description             = $description
            ExcludedFromCorrelation = $dontCorr
            IncludedInCorrelation   = $incCorr
        }
    }

    [PSCustomObject]@{
        Rules         = $rules
        TableCoverage = $tableCoverage
        TotalRules    = $allRules.Count
        EnabledRules  = @($rules | Where-Object Enabled).Count
        DontCorrCount = @($rules | Where-Object ExcludedFromCorrelation).Count
        IncCorrCount  = @($rules | Where-Object IncludedInCorrelation).Count
    }
}

function Get-TablesFromKql {
    <#
    .SYNOPSIS
        Extracts table names referenced in a KQL query using regex heuristics.
    #>
    [CmdletBinding()]
    param([string]$Kql)

    $tables = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    # Pattern 1: table at start of expression (before pipe)
    $matches1 = [regex]::Matches($Kql, '(?m)^\s*([A-Z]\w+)\s*\n?\|')
    foreach ($m in $matches1) { [void]$tables.Add($m.Groups[1].Value) }

    # Pattern 2: table in join
    $matches2 = [regex]::Matches($Kql, '(?i)\bjoin\s+(?:kind\s*=\s*\w+\s+)?\(?\s*([A-Z]\w+)')
    foreach ($m in $matches2) { [void]$tables.Add($m.Groups[1].Value) }

    # Pattern 3: table in union
    $matches3 = [regex]::Matches($Kql, '(?i)\bunion\s+(?:isfuzzy\s*=\s*\w+\s+)?([A-Z]\w+)')
    foreach ($m in $matches3) { [void]$tables.Add($m.Groups[1].Value) }

    # Pattern 4: table after let assignment (let x = TableName | ...)
    $matches4 = [regex]::Matches($Kql, '(?im)^\s*let\s+\w+\s*=\s*([A-Z]\w+)\s*[\|\n;]')
    foreach ($m in $matches4) { [void]$tables.Add($m.Groups[1].Value) }

    # Filter out KQL functions/keywords that might false-positive
    $kqlKeywords = @(
        'let', 'where', 'project', 'extend', 'summarize', 'render', 'sort',
        'top', 'take', 'count', 'distinct', 'evaluate', 'parse', 'invoke',
        'limit', 'sample', 'search', 'find', 'print', 'range', 'datatable',
        'materialize', 'toscalar', 'bag_unpack', 'True', 'False',
        'set', 'alias', 'restrict', 'declare', 'pattern', 'tabular',
        'database', 'cluster', 'contains', 'has', 'startswith', 'endswith'
    )

    # Remove tables that are actually let-statement identifiers
    $letNames = [regex]::Matches($Kql, '(?im)^\s*let\s+(\w+)\s*=') |
        ForEach-Object { $_.Groups[1].Value }
    $tables | Where-Object { $_ -notin $kqlKeywords -and $_ -notin $letNames -and $_.Length -gt 2 }
}
