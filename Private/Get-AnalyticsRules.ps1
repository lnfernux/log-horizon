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
            Query                   = $query
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

    # Pattern 5: table in datatable() or externaldata() — skip, not real tables

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

function Get-FieldsFromKql {
    <#
    .SYNOPSIS
        Extracts column/field names referenced in a KQL query using regex heuristics.
        Returns unique field names used in where, project, summarize, join, and extend clauses.
    #>
    [CmdletBinding()]
    param([string]$Kql)

    if ([string]::IsNullOrWhiteSpace($Kql)) { return @() }

    $fields = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    # Operator pattern fragment (reused across patterns)
    $ops = '==|!=|<>|<=|>=|<|>|=~|!~|\bcontains\b|\b!contains\b|\bcontains_cs\b|\bhas\b|\b!has\b|\bhas_cs\b|\bstartswith\b|\b!startswith\b|\bendswith\b|\b!endswith\b|\bmatches\s+regex\b|\bin\s*\(|\b!in\s*\(|\bbetween\b|\bhas_any\b|\bhas_all\b'

    # 1. where <field> <operator>
    $m1 = [regex]::Matches($Kql, "(?i)\bwhere\s+(?:not\s+)?(\w+)\s*(?:$ops)")
    foreach ($m in $m1) { [void]$fields.Add($m.Groups[1].Value) }

    # 2. and/or <field> <operator>
    $m2 = [regex]::Matches($Kql, "(?i)\b(?:and|or)\s+(?:not\s+)?(\w+)\s*(?:$ops)")
    foreach ($m in $m2) { [void]$fields.Add($m.Groups[1].Value) }

    # 3. project / project-keep fields
    $m3 = [regex]::Matches($Kql, '(?i)\|\s*project(?:-keep)?\s+([\w\s,]+?)(?:\||$)')
    foreach ($m in $m3) {
        $parts = $m.Groups[1].Value -split ',' | ForEach-Object { ($_.Trim() -split '\s')[0] }
        foreach ($p in $parts) { if ($p -match '^\w+$' -and $p.Length -gt 1) { [void]$fields.Add($p) } }
    }

    # 4. project-away fields (these are also referenced)
    $m4 = [regex]::Matches($Kql, '(?i)\|\s*project-away\s+([\w\s,]+?)(?:\||$)')
    foreach ($m in $m4) {
        $parts = $m.Groups[1].Value -split ',' | ForEach-Object { ($_.Trim() -split '\s')[0] }
        foreach ($p in $parts) { if ($p -match '^\w+$' -and $p.Length -gt 1) { [void]$fields.Add($p) } }
    }

    # 5. summarize ... by <field1>, <field2>
    $m5 = [regex]::Matches($Kql, '(?i)\bby\s+([\w\s,()]+?)(?:\||$)')
    foreach ($m in $m5) {
        $parts = $m.Groups[1].Value -split ',' | ForEach-Object {
            $token = ($_.Trim() -split '\s')[0] -replace '[()]', ''
            $token
        }
        foreach ($p in $parts) { if ($p -match '^\w+$' -and $p.Length -gt 1) { [void]$fields.Add($p) } }
    }

    # 6. on <field> (join condition)
    $m6 = [regex]::Matches($Kql, '(?i)\bon\s+(\w+)')
    foreach ($m in $m6) { [void]$fields.Add($m.Groups[1].Value) }

    # 7. extend <field> = (new computed columns)
    $m7 = [regex]::Matches($Kql, '(?i)\bextend\s+(\w+)\s*=')
    foreach ($m in $m7) { [void]$fields.Add($m.Groups[1].Value) }

    # 8. isnotempty(<field>) / isnotnull(<field>) / isempty(<field>) / isnull(<field>)
    $m8 = [regex]::Matches($Kql, '(?i)\b(?:isnotempty|isnotnull|isempty|isnull)\s*\(\s*(\w+)\s*\)')
    foreach ($m in $m8) { [void]$fields.Add($m.Groups[1].Value) }

    # 9. mv-expand <field>
    $m9 = [regex]::Matches($Kql, '(?i)\bmv-expand\s+(\w+)')
    foreach ($m in $m9) { [void]$fields.Add($m.Groups[1].Value) }

    # Filter out KQL keywords, functions, and operators
    $kqlKeywords = @(
        'source', 'where', 'project', 'extend', 'summarize', 'render', 'sort', 'order',
        'top', 'take', 'count', 'distinct', 'evaluate', 'parse', 'invoke', 'not',
        'limit', 'sample', 'search', 'find', 'print', 'range', 'datatable',
        'materialize', 'toscalar', 'let', 'and', 'or', 'typeof', 'true', 'false',
        'contains', 'has', 'startswith', 'endswith', 'between', 'matches', 'regex',
        'ago', 'now', 'datetime', 'timespan', 'time', 'dynamic', 'real', 'long', 'int',
        'bin', 'tolower', 'toupper', 'tostring', 'toint', 'tolong', 'todouble', 'tobool',
        'set', 'alias', 'restrict', 'declare', 'pattern', 'kind', 'inner', 'outer',
        'leftouter', 'rightouter', 'fullouter', 'leftanti', 'rightanti', 'leftsemi',
        'isnotempty', 'isempty', 'isnotnull', 'isnull', 'strcat', 'format_timespan',
        'countif', 'sumif', 'avgif', 'minif', 'maxif', 'dcountif', 'makelist', 'makeset',
        'arg_max', 'arg_min', 'dcount', 'avg', 'sum', 'min', 'max', 'any', 'all',
        'pack', 'pack_all', 'parse_json', 'array_length', 'bag_keys', 'bag_unpack',
        'union', 'join', 'lookup', 'asc', 'desc', 'nulls', 'first', 'last',
        'prev', 'next', 'row_number', 'serialize', 'todynamic', 'split', 'trim',
        'replace', 'extract', 'parse_path', 'parse_url', 'parse_urlquery',
        'format_datetime', 'todatetime', 'make_datetime', 'make_timespan',
        'geo_info_from_ip_address', 'ipv4_is_private', 'ipv4_is_match',
        'case', 'iff', 'coalesce', 'iif', 'ingestion_time'
    )

    @($fields | Where-Object { $_ -notin $kqlKeywords -and $_.Length -gt 1 })
}
