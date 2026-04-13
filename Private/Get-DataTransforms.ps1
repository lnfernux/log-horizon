function Get-DataTransforms {
    <#
    .SYNOPSIS
        Discovers Data Collection Rules (DCRs) with ingest-time transforms,
        filters, or split configurations targeting the workspace.
    .OUTPUTS
        PSCustomObject with Transforms (array of per-table transform info)
        and RawDCRs (array of all relevant DCRs).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Context
    )

    $headers = @{ Authorization = "Bearer $($Context.ArmToken)" }

    # List all DCRs in the resource group
    $dcrUri = "https://management.azure.com/subscriptions/$($Context.SubscriptionId)" +
              "/resourceGroups/$($Context.ResourceGroup)" +
              "/providers/Microsoft.Insights/dataCollectionRules?api-version=2023-03-11"

    $dcrs = @()
    try {
        $response = Invoke-AzRestWithRetry -Uri $dcrUri -Headers $headers
        $dcrs = @($response.value)
    }
    catch {
        Write-Verbose "Could not list DCRs: $_"
    }

    # Also check workspace-level transformation DCR
    $wsDcrUri = "https://management.azure.com$($Context.ResourceId)" +
                "/providers/Microsoft.Insights/dataCollectionRules?api-version=2023-03-11"
    try {
        $wsResponse = Invoke-RestMethod -Uri $wsDcrUri -Headers $headers -ErrorAction SilentlyContinue
        if ($wsResponse.value) {
            $dcrs += @($wsResponse.value)
        }
    }
    catch { 
        Write-Verbose "Could not check workspace-level DCRs."
    }

    # Parse transforms from DCR dataFlows
    $transforms = [System.Collections.Generic.List[PSCustomObject]]::new()
    $relevantDCRs = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($dcr in $dcrs) {
        $props = $dcr.properties
        if (-not $props.dataFlows) { continue }

        $dcrHasTransform = $false

        foreach ($flow in $props.dataFlows) {
            $kql = $flow.transformKql
            if (-not $kql -or $kql -eq 'source') { continue }

            $dcrHasTransform = $true

            # Determine output table from outputStream (format: "Microsoft-TableName" or "Custom-TableName_CL")
            $outputTable = $null
            if ($flow.outputStream) {
                $outputTable = $flow.outputStream -replace '^(Microsoft|Custom)-', ''
            }

            # Determine input streams
            $inputStreams = @()
            if ($flow.streams) {
                $inputStreams = @($flow.streams | ForEach-Object { $_ -replace '^(Microsoft|Custom)-', '' })
            }

            # Classify transform type
            $transformType = Get-TransformType -KQL $kql

            $transforms.Add([PSCustomObject]@{
                DCRName         = $dcr.name
                DCRId           = $dcr.id
                OutputTable     = $outputTable
                InputStreams    = $inputStreams
                TransformKql    = $kql
                TransformType   = $transformType
                Destination     = if ($flow.destinations) { $flow.destinations -join ', ' } else { '' }
            })
        }

        if ($dcrHasTransform) {
            $relevantDCRs.Add([PSCustomObject]@{
                Name     = $dcr.name
                Id       = $dcr.id
                Location = $dcr.location
                Kind     = $props.description
            })
        }
    }

    # Build per-table lookup
    $tableLookup = @{}
    foreach ($t in $transforms) {
        $key = $t.OutputTable
        if (-not $key) { continue }
        if (-not $tableLookup.ContainsKey($key)) {
            $tableLookup[$key] = [System.Collections.Generic.List[PSCustomObject]]::new()
        }
        $tableLookup[$key].Add($t)
    }

    [PSCustomObject]@{
        Transforms   = @($transforms)
        TableLookup  = $tableLookup
        RelevantDCRs = @($relevantDCRs)
        TotalDCRs    = $dcrs.Count
    }
}

function Get-TransformType {
    <#
    .SYNOPSIS
        Classifies a transform KQL expression into a category.
    #>
    [CmdletBinding()]
    param([string]$KQL)

    $kqlLower = $KQL.ToLower().Trim()

    # Filter: where clause that drops records
    if ($kqlLower -match '^\s*source\s*\|\s*where\s+' -and $kqlLower -notmatch '\|\s*project') {
        return 'Filter'
    }

    # Column removal: project-away
    if ($kqlLower -match 'project-away') {
        return 'ColumnRemoval'
    }

    # Enrichment: extend adds columns
    if ($kqlLower -match '\|\s*extend\s+') {
        return 'Enrichment'
    }

    # Projection: project selects columns
    if ($kqlLower -match '\|\s*project\s+') {
        return 'Projection'
    }

    # Aggregation: summarize
    if ($kqlLower -match '\|\s*summarize\s+') {
        return 'Aggregation'
    }

    'Custom'
}

function Get-LiveTuningAnalysis {
    <#
    .SYNOPSIS
        Analyzes the customer's deployed rules to build per-table tuning KQL
        (filter, project, combined) using live rule data and schema columns.
    .OUTPUTS
        Array of PSCustomObjects, one per table, with filter/project/combined KQL,
        field usage stats, and estimated savings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Rules,
        [array]$HuntingQueries = @(),
        [array]$TableAnalysis = @(),
        [hashtable]$SchemaLookup = @{}
    )

    # Build per-table field + condition maps from deployed rules
    $tableFieldMap = @{}      # TableName -> HashSet of field names
    $tableConditionMap = @{}  # TableName -> List of WHERE conditions
    $tableRuleMap = @{}       # TableName -> List of rule objects (for field-by-rule matrix)

    $allSources = @($Rules) + @($HuntingQueries | Where-Object { $_.Query })
    foreach ($rule in $allSources) {
        if (-not $rule.Enabled -or -not $rule.Query) { continue }
        $tables = if ($rule.Tables) { $rule.Tables } else { @() }

        foreach ($tableName in $tables) {
            if (-not $tableFieldMap.ContainsKey($tableName)) {
                $tableFieldMap[$tableName] = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                $tableConditionMap[$tableName] = [System.Collections.Generic.List[string]]::new()
                $tableRuleMap[$tableName] = [System.Collections.Generic.List[PSCustomObject]]::new()
            }

            $fields = Get-FieldsFromKql -Kql $rule.Query
            foreach ($f in $fields) { [void]$tableFieldMap[$tableName].Add($f) }

            # Extract WHERE conditions
            $whereMatches = [regex]::Matches($rule.Query, '(?i)\|\s*where\s+(.+?)(?:\||$)')
            foreach ($wm in $whereMatches) {
                $condition = $wm.Groups[1].Value.Trim()
                if ($condition.Length -gt 5 -and $condition.Length -lt 200) {
                    $tableConditionMap[$tableName].Add($condition)
                }
            }

            $ruleName = if ($rule.RuleName) { $rule.RuleName } elseif ($rule.QueryName) { $rule.QueryName } elseif ($rule.DisplayName) { $rule.DisplayName } else { 'Unknown' }
            $tableRuleMap[$tableName].Add([PSCustomObject]@{
                RuleName = $ruleName
                Fields   = @($fields)
            })
        }
    }

    # Generate per-table analysis for tables that have at least 1 rule
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($tableName in ($tableFieldMap.Keys | Sort-Object)) {
        $usedFields = $tableFieldMap[$tableName]
        [void]$usedFields.Add('TimeGenerated')  # Always include

        $conditions = $tableConditionMap[$tableName]
        $ruleDetails = $tableRuleMap[$tableName]

        # Get schema columns if available
        $schemaColumns = @()
        if ($SchemaLookup.ContainsKey($tableName)) {
            $schemaColumns = @($SchemaLookup[$tableName])
        }

        # Compute unused fields (schema - used)
        $unusedFields = @()
        if ($schemaColumns.Count -gt 0) {
            $unusedFields = @($schemaColumns | Where-Object { -not $usedFields.Contains($_) } | Sort-Object)
        }

        # Lookup table analysis entry for cost data
        $tableEntry = $TableAnalysis | Where-Object { $_.TableName -eq $tableName } | Select-Object -First 1
        $monthlyGB = if ($tableEntry) { $tableEntry.MonthlyGB } else { 0 }
        $monthlyCost = if ($tableEntry) { $tableEntry.EstMonthlyCostUSD } else { 0 }

        # Generate filter KQL (condition-only for portal)
        $filterKql = $null
        if ($conditions.Count -gt 0) {
            $uniqueConditions = @($conditions | Select-Object -Unique | Select-Object -First 10)
            $filterKql = ($uniqueConditions | ForEach-Object { "($($_))" }) -join "`n    or "
        }

        # Generate project KQL (full source | project syntax for DCR)
        $sortedUsed = @($usedFields | Sort-Object)
        $projectKql = $null
        if ($sortedUsed.Count -gt 1) {
            $projectKql = "source`n| project $($sortedUsed -join ', ')"
        }

        # Generate combined KQL
        $combinedKql = $null
        if ($filterKql -and $projectKql) {
            $combinedKql = "source`n| where $filterKql`n| project $($sortedUsed -join ', ')"
        }
        elseif ($filterKql) {
            $combinedKql = "source`n| where $filterKql"
        }
        elseif ($projectKql) {
            $combinedKql = $projectKql
        }

        # Estimate savings
        $estFilterSavings = if ($filterKql -and $monthlyCost -gt 0) { [math]::Round($monthlyCost * 0.50, 2) } else { 0 }
        $estProjectSavings = 0
        if ($schemaColumns.Count -gt 0 -and $unusedFields.Count -gt 0 -and $monthlyCost -gt 0) {
            $reductionRatio = $unusedFields.Count / $schemaColumns.Count
            $estProjectSavings = [math]::Round($monthlyCost * $reductionRatio * 0.80, 2)  # ~80% of proportional savings
        }

        $results.Add([PSCustomObject]@{
            TableName          = $tableName
            MonthlyGB          = $monthlyGB
            EstMonthlyCostUSD  = $monthlyCost
            UsedFields         = @($sortedUsed)
            UnusedFields       = $unusedFields
            SchemaColumns      = $schemaColumns
            FieldCount         = $usedFields.Count
            SchemaColumnCount  = $schemaColumns.Count
            UnusedFieldCount   = $unusedFields.Count
            RuleCount          = $ruleDetails.Count
            ConditionCount     = $conditions.Count
            FilterKql          = $filterKql
            ProjectKql         = $projectKql
            CombinedKql        = $combinedKql
            EstFilterSavings   = $estFilterSavings
            EstProjectSavings  = $estProjectSavings
            RuleDetails        = @($ruleDetails)
        })
    }

    @($results)
}

function Get-SplitKql {
    <#
    .SYNOPSIS
        Generates a recommended split transform KQL for a table based on analytics
        rule field analysis and the high-value-fields knowledge base.
    .DESCRIPTION
        Combines fields extracted from deployed analytics rules with pre-built
        split hints from the knowledge base to produce a usable split KQL.
        The generated KQL routes detection-relevant rows to Analytics tier.

        IMPORTANT: The Sentinel portal split rule editor implicitly prepends
        "source | where" to the KQL you enter. The output of this function is
        condition-only (no "source | where" prefix) so it can be pasted directly
        into the portal. Submitting "source | where ..." in the portal will
        double-apply the prefix and cause a KQL syntax error.
    .OUTPUTS
        PSCustomObject with SplitKql (condition-only), ProjectKql, RuleFields,
        HighValueFields, and Source.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TableName,
        [array]$Rules,
        [hashtable]$HighValueFieldsDB,
        [hashtable]$FieldFrequencyStats,
        [string]$TableCategory
    )

    # 1. Extract fields from rules targeting this table
    $ruleFields = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $ruleConditions = [System.Collections.Generic.List[string]]::new()

    if ($Rules) {
        $tableRules = @($Rules | Where-Object { $_.Enabled -and $_.Tables -contains $TableName -and $_.Query })
        foreach ($rule in $tableRules) {
            $fields = Get-FieldsFromKql -Kql $rule.Query
            foreach ($f in $fields) { [void]$ruleFields.Add($f) }

            # Extract where conditions specific to this table for split hints
            $whereMatches = [regex]::Matches($rule.Query, '(?i)\|\s*where\s+(.+?)(?:\||$)')
            foreach ($wm in $whereMatches) {
                $condition = $wm.Groups[1].Value.Trim()
                if ($condition.Length -gt 5 -and $condition.Length -lt 200) {
                    $ruleConditions.Add($condition)
                }
            }
        }
    }

    # 2. Look up high-value fields from knowledge base
    $hvEntry = $null
    $hvFields = @()
    $splitHint = $null
    if ($HighValueFieldsDB -and $HighValueFieldsDB.ContainsKey($TableName)) {
        $hvEntry = $HighValueFieldsDB[$TableName]
        $hvFields = @($hvEntry.highValueFields)
        if ($hvEntry.splitHints -and $hvEntry.splitHints.Count -gt 0) {
            $splitHint = $hvEntry.splitHints[0]  # Use first (primary) hint
        }
    }

    # 2b. Fallback: use field-frequency-stats for tables not in KB and with no rules
    $fallbackSource = $null
    $fallbackFields = @()
    if (-not $hvEntry -and $ruleFields.Count -eq 0 -and $FieldFrequencyStats) {
        # Try per-table stats first
        if ($FieldFrequencyStats.perTable -and $FieldFrequencyStats.perTable.$TableName) {
            $perTableStats = $FieldFrequencyStats.perTable.$TableName
            # Get top fields by frequency (sorted by count descending)
            $fallbackFields = @($perTableStats.PSObject.Properties |
                Sort-Object { [int]$_.Value } -Descending |
                Select-Object -First 20 -ExpandProperty Name)
            $fallbackSource = 'community-stats'
        }
        # Then try category defaults
        elseif ($TableCategory -and $FieldFrequencyStats.categoryDefaults -and $FieldFrequencyStats.categoryDefaults.$TableCategory) {
            $fallbackFields = @($FieldFrequencyStats.categoryDefaults.$TableCategory)
            $fallbackSource = 'category-defaults'
        }
        # Last resort: universal fields
        elseif ($FieldFrequencyStats.universalFields) {
            $fallbackFields = @($FieldFrequencyStats.universalFields)
            $fallbackSource = 'universal'
        }
    }

    # 3. Merge field sets
    $allFields = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [void]$allFields.Add('TimeGenerated')  # Always include
    foreach ($f in $ruleFields)     { [void]$allFields.Add($f) }
    foreach ($f in $hvFields)       { [void]$allFields.Add($f) }
    foreach ($f in $fallbackFields) { [void]$allFields.Add($f) }

    # 4. Generate KQL (condition-only — the Sentinel portal prepends "source | where" implicitly)
    $splitKql = $null
    $projectKql = $null
    $source = 'none'

    # Prefer knowledge-base split hint if available (these are curated)
    if ($splitHint) {
        $splitKql = $splitHint.kql
        $source = 'knowledge-base'

        # If we have rule conditions, append them to enhance the hint
        if ($ruleConditions.Count -gt 0) {
            $source = 'combined'
        }
    }
    elseif ($ruleConditions.Count -gt 0) {
        # Build split KQL from rule conditions (OR them together — keep any row a rule cares about)
        $uniqueConditions = @($ruleConditions | Select-Object -Unique | Select-Object -First 10)
        $combined = ($uniqueConditions | ForEach-Object { "($($_))" }) -join "`n    or "
        $splitKql = $combined
        $source = 'rule-analysis'
    }

    # Always generate a projection KQL (useful for column reduction transforms — these use full KQL syntax)
    if ($allFields.Count -gt 1) {
        $sortedFields = @($allFields | Sort-Object)
        $projectKql = "source`n| project $($sortedFields -join ', ')"
    }

    # Determine effective source (including fallback)
    if ($source -eq 'none' -and $fallbackSource) {
        $source = $fallbackSource
    }

    [PSCustomObject]@{
        TableName       = $TableName
        SplitKql        = $splitKql
        ProjectKql      = $projectKql
        RuleFields      = @($ruleFields | Sort-Object)
        HighValueFields = $hvFields
        FallbackFields  = $fallbackFields
        AllFields       = @($allFields | Sort-Object)
        RuleCount       = if ($Rules) { @($Rules | Where-Object { $_.Enabled -and $_.Tables -contains $TableName }).Count } else { 0 }
        ConditionCount  = $ruleConditions.Count
        Source          = $source
        FallbackSource  = $fallbackSource
        Description     = if ($hvEntry) { $hvEntry.description } else { $null }
    }
}
