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
        $response = Invoke-RestMethod -Uri $dcrUri -Headers $headers -ErrorAction Stop
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
    catch { }

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

function New-SplitKql {
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
        [hashtable]$HighValueFieldsDB
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

    # 3. Merge field sets
    $allFields = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [void]$allFields.Add('TimeGenerated')  # Always include
    foreach ($f in $ruleFields)  { [void]$allFields.Add($f) }
    foreach ($f in $hvFields)    { [void]$allFields.Add($f) }

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

    [PSCustomObject]@{
        TableName       = $TableName
        SplitKql        = $splitKql
        ProjectKql      = $projectKql
        RuleFields      = @($ruleFields | Sort-Object)
        HighValueFields = $hvFields
        AllFields       = @($allFields | Sort-Object)
        RuleCount       = if ($Rules) { @($Rules | Where-Object { $_.Enabled -and $_.Tables -contains $TableName }).Count } else { 0 }
        ConditionCount  = $ruleConditions.Count
        Source          = $source
        Description     = if ($hvEntry) { $hvEntry.description } else { $null }
    }
}
