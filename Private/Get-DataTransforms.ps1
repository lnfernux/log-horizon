function Get-DataTransforms {
    <#
    .SYNOPSIS
        Discovers Data Collection Rules (DCRs) with ingest-time transforms,
        filters, or split configurations targeting the workspace.
    .DESCRIPTION
        Discovery order (results are de-duplicated on DCR id):
        1. List DCRs at subscription scope and keep those whose Log Analytics
           destination is this workspace. Falls back to the resource-group scope
           when the subscription list is not permitted.
        2. The workspace transformation DCR referenced by the workspace's
           defaultDataCollectionRuleResourceId (when supplied).
        3. Data collection rule associations on the workspace resource, each
           dereferenced to its DCR.
        Failures are reported through Write-Warning and in DiscoveryStatus so a
        least-privilege identity does not silently produce "no transforms".
    .OUTPUTS
        PSCustomObject with Transforms (array of per-table transform info),
        TableLookup, RelevantDCRs, TotalDCRs and DiscoveryStatus.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Context,
        [string]$WorkspaceDefaultDcrId,
        [string]$ApiVersion = '2024-03-11'
    )

    $headers = @{ Authorization = "Bearer $($Context.ArmToken)" }
    $arm = Get-LogHorizonEndpoint -Name Arm -Context $Context
    $workspaceId = "$($Context.ResourceId)"

    $dcrById = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    $status = [ordered]@{
        SubscriptionList  = 'NotAttempted'
        ResourceGroupList = 'NotAttempted'
        DefaultDcr        = 'NotAttempted'
        Associations      = 'NotAttempted'
        Errors            = [System.Collections.Generic.List[string]]::new()
    }

    $addDcr = {
        param($dcr)
        if ($dcr -and $dcr.id -and -not $dcrById.ContainsKey("$($dcr.id)")) { $dcrById["$($dcr.id)"] = $dcr }
    }

    # 1. Subscription scope, filtered on destination workspace; resource group scope as fallback
    $listed = $false
    foreach ($scope in 'Subscription', 'ResourceGroup') {
        $listUri = if ($scope -eq 'Subscription') {
            "$arm/subscriptions/$($Context.SubscriptionId)/providers/Microsoft.Insights/dataCollectionRules?api-version=$ApiVersion"
        } else {
            "$arm/subscriptions/$($Context.SubscriptionId)/resourceGroups/$($Context.ResourceGroup)/providers/Microsoft.Insights/dataCollectionRules?api-version=$ApiVersion"
        }
        try {
            $count = 0
            foreach ($dcr in (Get-ArmListPage -Uri $listUri -Headers $headers)) {
                if (Test-DcrTargetsWorkspace -Dcr $dcr -WorkspaceResourceId $workspaceId) {
                    & $addDcr $dcr
                    $count++
                }
            }
            $status["${scope}List"] = "Succeeded ($count matching)"
            $listed = $true
            break
        }
        catch {
            $status["${scope}List"] = 'Failed'
            $status.Errors.Add("${scope} DCR list: $(Get-ArmErrorSummary -ErrorRecord $_)")
            Write-Verbose "Could not list DCRs at $scope scope: $($_.Exception.Message)"
        }
    }

    # 2. Workspace transformation DCR
    if (-not [string]::IsNullOrWhiteSpace($WorkspaceDefaultDcrId)) {
        try {
            $dcr = Invoke-AzRestWithRetry -Uri "$arm$WorkspaceDefaultDcrId`?api-version=$ApiVersion" -Headers $headers
            & $addDcr $dcr
            $status.DefaultDcr = 'Succeeded'
        }
        catch {
            $status.DefaultDcr = 'Failed'
            $status.Errors.Add("Default DCR: $(Get-ArmErrorSummary -ErrorRecord $_)")
            Write-Warning "The workspace has a transformation DCR ($WorkspaceDefaultDcrId) but it could not be read ($(Get-ArmErrorSummary -ErrorRecord $_)). Workspace-level transforms will be missing from the analysis."
        }
    }
    else {
        $status.DefaultDcr = 'NotConfigured'
    }

    # 3. Associations on the workspace resource
    $assocUri = "$arm$workspaceId/providers/Microsoft.Insights/dataCollectionRuleAssociations?api-version=$ApiVersion"
    try {
        $assocIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($assoc in (Get-ArmListPage -Uri $assocUri -Headers $headers)) {
            $id = $assoc.properties.dataCollectionRuleId
            if (-not [string]::IsNullOrWhiteSpace($id)) { [void]$assocIds.Add("$id") }
        }
        $fetched = 0
        foreach ($id in $assocIds) {
            if ($dcrById.ContainsKey($id)) { continue }
            try {
                $dcr = Invoke-AzRestWithRetry -Uri "$arm$id`?api-version=$ApiVersion" -Headers $headers
                & $addDcr $dcr
                $fetched++
            }
            catch {
                $status.Errors.Add("Associated DCR ${id}: $(Get-ArmErrorSummary -ErrorRecord $_)")
                Write-Verbose "Could not read associated DCR ${id}: $($_.Exception.Message)"
            }
        }
        $status.Associations = "Succeeded ($($assocIds.Count) association(s), $fetched fetched)"
    }
    catch {
        $status.Associations = 'Failed'
        $status.Errors.Add("Associations: $(Get-ArmErrorSummary -ErrorRecord $_)")
        Write-Verbose "Could not list DCR associations: $($_.Exception.Message)"
    }

    if (-not $listed -and $status.Associations -eq 'Failed') {
        Write-Warning "DCR discovery failed on every route. Grant Microsoft.Insights/dataCollectionRules/read (Monitoring Reader) on the subscription or resource group to enable transform analysis. $($status.Errors -join ' | ')"
    }
    elseif (-not $listed) {
        Write-Warning 'DCR listing was denied; only DCRs associated directly with the workspace were discovered. Grant Microsoft.Insights/dataCollectionRules/read on the subscription for full transform coverage.'
    }

    $dcrs = @($dcrById.Values)

    # Parse transforms from DCR dataFlows
    $transforms = [System.Collections.Generic.List[PSCustomObject]]::new()
    $relevantDCRs = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($dcr in $dcrs) {
        $props = $dcr.properties
        if (-not $props.dataFlows) { continue }

        $dcrHasTransform = $false

        foreach ($flow in $props.dataFlows) {
            $kql = Resolve-DcrFlowTransformKql -Flow $flow -Properties $props
            if (-not $kql -or $kql.Trim() -eq 'source') { continue }

            $dcrHasTransform = $true

            # Output table: outputStream ("Microsoft-X", "Custom-X_CL"), or the first stream for
            # workspace transformation DCRs whose streams are "Microsoft-Table-X" and have no outputStream
            $outputTable = $null
            if ($flow.outputStream) {
                $outputTable = ConvertTo-DcrTableName -Stream $flow.outputStream
            }
            elseif ($flow.streams) {
                $outputTable = ConvertTo-DcrTableName -Stream (@($flow.streams)[0])
            }

            $inputStreams = @()
            if ($flow.streams) {
                $inputStreams = @($flow.streams | ForEach-Object { ConvertTo-DcrTableName -Stream $_ })
            }

            $transformType = Get-TransformType -KQL $kql

            $transforms.Add([PSCustomObject]@{
                DCRName         = $dcr.name
                DCRId           = $dcr.id
                DCRKind         = $dcr.kind
                OutputTable     = $outputTable
                InputStreams    = $inputStreams
                TransformKql    = $kql
                TransformType   = $transformType
                Operations      = @(Get-TransformOperation -KQL $kql)
                Destination     = if ($flow.destinations) { $flow.destinations -join ', ' } else { '' }
            })
        }

        if ($dcrHasTransform) {
            $relevantDCRs.Add([PSCustomObject]@{
                Name     = $dcr.name
                Id       = $dcr.id
                Location = $dcr.location
                Kind     = if ($dcr.kind) { $dcr.kind } else { $props.description }
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
        Transforms      = @($transforms)
        TableLookup     = $tableLookup
        RelevantDCRs    = @($relevantDCRs)
        TotalDCRs       = $dcrs.Count
        DiscoveryStatus = [PSCustomObject]$status
    }
}

function Get-ArmListPage {
    <#
    .SYNOPSIS
        Enumerates an ARM list endpoint, following nextLink.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [int]$MaxPages = 1000
    )

    $page = 0
    do {
        $page++
        $response = Invoke-AzRestWithRetry -Uri $Uri -Headers $Headers
        foreach ($item in @($response.value)) { $item }
        $Uri = $response.nextLink
        if ($page -ge $MaxPages) {
            Write-Warning "Pagination limit reached for $Uri. Stopping to avoid infinite loop."
            break
        }
    } while ($Uri)
}

function Get-ArmErrorSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    $code = $null
    if ($ErrorRecord.Exception.Response) { try { $code = [int]$ErrorRecord.Exception.Response.StatusCode } catch { $code = $null } }
    $detail = "$($ErrorRecord.ErrorDetails.Message)"
    if ($detail -match '"code"\s*:\s*"([^"]+)"') { $detail = $Matches[1] }
    elseif ([string]::IsNullOrWhiteSpace($detail)) { $detail = $ErrorRecord.Exception.Message }
    if ($detail.Length -gt 120) { $detail = $detail.Substring(0, 120) }
    if ($code) { "HTTP $code $detail" } else { $detail }
}

function Test-DcrTargetsWorkspace {
    <#
    .SYNOPSIS
        True when any Log Analytics destination of the DCR is the given workspace.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Dcr,
        [Parameter(Mandatory)][string]$WorkspaceResourceId
    )

    $dests = $Dcr.properties.destinations
    if (-not $dests -or -not $dests.logAnalytics) { return $false }
    foreach ($la in @($dests.logAnalytics)) {
        if ("$($la.workspaceResourceId)" -ieq $WorkspaceResourceId) { return $true }
    }
    $false
}

function ConvertTo-DcrTableName {
    <#
    .SYNOPSIS
        Strips DCR stream prefixes: Microsoft-Table-X, Microsoft-X, Custom-X.
    #>
    [CmdletBinding()]
    param([string]$Stream)

    if ([string]::IsNullOrWhiteSpace($Stream)) { return $null }
    $Stream -replace '^(Microsoft-Table-|Microsoft-|Custom-)', ''
}

function Resolve-DcrFlowTransformKql {
    <#
    .SYNOPSIS
        Returns the transform KQL for a data flow: inline transformKql, or the KQL
        processors of the named multi-stage transformation it references.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Flow,
        [object]$Properties
    )

    if ($Flow.transformKql) { return [string]$Flow.transformKql }

    $name = $Flow.transform
    if ([string]::IsNullOrWhiteSpace("$name") -or -not $Properties -or -not $Properties.transformations) { return $null }

    $tr = @($Properties.transformations | Where-Object { "$($_.name)" -eq "$name" }) | Select-Object -First 1
    if (-not $tr) { return $null }

    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($p in @($tr.processors)) {
        if (-not $p) { continue }
        $kind = "$($p.processor)"
        $cfg = $p.configuration
        $expr = $null
        if ($cfg) {
            if ($cfg.PSObject.Properties.Name -contains 'expression') { $expr = $cfg.expression }
            elseif ($cfg.PSObject.Properties.Name -contains 'transformKql') { $expr = $cfg.transformKql }
        }
        if ($kind -match '(?i)kql' -and -not [string]::IsNullOrWhiteSpace("$expr")) { $parts.Add(("$expr").Trim()) }
    }
    if ($parts.Count -eq 0) { return $null }
    $parts -join "`n"
}

function Get-TransformOperation {
    <#
    .SYNOPSIS
        Lists every operation a transform KQL performs, in order of first appearance:
        Filter, ColumnRemoval, Projection, Enrichment, Aggregation. Empty when none match.
    #>
    [CmdletBinding()]
    param([string]$KQL)

    $ops = [System.Collections.Generic.List[string]]::new()
    if ([string]::IsNullOrWhiteSpace($KQL)) { return @() }
    $kqlLower = $KQL.ToLower()

    $patterns = [ordered]@{
        Filter        = '\|\s*where\s+'
        ColumnRemoval = '\|\s*project-away\s+'
        Projection    = '\|\s*project\s+'
        Enrichment    = '\|\s*extend\s+'
        Aggregation   = '\|\s*summarize\s+'
    }
    $found = foreach ($k in $patterns.Keys) {
        $m = [regex]::Match($kqlLower, $patterns[$k])
        if ($m.Success) { [PSCustomObject]@{ Op = $k; Index = $m.Index } }
    }
    foreach ($f in @($found | Sort-Object Index)) { $ops.Add($f.Op) }
    @($ops)
}

function Get-TransformType {
    <#
    .SYNOPSIS
        Classifies a transform KQL expression. Single-operation transforms return
        that label (Filter, ColumnRemoval, Projection, Enrichment, Aggregation);
        multi-operation transforms return the labels joined with '+', in order of
        appearance; anything else is Custom.
    #>
    [CmdletBinding()]
    param([string]$KQL)

    $ops = @(Get-TransformOperation -KQL $KQL)
    if ($ops.Count -eq 0) { return 'Custom' }
    $ops -join '+'
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
    $tableEntryMap = @{}
    foreach ($te in @($TableAnalysis)) { if ($te.TableName -and -not $tableEntryMap.ContainsKey($te.TableName)) { $tableEntryMap[$te.TableName] = $te } }

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

            foreach ($condition in (Get-KqlWhereCondition -Kql $rule.Query)) {
                $tableConditionMap[$tableName].Add($condition)
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

        # Fields referenced by rules but absent from the live schema (joined-table columns, renamed fields)
        $droppedFields = @()
        if ($schemaColumns.Count -gt 0) {
            $schemaSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$schemaColumns, [StringComparer]::OrdinalIgnoreCase)
            $droppedFields = @($usedFields | Where-Object { $_ -ne 'TimeGenerated' -and -not $schemaSet.Contains($_) } | Sort-Object)
            foreach ($d in $droppedFields) { [void]$usedFields.Remove($d) }
        }

        # Compute unused fields (schema - used)
        $unusedFields = @()
        if ($schemaColumns.Count -gt 0) {
            $unusedFields = @($schemaColumns | Where-Object { -not $usedFields.Contains($_) } | Sort-Object)
        }

        # Lookup table analysis entry for cost data
        $tableEntry = if ($tableEntryMap.ContainsKey($tableName)) { $tableEntryMap[$tableName] } else { $null }
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
            DroppedFields      = $droppedFields
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
        HighValueFields, DroppedFields (candidates not in the live schema) and Source.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TableName,
        [array]$Rules,
        [hashtable]$HighValueFieldsDB,
        [hashtable]$FieldFrequencyStats,
        [string]$TableCategory,
        [string[]]$SchemaColumns = @()
    )

    # 1. Extract fields from rules targeting this table
    $ruleFields = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $ruleConditions = [System.Collections.Generic.List[string]]::new()

    $tableRulesAll = @()
    if ($Rules) {
        $tableRulesAll = @($Rules | Where-Object { $_.Enabled -and $_.Tables -contains $TableName })
        $tableRules = @($tableRulesAll | Where-Object { $_.Query })
        foreach ($rule in $tableRules) {
            $fields = Get-FieldsFromKql -Kql $rule.Query
            foreach ($f in $fields) { [void]$ruleFields.Add($f) }

            foreach ($condition in (Get-KqlWhereCondition -Kql $rule.Query)) {
                $ruleConditions.Add($condition)
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

    # 3. Merge field sets, then keep only columns that exist in the live schema (when known)
    $allFields = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [void]$allFields.Add('TimeGenerated')  # Always include
    foreach ($f in $ruleFields)     { [void]$allFields.Add($f) }
    foreach ($f in $hvFields)       { [void]$allFields.Add($f) }
    foreach ($f in $fallbackFields) { [void]$allFields.Add($f) }

    $droppedFields = @()
    if ($SchemaColumns -and $SchemaColumns.Count -gt 0) {
        $schemaSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$SchemaColumns, [StringComparer]::OrdinalIgnoreCase)
        $droppedFields = @($allFields | Where-Object { $_ -ne 'TimeGenerated' -and -not $schemaSet.Contains($_) } | Sort-Object)
        foreach ($d in $droppedFields) { [void]$allFields.Remove($d) }
    }

    # 4. Generate KQL (condition-only - the Sentinel portal prepends "source | where" implicitly)
    $splitKql = $null
    $projectKql = $null
    $source = 'none'
    $uniqueConditions = @($ruleConditions | Select-Object -Unique | Select-Object -First 10)

    # Prefer knowledge-base split hint if available (these are curated)
    if ($splitHint) {
        $splitKql = $splitHint.kql
        $source = 'knowledge-base'

        # Rule conditions widen the hint so every row a deployed rule needs stays in Analytics
        if ($uniqueConditions.Count -gt 0) {
            $hintNorm = ("$splitKql" -replace '\s+', ' ').Trim()
            $extra = @($uniqueConditions | Where-Object { (($_ -replace '\s+', ' ').Trim()) -ine $hintNorm })
            if ($extra.Count -gt 0) {
                $ruleClause = ($extra | ForEach-Object { "($($_))" }) -join "`n    or "
                $splitKql = "($splitKql)`n    or $ruleClause"
            }
            $source = 'combined'
        }
    }
    elseif ($uniqueConditions.Count -gt 0) {
        # Build split KQL from rule conditions (OR them together - keep any row a rule cares about)
        $splitKql = ($uniqueConditions | ForEach-Object { "($($_))" }) -join "`n    or "
        $source = 'rule-analysis'
    }

    # Always generate a projection KQL (useful for column reduction transforms - these use full KQL syntax)
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
        DroppedFields   = $droppedFields
        RuleCount       = $tableRulesAll.Count
        ConditionCount  = $ruleConditions.Count
        Source          = $source
        FallbackSource  = $fallbackSource
        Description     = if ($hvEntry) { $hvEntry.description } else { $null }
    }
}

function Get-KqlWhereCondition {
    <#
    .SYNOPSIS
        Extracts the predicate of each "| where" clause (5-200 chars) with a regex timeout.
        Multi-line predicates are collapsed to one line.
    #>
    [CmdletBinding()]
    param(
        [string]$Kql,
        [int]$MinLength = 5,
        [int]$MaxLength = 200
    )

    if ([string]::IsNullOrWhiteSpace($Kql)) { return @() }
    $results = [System.Collections.Generic.List[string]]::new()
    try {
        $rx = [regex]::new('(?is)\|\s*where\s+(.+?)(?=\||$)', [System.Text.RegularExpressions.RegexOptions]::None, [timespan]::FromSeconds(2))
        foreach ($m in $rx.Matches($Kql)) {
            $condition = ($m.Groups[1].Value -replace '\s+', ' ').Trim()
            if ($condition.Length -gt $MinLength -and $condition.Length -lt $MaxLength) { $results.Add($condition) }
        }
    }
    catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
        Write-Warning 'Regex execution timed out while extracting where conditions from KQL.'
    }
    @($results)
}
