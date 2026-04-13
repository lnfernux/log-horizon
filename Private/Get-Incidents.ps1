function Get-Incidents {
    <#
    .SYNOPSIS
        Fetches Sentinel incidents and normalizes fields used by Detection Analyzer.
    .OUTPUTS
        Array of PSCustomObject incidents.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Context,
        [ValidateRange(1, 365)][int]$DaysBack = 90
    )

    $headers = @{ Authorization = "Bearer $($Context.ArmToken)" }
    $since = (Get-Date).ToUniversalTime().AddDays(-$DaysBack).ToString('o')
    $escapedSince = [System.Uri]::EscapeDataString("properties/createdTimeUtc ge $since")
    $uri = "https://management.azure.com$($Context.ResourceId)" +
           "/providers/Microsoft.SecurityInsights/incidents?api-version=2021-10-01&`$filter=$escapedSince"

    $allIncidents = [System.Collections.Generic.List[object]]::new()
    $maxPages = 1000
    $pageCount = 0

    do {
        $pageCount++
        $response = Invoke-AzRestWithRetry -Uri $uri -Headers $headers
        foreach ($incident in $response.value) { $allIncidents.Add($incident) }
        $uri = $response.nextLink

        if ($pageCount -ge $maxPages) {
            Write-Warning 'Pagination limit reached fetching incidents. Stopping to avoid infinite loop.'
            break
        }
    } while ($uri)

    $normalized = foreach ($incident in $allIncidents) {
        $props = $incident.properties
        $created = ConvertTo-UtcDateOrNull -Value $props.createdTimeUtc
        $closed = ConvertTo-UtcDateOrNull -Value $props.closedTimeUtc
        $modified = ConvertTo-UtcDateOrNull -Value $props.lastModifiedTimeUtc

        [PSCustomObject]@{
            IncidentId                 = $incident.name
            IncidentNumber             = [int]$props.incidentNumber
            Title                      = $props.title
            Status                     = $props.status
            Severity                   = $props.severity
            Classification             = $props.classification
            ClassificationReason       = $props.classificationReason
            CreatedTimeUtc             = $created
            ClosedTimeUtc              = $closed
            LastModifiedTimeUtc        = $modified
            RelatedAnalyticRuleIds     = @(Get-NormalizedArray -Value $props.relatedAnalyticRuleIds)
            RelatedAnalyticRuleNames   = @(Get-NormalizedArray -Value $props.relatedAnalyticRuleNames)
            Owner                      = if ($props.owner) { $props.owner.userPrincipalName } else { $null }
            Raw                         = $incident
        }
    }

    @($normalized)
}

function ConvertTo-UtcDateOrNull {
    [CmdletBinding()]
    param([object]$Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace("$Value")) {
        return $null
    }

    try {
        return ([datetime]$Value).ToUniversalTime()
    }
    catch {
        return $null
    }
}

function Get-NormalizedArray {
    [CmdletBinding()]
    param([object]$Value)

    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Array]) { return @($Value | ForEach-Object { "$_" } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) }

    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
        return @($Value)
    }

    return @("$Value")
}

function Get-AutoCloseFromHealth {
    <#
    .SYNOPSIS
        Queries SentinelHealth for automation rule run events to determine auto-closed incidents.
    .DESCRIPTION
        Checks if SentinelHealth table is available (health monitoring enabled), then queries for
        automation rule run events. Cross-references with known close-incident automation rules
        to return a set of incident numbers that were auto-closed.
    .OUTPUTS
        Hashtable of IncidentNumber (int) -> $true, or $null if SentinelHealth is unavailable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Context,
        [int]$DaysBack = 90,
        [string[]]$CloseRuleNames = @()
    )

    $headers = @{
        Authorization  = "Bearer $($Context.LaToken)"
        'Content-Type' = 'application/json'
    }
    $baseUri = "https://api.loganalytics.io/v1/workspaces/$($Context.WorkspaceId)/query"

    # Check if SentinelHealth table exists
    $checkQuery = 'SentinelHealth | take 1'
    $checkBody = @{ query = $checkQuery } | ConvertTo-Json -Compress
    try {
        $checkResponse = Invoke-AzRestWithRetry -Uri $baseUri -Method Post -Headers $headers -Body $checkBody
        if (-not $checkResponse.tables -or $checkResponse.tables[0].rows.Count -eq 0) {
            Write-Verbose 'SentinelHealth table exists but has no data.'
        }
    }
    catch {
        Write-Verbose "SentinelHealth table not available: $_"
        return $null
    }

    # Query automation rule run events
    $query = @"
SentinelHealth
| where TimeGenerated > ago(${DaysBack}d)
| where OperationName == "Automation rule run"
| where Status in ("Success", "Partial success")
| extend props = parse_json(ExtendedProperties)
| extend IncidentNumber = toint(props.IncidentNumber)
| extend RuleName = SentinelResourceName
| where isnotempty(IncidentNumber)
| project IncidentNumber, RuleName
| distinct IncidentNumber, RuleName
"@

    $body = @{ query = $query } | ConvertTo-Json -Compress
    try {
        $response = Invoke-AzRestWithRetry -Uri $baseUri -Method Post -Headers $headers -Body $body
    }
    catch {
        Write-Warning "Failed to query SentinelHealth for auto-close data: $_"
        return $null
    }

    $rows = $response.tables[0].rows
    Write-Verbose "SentinelHealth returned $($rows.Count) automation rule run event(s)."

    if ($rows.Count -eq 0) {
        return @{}
    }

    # If we have close rule names, filter to only those rules; otherwise return all
    $autoClosedSet = @{}
    foreach ($row in $rows) {
        $incidentNum = [int]$row[0]
        $ruleName    = "$($row[1])"

        if ($CloseRuleNames.Count -eq 0 -or $ruleName -in $CloseRuleNames) {
            $autoClosedSet[$incidentNum] = $true
        }
    }

    Write-Verbose "Identified $($autoClosedSet.Count) auto-closed incident(s) from SentinelHealth."
    $autoClosedSet
}
