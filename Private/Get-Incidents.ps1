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
