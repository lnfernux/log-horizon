function Get-DefenderXDR {
    <#
    .SYNOPSIS
        Queries Defender XDR for custom detection rules and streaming configuration.
        Requires -IncludeDefenderXDR flag and SecurityEvents.Read.All Graph permission.
    .OUTPUTS
        PSCustomObject with custom detection rules and XDR table analysis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Context
    )

    # Acquire Graph token
    $graphToken = $null
    try {
        $graphToken = (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com' -ErrorAction Stop).Token
    }
    catch {
        Write-Warning 'Cannot acquire Microsoft Graph token. Defender XDR analysis will be skipped.'
        return $null
    }

    $headers = @{
        Authorization  = "Bearer $graphToken"
        'Content-Type' = 'application/json'
    }

    # Fetch custom detection rules
    $customRules = @()
    try {
        $uri = 'https://graph.microsoft.com/v1.0/security/rules/detectionRules'
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -ErrorAction Stop
        $customRules = $response.value
    }
    catch {
        Write-Verbose "Could not fetch Defender custom detection rules: $_"
        # Try beta endpoint as fallback
        try {
            $uri = 'https://graph.microsoft.com/beta/security/rules/detectionRules'
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -ErrorAction Stop
            $customRules = $response.value
        }
        catch {
            Write-Verbose "Beta endpoint also failed: $_"
        }
    }

    # Parse XDR rule queries for table references
    $xdrTableCoverage = @{}
    foreach ($rule in $customRules) {
        $query = $rule.detectionAction.queryCondition.queryText
        if (-not $query) { $query = $rule.queryCondition.queryText }
        if ($query) {
            $tables = Get-TablesFromKql -Kql $query
            foreach ($t in $tables) {
                if (-not $xdrTableCoverage.ContainsKey($t)) { $xdrTableCoverage[$t] = 0 }
                $xdrTableCoverage[$t]++
            }
        }
    }

    # Known Defender XDR streaming tables
    $xdrStreamingTables = @(
        'DeviceEvents', 'DeviceProcessEvents', 'DeviceFileEvents',
        'DeviceRegistryEvents', 'DeviceNetworkEvents', 'DeviceLogonEvents',
        'DeviceImageLoadEvents', 'EmailEvents', 'EmailAttachmentInfo',
        'EmailUrlInfo', 'EmailPostDeliveryEvents', 'CloudAppEvents',
        'IdentityLogonEvents', 'IdentityQueryEvents', 'IdentityDirectoryEvents',
        'AlertEvidence', 'AlertInfo', 'UrlClickEvents'
    )

    [PSCustomObject]@{
        CustomRules      = $customRules
        TotalXDRRules    = $customRules.Count
        XDRTableCoverage = $xdrTableCoverage
        StreamingTables  = $xdrStreamingTables
    }
}
