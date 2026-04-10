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

    function ConvertTo-PlainTextToken {
        param([Parameter(Mandatory)]$AccessToken)

        if ($AccessToken -is [string]) {
            return $AccessToken
        }

        if ($AccessToken -is [securestring]) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken)
            try {
                return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            }
            finally {
                if ($bstr -ne [IntPtr]::Zero) {
                    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                }
            }
        }

        return [string]$AccessToken
    }

    # Fetch custom detection rules.
    # Prefer delegated user context via Microsoft Graph PowerShell for CustomDetection.Read.All.
    $customRules = @()
    $fetched = $false
    $endpoints = @(
        'https://graph.microsoft.com/beta/security/rules/detectionRules',
        'https://graph.microsoft.com/v1.0/security/rules/detectionRules'
    )

    $mgCmd = Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue
    if ($mgCmd) {
        try {
            $requiredScopes = @('CustomDetection.Read.All', 'CustomDetection.ReadWrite.All')
            $mgContext = Get-MgContext -ErrorAction SilentlyContinue
            $hasRequiredScope = $false

            if ($mgContext -and $mgContext.Scopes) {
                $hasRequiredScope = @($mgContext.Scopes | Where-Object { $_ -in $requiredScopes }).Count -gt 0
            }

            if (-not $hasRequiredScope) {
                $connectParams = @{
                    Scopes       = @('CustomDetection.Read.All')
                    ContextScope = 'Process'
                    NoWelcome    = $true
                }
                if ($Context.PSObject.Properties.Name -contains 'TenantId' -and -not [string]::IsNullOrWhiteSpace($Context.TenantId)) {
                    $connectParams.TenantId = $Context.TenantId
                }

                Connect-MgGraph @connectParams -ErrorAction Stop | Out-Null
                $mgContext = Get-MgContext -ErrorAction SilentlyContinue
                $hasRequiredScope = $mgContext -and $mgContext.Scopes -and (@($mgContext.Scopes | Where-Object { $_ -in $requiredScopes }).Count -gt 0)
            }

            if ($hasRequiredScope) {
                foreach ($endpoint in $endpoints) {
                    try {
                        $uri = $endpoint
                        do {
                            $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop
                            if ($response -and $response.PSObject.Properties.Name -contains 'value') {
                                $customRules += @($response.value)
                            }

                            if ($response -and $response.PSObject.Properties.Name -contains '@odata.nextLink' -and -not [string]::IsNullOrWhiteSpace($response.'@odata.nextLink')) {
                                $uri = $response.'@odata.nextLink'
                            }
                            else {
                                $uri = $null
                            }
                        } while ($uri)

                        $fetched = $true
                        Write-Verbose "Fetched Defender custom detection rules using delegated Graph user context (${endpoint})."
                        break
                    }
                    catch {
                        Write-Verbose "Delegated Graph request failed for ${endpoint}: $_"
                    }
                }
            }
            else {
                Write-Warning 'Defender XDR retrieval could not establish delegated Microsoft Graph scope CustomDetection.Read.All.'
            }
        }
        catch {
            Write-Verbose "Delegated Graph auth/request path failed: $_"
        }
    }

    # Fallback: Az token + raw REST only when Graph PowerShell cmdlets are unavailable.
    # In interactive/user mode, prefer delegated Graph scopes and avoid app-scope confusion.
    if (-not $fetched -and -not $mgCmd) {
        $graphToken = $null
        try {
            $tokenResult = $null
            if ($Context.PSObject.Properties.Name -contains 'TenantId' -and -not [string]::IsNullOrWhiteSpace($Context.TenantId)) {
                $tokenResult = Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com' -TenantId $Context.TenantId -ErrorAction Stop
            }
            else {
                $tokenResult = Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com' -ErrorAction Stop
            }
            $graphToken = ConvertTo-PlainTextToken -AccessToken $tokenResult.Token
        }
        catch {
            Write-Warning 'Cannot acquire Microsoft Graph token. Defender XDR analysis will be skipped.'
            return $null
        }

        $headers = @{
            Authorization  = "Bearer $graphToken"
            'Content-Type' = 'application/json'
        }

        foreach ($endpoint in $endpoints) {
            try {
                $uri = $endpoint
                do {
                    $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -ErrorAction Stop
                    if ($response -and $response.PSObject.Properties.Name -contains 'value') {
                        $customRules += @($response.value)
                    }

                    if ($response -and $response.PSObject.Properties.Name -contains '@odata.nextLink' -and -not [string]::IsNullOrWhiteSpace($response.'@odata.nextLink')) {
                        $uri = $response.'@odata.nextLink'
                    }
                    else {
                        $uri = $null
                    }
                } while ($uri)

                $fetched = $true
                break
            }
            catch {
                Write-Verbose "Could not fetch Defender custom detection rules from ${endpoint}: $_"
            }
        }
    }

    if (-not $fetched) {
        Write-Warning 'Could not fetch Defender custom detection rules from Graph API (beta/v1.0).'
        return [PSCustomObject]@{
            CustomRules      = @()
            TotalXDRRules    = 0
            XDRTableCoverage = @{}
            KnownXDRTables   = @(
                'DeviceInfo', 'DeviceNetworkInfo', 'DeviceProcessEvents',
                'DeviceNetworkEvents', 'DeviceFileEvents', 'DeviceRegistryEvents',
                'DeviceLogonEvents', 'DeviceImageLoadEvents', 'DeviceEvents',
                'DeviceFileCertificateInfo', 'EmailAttachmentInfo', 'EmailEvents',
                'EmailPostDeliveryEvents', 'EmailUrlInfo', 'UrlClickEvents',
                'IdentityDirectoryEvents', 'IdentityLogonEvents', 'IdentityQueryEvents',
                'CloudAppEvents', 'AlertInfo', 'AlertEvidence'
            )
        }
    }

    # Parse XDR rule queries for table references
    $xdrTableCoverage = @{}
    foreach ($rule in $customRules) {
        $query = $null
        if ($rule.PSObject.Properties.Name -contains 'queryCondition' -and $rule.queryCondition) {
            $query = $rule.queryCondition.queryText
        }
        if ($query) {
            $tables = Get-TablesFromKql -Kql $query
            foreach ($t in $tables) {
                if (-not $xdrTableCoverage.ContainsKey($t)) { $xdrTableCoverage[$t] = 0 }
                $xdrTableCoverage[$t]++
            }
        }
    }

    # Known Defender XDR advanced hunting tables (reference list).
    # A table is only "streaming" if it actually exists in Sentinel as an Analytics-tier table.
    $knownXDRTables = @(
        'DeviceInfo', 'DeviceNetworkInfo', 'DeviceProcessEvents',
        'DeviceNetworkEvents', 'DeviceFileEvents', 'DeviceRegistryEvents',
        'DeviceLogonEvents', 'DeviceImageLoadEvents', 'DeviceEvents',
        'DeviceFileCertificateInfo', 'EmailAttachmentInfo', 'EmailEvents',
        'EmailPostDeliveryEvents', 'EmailUrlInfo', 'UrlClickEvents',
        'IdentityDirectoryEvents', 'IdentityLogonEvents', 'IdentityQueryEvents',
        'CloudAppEvents', 'AlertInfo', 'AlertEvidence'
    )

    [PSCustomObject]@{
        CustomRules      = $customRules
        TotalXDRRules    = $customRules.Count
        XDRTableCoverage = $xdrTableCoverage
        KnownXDRTables   = $knownXDRTables
    }
}
