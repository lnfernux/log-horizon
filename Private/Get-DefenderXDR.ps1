# Known Defender XDR advanced hunting tables the Sentinel connector can stream.
# A table is only "streaming" if it actually exists in the workspace.
$script:KnownXDRTables = @(
    'DeviceInfo', 'DeviceNetworkInfo', 'DeviceProcessEvents',
    'DeviceNetworkEvents', 'DeviceFileEvents', 'DeviceRegistryEvents',
    'DeviceLogonEvents', 'DeviceImageLoadEvents', 'DeviceEvents',
    'DeviceFileCertificateInfo', 'EmailAttachmentInfo', 'EmailEvents',
    'EmailPostDeliveryEvents', 'EmailUrlInfo', 'UrlClickEvents',
    'IdentityDirectoryEvents', 'IdentityLogonEvents', 'IdentityQueryEvents',
    'CloudAppEvents', 'AlertInfo', 'AlertEvidence'
)

function Get-DefenderXDR {
    <#
    .SYNOPSIS
        Queries Defender XDR for custom detection rules and streaming configuration.
        Requires -IncludeDefenderXDR flag. Uses delegated Microsoft Graph auth with
        CustomDetection.Read.All (or CustomDetection.ReadWrite.All) scope. Falls back
        to an Az access-token REST call if delegated Graph auth is unavailable.
    .OUTPUTS
        PSCustomObject with custom detection rules and XDR table analysis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Context
    )

    # Fetch custom detection rules.
    # Prefer delegated user context via Microsoft Graph PowerShell for CustomDetection.Read.All.
    $customRules = [System.Collections.Generic.List[object]]::new()
    $fetched = $false
    $graphBase = Get-LogHorizonEndpoint -Name Graph -Context $Context
    $graphEnvironment = Get-LogHorizonEndpoint -Name GraphEnvironment -Context $Context
    $endpoints = @(
        "$graphBase/beta/security/rules/detectionRules",
        "$graphBase/v1.0/security/rules/detectionRules"
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
                if ($graphEnvironment -and $graphEnvironment -ne 'Global') {
                    $connectParams.Environment = $graphEnvironment
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
                                foreach ($v in @($response.value)) { $customRules.Add($v) }
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

    # Fallback: if delegated Graph auth/request did not fetch results, try Az token + raw REST.
    # This keeps delegated Graph as the preferred path while still supporting non-interactive/CI environments.
    $fetchError = $null
    if (-not $fetched) {
        $graphToken = $null
        try {
            $tenantId = if ($Context.PSObject.Properties.Name -contains 'TenantId' -and -not [string]::IsNullOrWhiteSpace($Context.TenantId)) { $Context.TenantId } else { $null }
            $graphToken = Resolve-AzToken -ResourceUrl $graphBase -TenantId $tenantId
        }
        catch {
            $fetchError = "Cannot acquire Microsoft Graph token: $($_.Exception.Message)"
            Write-Warning "$fetchError. Defender XDR custom detection coverage is unavailable for this run."
            return ConvertTo-DefenderXDRResult -Fetched $false -FetchError $fetchError
        }

        $headers = @{
            Authorization  = "Bearer $graphToken"
            'Content-Type' = 'application/json'
        }

        foreach ($endpoint in $endpoints) {
            try {
                $uri = $endpoint
                do {
                    $response = Invoke-AzRestWithRetry -Uri $uri -Headers $headers
                    if ($response -and $response.PSObject.Properties.Name -contains 'value') {
                        foreach ($v in @($response.value)) { $customRules.Add($v) }
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
        $missing = if (-not $mgCmd) { ' Install Microsoft.Graph.Authentication for delegated access (CustomDetection.Read.All).' } else { '' }
        $fetchError = "Could not fetch Defender custom detection rules from Graph API (beta/v1.0).$missing"
        Write-Warning $fetchError
        return ConvertTo-DefenderXDRResult -Fetched $false -FetchError $fetchError
    }

    # Parse enabled XDR rule queries for table references
    $xdrTableCoverage = @{}
    $projectedRules = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in $customRules) {
        $query = $null
        if ($rule.PSObject.Properties.Name -contains 'queryCondition' -and $rule.queryCondition) {
            $query = $rule.queryCondition.queryText
        }
        if (-not $query -and
            $rule.PSObject.Properties.Name -contains 'detectionAction' -and
            $rule.detectionAction -and
            $rule.detectionAction.PSObject.Properties.Name -contains 'queryCondition' -and
            $rule.detectionAction.queryCondition) {
            $query = $rule.detectionAction.queryCondition.queryText
        }
        $isEnabled = -not ($rule.PSObject.Properties.Name -contains 'isEnabled' -and $rule.isEnabled -eq $false)

        # Only the fields the analysis reads are kept; Graph objects also carry createdBy/lastModifiedBy identities
        $projectedRules.Add([PSCustomObject]@{
            id             = $(if ($rule.PSObject.Properties.Name -contains 'id') { $rule.id } else { $null })
            displayName    = $(if ($rule.PSObject.Properties.Name -contains 'displayName') { $rule.displayName } else { $null })
            isEnabled      = $isEnabled
            queryCondition = [PSCustomObject]@{ queryText = $query }
            schedule       = $(if ($rule.PSObject.Properties.Name -contains 'schedule' -and $rule.schedule) { [PSCustomObject]@{ period = $rule.schedule.period } } else { $null })
        })

        if (-not $isEnabled) { continue }
        if ($query) {
            $tables = @(Get-TablesFromKql -Kql $query)
            foreach ($t in $tables) {
                if (-not $xdrTableCoverage.ContainsKey($t)) { $xdrTableCoverage[$t] = 0 }
                $xdrTableCoverage[$t]++
            }
        }
    }

    ConvertTo-DefenderXDRResult -Fetched $true -CustomRules @($projectedRules) -XDRTableCoverage $xdrTableCoverage
}

function ConvertTo-DefenderXDRResult {
    <#
    .SYNOPSIS
        The one shape every Get-DefenderXDR path returns, so callers never see $null.
        Fetched=$false with FetchError tells the run and the exports that the flag had no data.
    #>
    [CmdletBinding()]
    param(
        [bool]$Fetched,
        [string]$FetchError,
        [array]$CustomRules = @(),
        [hashtable]$XDRTableCoverage = @{}
    )

    [PSCustomObject]@{
        Fetched          = $Fetched
        FetchError       = $FetchError
        CustomRules      = @($CustomRules)
        TotalXDRRules    = @($CustomRules).Count
        XDRTableCoverage = $XDRTableCoverage
        KnownXDRTables   = @($script:KnownXDRTables)
    }
}
