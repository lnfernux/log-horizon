function Connect-Sentinel {
    <#
    .SYNOPSIS
        Authenticates to Azure and resolves the target Sentinel workspace.
    .OUTPUTS
        PSCustomObject with SubscriptionId, ResourceGroup, WorkspaceName,
        WorkspaceId, ResourceId, tokens, workspace facts and Endpoints.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$WorkspaceName,
        [string]$WorkspaceId
    )

    # Authenticate only if not already connected to the right subscription
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx -or $ctx.Subscription.Id -ne $SubscriptionId) {
        Write-Verbose "Authenticating to subscription $SubscriptionId ..."
        Connect-AzAccount -SubscriptionId $SubscriptionId -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        $ctx = Get-AzContext
    }
    else {
        Write-Verbose "Already connected to subscription $SubscriptionId."
    }

    # Endpoints for the signed-in cloud (public defaults when the environment does not supply them)
    $endpoints = Resolve-LogHorizonEndpoints -Environment $ctx.Environment
    Write-Verbose "Azure environment: $($endpoints.Name) (ARM $($endpoints.Arm))"

    # Acquire ARM token
    $token = Resolve-AzToken -ResourceUrl $endpoints.Arm

    # Acquire Log Analytics token
    $laToken = Resolve-AzToken -ResourceUrl $endpoints.LogAnalyticsResource

    # Resolve workspace via REST (no Az.Resources dependency)
    $resourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
                  "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"

    $wsUri = "$($endpoints.Arm)${resourceId}?api-version=2025-07-01"
    $ws = Invoke-AzRestWithRetry -Uri $wsUri -Headers @{ Authorization = "Bearer $token" }
    $resolvedWsId = $ws.properties.customerId   # Log Analytics workspace GUID
    if ([string]::IsNullOrWhiteSpace("$resolvedWsId")) {
        throw "Workspace '$WorkspaceName' in resource group '$ResourceGroup' returned no customerId; check the name and your permissions."
    }

    if ($WorkspaceId -and $resolvedWsId -ne $WorkspaceId) {
        Write-Warning "Supplied WorkspaceId ($WorkspaceId) differs from resolved ID ($resolvedWsId). Using resolved."
    }

    [PSCustomObject]@{
        SubscriptionId                      = $SubscriptionId
        TenantId                            = $ctx.Tenant.Id
        ResourceGroup                       = $ResourceGroup
        WorkspaceName                       = $WorkspaceName
        WorkspaceId                         = $resolvedWsId
        ResourceId                          = $resourceId
        ArmToken                            = $token
        LaToken                             = $laToken
        Region                              = $ws.location
        WorkspaceRetentionDays              = if ($null -ne $ws.properties.retentionInDays) { [int]$ws.properties.retentionInDays } else { $null }
        DefaultDataCollectionRuleResourceId = $ws.properties.defaultDataCollectionRuleResourceId
        Endpoints                           = $endpoints
    }
}

function Resolve-AzToken {
    <#
    .SYNOPSIS
        Wraps Get-AzAccessToken and handles both plain-string and SecureString
        token formats across Az module versions.
    #>
    [CmdletBinding()]
    param(
        [string]$ResourceUrl,
        [string]$TenantId
    )

    $splat = @{ ResourceUrl = $ResourceUrl; ErrorAction = 'Stop' }
    if (-not [string]::IsNullOrWhiteSpace($TenantId)) { $splat.TenantId = $TenantId }
    $tokenObj = Get-AzAccessToken @splat
    $raw = $tokenObj.Token

    if ($raw -is [System.Security.SecureString]) {
        [System.Net.NetworkCredential]::new('', $raw).Password
    }
    else {
        [string]$raw
    }
}
