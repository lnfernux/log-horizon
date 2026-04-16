function Connect-Sentinel {
    <#
    .SYNOPSIS
        Authenticates to Azure and resolves the target Sentinel workspace.
    .OUTPUTS
        PSCustomObject with SubscriptionId, ResourceGroup, WorkspaceName,
        WorkspaceId, ResourceId, and Token properties.
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
        Write-Verbose "Authenticating to subscription $SubscriptionId …"
        $prevWarning = $WarningPreference
        $WarningPreference = 'SilentlyContinue'
        Connect-AzAccount -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
        $WarningPreference = $prevWarning
        $ctx = Get-AzContext
    }
    else {
        Write-Verbose "Already connected to subscription $SubscriptionId."
    }

    # Resolve workspace
    $resourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
                  "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"

    $ws = Get-AzResource -ResourceId $resourceId -ErrorAction Stop
    $resolvedWsId = $ws.Properties.customerId   # Log Analytics workspace GUID

    if ($WorkspaceId -and $resolvedWsId -ne $WorkspaceId) {
        Write-Warning "Supplied WorkspaceId ($WorkspaceId) differs from resolved ID ($resolvedWsId). Using resolved."
    }

    # Acquire ARM token
    $token = Resolve-AzToken -ResourceUrl 'https://management.azure.com'

    # Acquire Log Analytics token
    $laToken = Resolve-AzToken -ResourceUrl 'https://api.loganalytics.io'

    # Check if Defender XDR unified experience is enabled
    $sentinelResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" +
                          "/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName" +
                          "/providers/Microsoft.SecurityInsights/onboardingStates/default"

    $defenderUnified = $false
    try {
        $headers = @{ Authorization = "Bearer $token" }
        $onboardUri = "https://management.azure.com${sentinelResourceId}?api-version=2024-03-01"
        $onboard = Invoke-RestMethod -Uri $onboardUri -Headers $headers -ErrorAction Stop
        if ($onboard.properties) {
            # If the onboarding state exists, workspace is onboarded to Sentinel
            $defenderUnified = $true
        }
    }
    catch {
        Write-Verbose 'Could not determine Defender XDR  and Microsoft Sentinel unified experience status.'
    }

    [PSCustomObject]@{
        SubscriptionId  = $SubscriptionId
        TenantId        = $ctx.Tenant.Id
        ResourceGroup   = $ResourceGroup
        WorkspaceName   = $WorkspaceName
        WorkspaceId     = $resolvedWsId
        ResourceId      = $resourceId
        ArmToken        = $token
        LaToken         = $laToken
        DefenderUnified = $defenderUnified
        Region          = $ws.Location
    }
}

function Resolve-AzToken {
    <#
    .SYNOPSIS
        Wraps Get-AzAccessToken and handles both plain-string and SecureString
        token formats across Az module versions.
    #>
    param([string]$ResourceUrl)

    $tokenObj = Get-AzAccessToken -ResourceUrl $ResourceUrl -ErrorAction Stop
    $raw = $tokenObj.Token

    if ($raw -is [System.Security.SecureString]) {
        [System.Net.NetworkCredential]::new('', $raw).Password
    }
    else {
        [string]$raw
    }
}
