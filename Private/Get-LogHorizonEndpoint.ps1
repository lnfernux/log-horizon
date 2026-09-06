function Resolve-LogHorizonEndpoints {
    <#
    .SYNOPSIS
        Derives the service endpoints for the signed-in Azure environment.
    .DESCRIPTION
        Reads the Az environment (from -Environment or Get-AzContext) and falls
        back to the public cloud values for anything the environment does not
        supply. Az.Accounts exposes some values as properties and others only
        through ExtendedProperties, so both are consulted.
    .OUTPUTS
        PSCustomObject with Name, Arm, LogAnalytics, LogAnalyticsResource,
        Graph and GraphEnvironment.
    #>
    [CmdletBinding()]
    param(
        [object]$Environment
    )

    if ($null -eq $Environment) {
        try { $Environment = (Get-AzContext -ErrorAction SilentlyContinue).Environment } catch { $Environment = $null }
    }

    $defaults = [ordered]@{
        Name                 = 'AzureCloud'
        Arm                  = 'https://management.azure.com'
        LogAnalytics         = 'https://api.loganalytics.io/v1'
        LogAnalyticsResource = 'https://api.loganalytics.io'
        Graph                = 'https://graph.microsoft.com'
        GraphEnvironment     = 'Global'
    }

    if ($null -eq $Environment) { return [PSCustomObject]$defaults }

    $extended = $null
    if ($Environment.PSObject.Properties.Name -contains 'ExtendedProperties') { $extended = $Environment.ExtendedProperties }

    $read = {
        param([string[]]$Keys)
        foreach ($k in $Keys) {
            $v = $null
            if ($Environment.PSObject.Properties.Name -contains $k) { $v = $Environment.$k }
            if ([string]::IsNullOrWhiteSpace("$v") -and $null -ne $extended -and $extended.ContainsKey($k)) { $v = $extended[$k] }
            if (-not [string]::IsNullOrWhiteSpace("$v")) { return "$v".TrimEnd('/') }
        }
        $null
    }

    $envName = if (-not [string]::IsNullOrWhiteSpace("$($Environment.Name)")) { "$($Environment.Name)" } else { $defaults.Name }
    $graphEnvironment = switch -Regex ($envName) {
        'USGovernment' { 'USGov'; break }
        'China'        { 'China'; break }
        default        { 'Global' }
    }

    $arm   = & $read @('ResourceManagerUrl')
    $la    = & $read @('AzureOperationalInsightsEndpoint', 'OperationalInsightsEndpoint')
    $laRes = & $read @('AzureOperationalInsightsEndpointResourceId', 'OperationalInsightsEndpointResourceId')
    $graph = & $read @('MicrosoftGraphUrl', 'MicrosoftGraphEndpointResourceId')

    [PSCustomObject]@{
        Name                 = $envName
        Arm                  = if ($arm)   { $arm }   else { $defaults.Arm }
        LogAnalytics         = if ($la)    { $la }    else { $defaults.LogAnalytics }
        LogAnalyticsResource = if ($laRes) { $laRes } else { $defaults.LogAnalyticsResource }
        Graph                = if ($graph) { $graph } else { $defaults.Graph }
        GraphEnvironment     = $graphEnvironment
    }
}

function Get-LogHorizonEndpoint {
    <#
    .SYNOPSIS
        Returns one service endpoint for the current run.
    .DESCRIPTION
        Prefers the Endpoints object that Connect-Sentinel places on the run
        context, then the signed-in Az environment, then the public defaults.
        Collectors call this instead of hardcoding management.azure.com,
        api.loganalytics.io or graph.microsoft.com so sovereign clouds work.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Arm', 'LogAnalytics', 'LogAnalyticsResource', 'Graph', 'GraphEnvironment')]
        [string]$Name,
        [PSCustomObject]$Context
    )

    if ($Context -and $Context.PSObject.Properties.Name -contains 'Endpoints' -and $Context.Endpoints) {
        $v = $Context.Endpoints.$Name
        if (-not [string]::IsNullOrWhiteSpace("$v")) { return "$v" }
    }

    (Resolve-LogHorizonEndpoints).$Name
}
