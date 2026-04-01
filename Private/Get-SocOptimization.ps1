function Get-SocOptimization {
    <#
    .SYNOPSIS
        Fetches SOC optimization recommendations from the Sentinel REST API.
    .OUTPUTS
        Array of recommendation objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Context
    )

    $headers = @{ Authorization = "Bearer $($Context.ArmToken)" }
    $uri = "https://management.azure.com$($Context.ResourceId)" +
           "/providers/Microsoft.SecurityInsights/recommendations?api-version=2024-01-01-preview"

    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -ErrorAction Stop
        $response.value | ForEach-Object {
            [PSCustomObject]@{
                Id          = $_.id
                Title       = $_.properties.title
                Description = $_.properties.description
                Category    = $_.properties.category
                Priority    = $_.properties.priority
                State       = $_.properties.state
                Actions     = $_.properties.actions
            }
        }
    }
    catch {
        Write-Verbose "SOC optimization API not available or insufficient permissions: $_"
        @()
    }
}
