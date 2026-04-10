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
        $response = Invoke-AzRestWithRetry -Uri $uri -Headers $headers
        $response.value | ForEach-Object {
            # Extract actionable suggestions (e.g. specific tables to enable, rules to create)
            $suggestions = @()
            if ($_.properties.suggestions) {
                $suggestions = $_.properties.suggestions | ForEach-Object {
                    [PSCustomObject]@{
                        Title       = $_.title
                        Description = $_.description
                        Action      = $_.action
                        TypeId      = $_.suggestionTypeId
                        Properties  = $_.additionalProperties
                    }
                }
            }

            [PSCustomObject]@{
                Id                   = $_.id
                Title                = $_.properties.title
                Description          = $_.properties.description
                Category             = $_.properties.category
                Priority             = $_.properties.priority
                State                = $_.properties.state
                RecommendationTypeId = $_.properties.recommendationTypeId
                Suggestions          = $suggestions
                AdditionalProperties = $_.properties.additionalProperties
                Actions              = $_.properties.actions
            }
        }
    }
    catch {
        Write-Verbose "SOC optimization API not available or insufficient permissions: $_"
        @()
    }
}
