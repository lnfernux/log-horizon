function Get-AutomationRules {
    <#
    .SYNOPSIS
        Fetches Sentinel automation rules and extracts close-incident targeting hints.
    .OUTPUTS
        Array of PSCustomObject automation rules.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Context
    )

    $headers = @{ Authorization = "Bearer $($Context.ArmToken)" }
    $uri = "https://management.azure.com$($Context.ResourceId)" +
           "/providers/Microsoft.SecurityInsights/automationRules?api-version=2025-09-01"

    $allRules = [System.Collections.Generic.List[object]]::new()
    $maxPages = 1000
    $pageCount = 0

    do {
        $pageCount++
        $response = Invoke-AzRestWithRetry -Uri $uri -Headers $headers
        foreach ($rule in $response.value) { $allRules.Add($rule) }
        $uri = $response.nextLink

        if ($pageCount -ge $maxPages) {
            Write-Warning 'Pagination limit reached fetching automation rules. Stopping to avoid infinite loop.'
            break
        }
    } while ($uri)

    $normalized = foreach ($rule in $allRules) {
        $props = $rule.properties
        $actions = @($props.actions)
        $conditions = @($props.triggeringLogic.conditions)

        $closeAction = $actions | Where-Object {
            $_.actionType -eq 'ModifyProperties' -and
            $_.order -ge 0 -and
            $_.actionConfiguration -and
            $_.actionConfiguration.status -eq 'Closed'
        }

        $titleFilters = [System.Collections.Generic.List[string]]::new()
        foreach ($cond in $conditions) {
            if ($cond.conditionType -ne 'Property') { continue }
            $propertyName = "$($cond.conditionProperties.propertyName)"
            if ($propertyName -notmatch 'Title') { continue }

            $value = $cond.conditionProperties.propertyValues
            if ($value -is [System.Array]) {
                foreach ($item in $value) {
                    if (-not [string]::IsNullOrWhiteSpace("$item")) {
                        [void]$titleFilters.Add("$item")
                    }
                }
            } elseif (-not [string]::IsNullOrWhiteSpace("$value")) {
                [void]$titleFilters.Add("$value")
            }
        }

        [PSCustomObject]@{
            AutomationRuleId      = $rule.name
            DisplayName           = $props.displayName
            Enabled               = [bool]$props.isEnabled
            Order                 = [int]$props.order
            TriggersOn            = $props.triggeringLogic.triggersOn
            TriggersWhen          = $props.triggeringLogic.triggersWhen
            IsCloseIncidentRule   = $null -ne $closeAction
            TitleFilters          = @($titleFilters | Select-Object -Unique)
            Conditions            = $conditions
            Actions               = $actions
            Raw                   = $rule
        }
    }

    @($normalized)
}
