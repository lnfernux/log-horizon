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

        # Detect close action: check for Closed or Resolved status
        $closeAction = $actions | Where-Object {
            $_.actionType -eq 'ModifyProperties' -and
            $_.order -ge 0 -and
            $_.actionConfiguration -and
            ($_.actionConfiguration.status -eq 'Closed' -or $_.actionConfiguration.status -eq 'Resolved')
        }

        $titleFilters = [System.Collections.Generic.List[string]]::new()
        $titleOperators = [System.Collections.Generic.List[string]]::new()
        $ruleIdFilters = [System.Collections.Generic.List[string]]::new()
        $hasConditions = $conditions.Count -gt 0

        # Recursively extract Property conditions (handles Boolean wrappers)
        $propertyConditions = [System.Collections.Generic.List[object]]::new()
        $condStack = [System.Collections.Generic.Stack[object]]::new()
        foreach ($c in $conditions) { $condStack.Push($c) }
        while ($condStack.Count -gt 0) {
            $cond = $condStack.Pop()
            $condType = "$($cond.conditionType)"
            if ($condType -eq 'Property') {
                [void]$propertyConditions.Add($cond)
            } elseif ($condType -eq 'Boolean' -and $cond.conditionProperties.innerConditions) {
                foreach ($inner in $cond.conditionProperties.innerConditions) {
                    $condStack.Push($inner)
                }
            }
        }

        foreach ($cond in $propertyConditions) {
            $propertyName = "$($cond.conditionProperties.propertyName)"
            $operator = "$($cond.conditionProperties.operator)"

            # Title conditions
            if ($propertyName -match 'Title') {
                $value = $cond.conditionProperties.propertyValues
                if ($value -is [System.Array]) {
                    foreach ($item in $value) {
                        if (-not [string]::IsNullOrWhiteSpace("$item")) {
                            [void]$titleFilters.Add("$item")
                            [void]$titleOperators.Add($operator)
                        }
                    }
                } elseif (-not [string]::IsNullOrWhiteSpace("$value")) {
                    [void]$titleFilters.Add("$value")
                    [void]$titleOperators.Add($operator)
                }
            }

            # Analytic rule ID conditions
            if ($propertyName -match 'AnalyticRuleIds') {
                $value = $cond.conditionProperties.propertyValues
                if ($value -is [System.Array]) {
                    foreach ($item in $value) {
                        if (-not [string]::IsNullOrWhiteSpace("$item")) {
                            [void]$ruleIdFilters.Add("$item")
                        }
                    }
                } elseif (-not [string]::IsNullOrWhiteSpace("$value")) {
                    [void]$ruleIdFilters.Add("$value")
                }
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
            HasConditions         = $hasConditions
            TitleFilters          = @($titleFilters | Select-Object -Unique)
            TitleOperators        = @($titleOperators)
            RuleIdFilters         = @($ruleIdFilters | Select-Object -Unique)
            Conditions            = $conditions
            Actions               = $actions
            Raw                   = $rule
        }
    }

    @($normalized)
}
