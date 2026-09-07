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
    $uri = "$(Get-LogHorizonEndpoint -Name Arm -Context $Context)$($Context.ResourceId)" +
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
            $_.actionConfiguration -and
            ($_.actionConfiguration.status -eq 'Closed' -or $_.actionConfiguration.status -eq 'Resolved')
        }

        # Detect playbook action: automation rule triggers a playbook (may close incidents indirectly)
        $playbookAction = $actions | Where-Object { $_.actionType -eq 'RunPlaybook' }

        # Title conditions are kept as (Value, Operator) pairs so de-duplication never misaligns them
        $titleConditions = [System.Collections.Generic.List[object]]::new()
        $titleSeen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $ruleIdFilters = [System.Collections.Generic.List[string]]::new()
        $severityConditions = [System.Collections.Generic.List[object]]::new()
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
                foreach ($item in @($cond.conditionProperties.propertyValues)) {
                    if ([string]::IsNullOrWhiteSpace("$item")) { continue }
                    if ($titleSeen.Add("$operator|$item")) {
                        [void]$titleConditions.Add([PSCustomObject]@{ Value = "$item"; Operator = $operator })
                    }
                }
            }

            # Analytic rule ID conditions
            if ($propertyName -match 'AnalyticRuleIds') {
                foreach ($item in @($cond.conditionProperties.propertyValues)) {
                    if (-not [string]::IsNullOrWhiteSpace("$item")) {
                        [void]$ruleIdFilters.Add("$item")
                    }
                }
            }

            # Severity conditions (Equals / NotEquals with one or more severities)
            if ($propertyName -match 'Severity') {
                $values = @(@($cond.conditionProperties.propertyValues) | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") } | ForEach-Object { "$_" })
                if ($values.Count -gt 0) {
                    [void]$severityConditions.Add([PSCustomObject]@{ Values = $values; Operator = $(if ($operator) { $operator } else { 'Equals' }) })
                }
            }
        }

        # The API exposes the enabled flag under triggeringLogic.isEnabled
        $isEnabled = if ($null -ne $props.triggeringLogic -and $null -ne $props.triggeringLogic.isEnabled) {
            [bool]$props.triggeringLogic.isEnabled
        } elseif ($null -ne $props.isEnabled) {
            [bool]$props.isEnabled
        } else {
            $false
        }

        [PSCustomObject]@{
            AutomationRuleId      = $rule.name
            DisplayName           = $props.displayName
            Enabled               = $isEnabled
            Order                 = [int]$props.order
            TriggersOn            = $props.triggeringLogic.triggersOn
            TriggersWhen          = $props.triggeringLogic.triggersWhen
            IsCloseIncidentRule   = $null -ne $closeAction
            HasPlaybookAction     = $null -ne $playbookAction
            HasConditions         = $hasConditions
            TitleConditions       = @($titleConditions)
            TitleFilters          = @($titleConditions | ForEach-Object Value)
            TitleOperators        = @($titleConditions | ForEach-Object Operator)
            RuleIdFilters         = @($ruleIdFilters | Select-Object -Unique)
            SeverityConditions    = @($severityConditions)
            Conditions            = $conditions
            # Actions are projected: actionConfiguration can carry an assigned owner identity
            Actions               = @($actions | ForEach-Object { [PSCustomObject]@{ actionType = $_.actionType; order = $_.order; status = $_.actionConfiguration.status } })
        }
    }

    @($normalized)
}
