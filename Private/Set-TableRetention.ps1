# Discrete long-term retention values supported by the Tables API above 730 days.
$script:LongTermRetentionEnum = @(1095, 1460, 1826, 2191, 2556, 2922, 3288, 3653, 4018, 4383)

function Test-TotalRetentionValue {
    <#
    .SYNOPSIS
        Validates totalRetentionInDays against the Tables API contract:
        4..730 inclusive, OR one of the discrete long-term values, OR null.
    #>
    param([Nullable[int]]$Value)

    if ($null -eq $Value) { return $true }
    if ($Value -ge 4 -and $Value -le 730) { return $true }
    return $script:LongTermRetentionEnum -contains $Value
}

function Test-InteractiveRetentionValue {
    <#
    .SYNOPSIS
        Validates retentionInDays: 4..730 inclusive, or null to inherit workspace.
    #>
    param([Nullable[int]]$Value)

    if ($null -eq $Value) { return $true }
    return ($Value -ge 4 -and $Value -le 730)
}

function Get-TableRetentionSourceValue {
    <#
    .SYNOPSIS
        Reads a value from the first property name that exists and is non-null.
    #>
    param(
        [Parameter(Mandatory)][PSCustomObject]$Table,
        [Parameter(Mandatory)][string[]]$Names
    )

    foreach ($name in $Names) {
        $prop = $Table.PSObject.Properties[$name]
        if ($prop -and $null -ne $prop.Value) {
            return $prop.Value
        }
    }

    return $null
}

function Get-TableRetentionErrorStatusCode {
    param([Parameter(Mandatory)]$ErrorRecord)

    if ($ErrorRecord.Exception -and $ErrorRecord.Exception.Response -and $null -ne $ErrorRecord.Exception.Response.StatusCode) {
        return [int]$ErrorRecord.Exception.Response.StatusCode
    }
    if ($ErrorRecord.Exception -and $null -ne $ErrorRecord.Exception.StatusCode) {
        return [int]$ErrorRecord.Exception.StatusCode
    }
    if ($ErrorRecord.TargetObject -and $null -ne $ErrorRecord.TargetObject.StatusCode) {
        return [int]$ErrorRecord.TargetObject.StatusCode
    }

    return $null
}

function Get-TableRetentionErrorMessage {
    param([Parameter(Mandatory)]$ErrorRecord)

    if ($ErrorRecord.TargetObject -and $ErrorRecord.TargetObject.Message) {
        return [string]$ErrorRecord.TargetObject.Message
    }
    if ($ErrorRecord.Exception -and $ErrorRecord.Exception.Message) {
        return [string]$ErrorRecord.Exception.Message
    }

    return 'Unknown table retention update error.'
}

function ConvertTo-TableRetentionApiValue {
    param($Value)

    if ($null -eq $Value) {
        return -1
    }

    return $Value
}

function Get-BasicPlanSupportedTableSet {
    <#
    .SYNOPSIS
        Returns a cached set of built-in table names that Microsoft Learn lists
        as supporting the Basic table plan.
    #>
    if ($script:BasicPlanSupportedTableNames) {
        return $script:BasicPlanSupportedTableNames
    }

    $lookup = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $path = Join-Path $PSScriptRoot '..\Data\basic-plan-tables.json'
    if (Test-Path $path) {
        $data = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        foreach ($name in @($data.tables)) {
            if (-not [string]::IsNullOrWhiteSpace($name)) {
                [void]$lookup.Add([string]$name)
            }
        }
    }

    $script:BasicPlanSupportedTableNames = $lookup
    return $script:BasicPlanSupportedTableNames
}

function Test-TableSupportsBasicPlan {
    <#
    .SYNOPSIS
        Determines whether a table supports Analytics <-> Basic switching.
    .DESCRIPTION
        Uses a generated allow-list of built-in Azure tables from Microsoft Learn,
        plus the documented rule that DCR-based custom tables support Basic while
        Classic custom tables do not.
    #>
    param([Parameter(Mandatory)][PSCustomObject]$Table)

    $tableName = Get-TableRetentionSourceValue -Table $Table -Names @('TableName', 'Name')
    $currentPlan = Get-TableRetentionSourceValue -Table $Table -Names @('Plan', 'TablePlan', 'XDRState')
    $tableSubType = Get-TableRetentionSourceValue -Table $Table -Names @('TableSubType')

    if ([string]::IsNullOrWhiteSpace($tableName)) {
        return $false
    }

    if ($currentPlan -eq 'Auxiliary') {
        return $false
    }

    if ($currentPlan -eq 'Basic') {
        return $true
    }

    if ($tableName -match '_CL$') {
        return ($tableSubType -eq 'DataCollectionRuleBased')
    }

    return (Get-BasicPlanSupportedTableSet).Contains([string]$tableName)
}

function Get-TableRetentionChangeSet {
    <#
    .SYNOPSIS
        Builds a per-table change set with validation, current vs target diff,
        and warnings. Each item gets Status = Pending | Skipped | Invalid.
    .DESCRIPTION
        Inputs are the current table state (TableName, Plan, RetentionInDays,
        TotalRetentionInDays) and the desired target values. The function never
        calls Azure; it just produces the structured plan that Format-TableRetentionPreview
        and Invoke-TableRetentionApply consume.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]]$Tables,
        [ValidateSet('Analytics', 'Basic')]
        [string]$TargetPlan,
        # Use [Nullable[int]] so explicit $null means inherit / remove long-term.
        # Callers that do not want to change a field should omit the parameter
        # entirely; PSBoundParameters is checked below.
        [Nullable[int]]$TotalRetentionInDays,
        [Nullable[int]]$RetentionInDays
    )

    $changeTotal     = $PSBoundParameters.ContainsKey('TotalRetentionInDays')
    $changeRetention = $PSBoundParameters.ContainsKey('RetentionInDays')
    $changePlan      = $PSBoundParameters.ContainsKey('TargetPlan')

    if (-not ($changeTotal -or $changeRetention -or $changePlan)) {
        throw 'Get-TableRetentionChangeSet: at least one of -TargetPlan, -TotalRetentionInDays, -RetentionInDays must be supplied.'
    }

    # Range validation up front (same target applied to every table).
    if ($changeTotal -and -not (Test-TotalRetentionValue -Value $TotalRetentionInDays)) {
        throw "TotalRetentionInDays must be 4-730 or one of: $($script:LongTermRetentionEnum -join ', '), or null to remove long-term retention."
    }
    if ($changeRetention -and -not (Test-InteractiveRetentionValue -Value $RetentionInDays)) {
        throw 'RetentionInDays must be 4-730 or null to inherit workspace default.'
    }
    if ($changeTotal -and $changeRetention -and $null -ne $TotalRetentionInDays -and $null -ne $RetentionInDays -and $TotalRetentionInDays -lt $RetentionInDays) {
        throw 'TotalRetentionInDays must be greater than or equal to RetentionInDays.'
    }

    foreach ($t in $Tables) {
        $currentPlanValue = Get-TableRetentionSourceValue -Table $t -Names @('Plan', 'TablePlan', 'XDRState')
        $currentRetentionValue = Get-TableRetentionSourceValue -Table $t -Names @('RetentionInDays', 'ActualInteractiveRetentionDays')
        $currentTotalValue = Get-TableRetentionSourceValue -Table $t -Names @('TotalRetentionInDays', 'ActualRetentionDays')
        $tableSubType = Get-TableRetentionSourceValue -Table $t -Names @('TableSubType')
        $provisioningState = Get-TableRetentionSourceValue -Table $t -Names @('ProvisioningState', 'TableProvisioningState')

        $currentPlan      = if ($null -ne $currentPlanValue) { [string]$currentPlanValue } else { $null }
        $currentRetention = if ($null -ne $currentRetentionValue) { [int]$currentRetentionValue } else { $null }
        $currentTotal     = if ($null -ne $currentTotalValue) { [int]$currentTotalValue } else { $null }

        $effectivePlan = if ($changePlan) { $TargetPlan } else { $currentPlan }
        $warnings = New-Object System.Collections.Generic.List[string]
        $status   = 'Pending'
        $reason   = $null

        # Auxiliary tables cannot have their plan switched in or out.
        if ($currentPlan -eq 'Auxiliary' -or $effectivePlan -eq 'Auxiliary') {
            if ($changePlan -and $currentPlan -ne $effectivePlan) {
                $status = 'Invalid'
                $reason = 'Plan switching to or from Auxiliary is not supported by the Tables API.'
            }
            elseif ($changeRetention) {
                $status = 'Invalid'
                $reason = 'RetentionInDays is read-only on Auxiliary tables.'
            }
        }

        if ($status -eq 'Pending' -and $changePlan -and $currentPlan -ne $effectivePlan -and -not (Test-TableSupportsBasicPlan -Table $t)) {
            $status = 'Invalid'
            $reason = 'This table does not support Analytics <-> Basic plan switching.'
        }

        # retentionInDays is read-only on Basic tables.
        if ($status -eq 'Pending' -and $changeRetention -and $effectivePlan -eq 'Basic') {
            $status = 'Invalid'
            $reason = 'RetentionInDays is read-only on Basic tables. Switch to Analytics first or omit RetentionInDays.'
        }

        # Compute combined diff.
        $newRetention = if ($changeRetention) { $RetentionInDays } else { $currentRetention }
        $newTotal     = if ($changeTotal)     { $TotalRetentionInDays } else { $currentTotal }

        if ($status -eq 'Pending' -and $null -ne $newRetention -and $null -ne $newTotal -and $newTotal -lt $newRetention) {
            $status = 'Invalid'
            $reason = "Effective TotalRetentionInDays ($newTotal) is less than RetentionInDays ($newRetention)."
        }

        # No-op detection.
        $planChanged      = $changePlan      -and ($currentPlan -ne $effectivePlan)
        $retentionChanged = $changeRetention -and ($currentRetention -ne $newRetention)
        $totalChanged     = $changeTotal     -and ($currentTotal -ne $newTotal)
        if ($status -eq 'Pending' -and -not ($planChanged -or $retentionChanged -or $totalChanged)) {
            $status = 'Skipped'
            $reason = 'Target values match current configuration.'
        }

        # Warnings.
        if ($status -eq 'Pending') {
            if ($effectivePlan -eq 'Analytics' -and $null -ne $newRetention -and $newRetention -lt 31) {
                $warnings.Add('Analytics retention below 31 days does not reduce ingestion cost (first 31 days are included).') | Out-Null
            }
            if ($totalChanged -and $null -ne $currentTotal -and $null -ne $newTotal -and $newTotal -lt $currentTotal) {
                $warnings.Add('Reducing total retention triggers a 30-day grace period before data is deleted.') | Out-Null
            }
        }

        [PSCustomObject]@{
            TableName            = $t.TableName
            CurrentPlan          = $currentPlan
            TargetPlan           = $effectivePlan
            CurrentInteractive   = $currentRetention
            TargetInteractive    = $newRetention
            CurrentTotal         = $currentTotal
            TargetTotal          = $newTotal
            TableSubType         = $tableSubType
            ProvisioningState    = $provisioningState
            PlanChanged          = $planChanged
            RetentionChanged     = $retentionChanged
            TotalChanged         = $totalChanged
            Status               = $status
            Reason               = $reason
            Warnings             = @($warnings)
            # Indicates the fields the apply layer is allowed to send.
            FieldsToSend         = @(
                if ($planChanged)      { 'plan' }
                if ($retentionChanged) { 'retentionInDays' }
                if ($totalChanged)     { 'totalRetentionInDays' }
            )
        }
    }
}

function Format-TableRetentionPreview {
    <#
    .SYNOPSIS
        Returns the change-set as plain PSCustomObjects formatted for display.
        Caller decides whether to render with Format-SpectreTable or Format-Table.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSCustomObject[]]$ChangeSet)

    foreach ($c in $ChangeSet) {
        $statusMarkup = switch ($c.Status) {
            'Pending' { '[green]Apply[/]' }
            'Skipped' { '[dim]Skip[/]' }
            'Invalid' { '[red]Invalid[/]' }
            default   { $c.Status }
        }
        $fmt = {
            param($v)
            if ($null -eq $v) { 'inherit' } else { "$v d" }
        }
        [PSCustomObject]@{
            'Table'       = $c.TableName
            'Plan'        = if ($c.PlanChanged) { "$($c.CurrentPlan) -> $($c.TargetPlan)" } else { $c.CurrentPlan }
            'Interactive' = if ($c.RetentionChanged) { "$(& $fmt $c.CurrentInteractive) -> $(& $fmt $c.TargetInteractive)" } else { & $fmt $c.CurrentInteractive }
            'Total'       = if ($c.TotalChanged)     { "$(& $fmt $c.CurrentTotal) -> $(& $fmt $c.TargetTotal)" }             else { & $fmt $c.CurrentTotal }
            'Status'      = $statusMarkup
            'Reason'      = if ($c.Reason) { $c.Reason } else { ($c.Warnings -join '; ') }
        }
    }
}

function Invoke-TableRetentionApply {
    <#
    .SYNOPSIS
        Applies a change set against the Tables API via PATCH, polling async
        operations to terminal status. Implements a two-step fallback: if a
        combined PATCH carrying both plan and retention fails, retry as plan
        first then retention. Pattern adopted from Morten Knudsen's production
        Sentinel retention script.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Context,
        [Parameter(Mandatory)][PSCustomObject[]]$ChangeSet,
        [int]$AsyncTimeoutSeconds = 300
    )

    $apiVersion = '2025-07-01'
    $headers = @{
        Authorization  = "Bearer $($Context.ArmToken)"
        'Content-Type' = 'application/json'
    }

    foreach ($c in $ChangeSet) {
        if ($c.Status -ne 'Pending') {
            [PSCustomObject]@{
                TableName  = $c.TableName
                Action     = $c.Status
                Success    = ($c.Status -eq 'Skipped')
                Fallback   = $false
                StatusCode = $null
                Error      = $c.Reason
            }
            continue
        }

        if ($c.ProvisioningState -and $c.ProvisioningState -ne 'Succeeded') {
            [PSCustomObject]@{
                TableName  = $c.TableName
                Action     = 'Skipped'
                Success    = $false
                Fallback   = $false
                StatusCode = $null
                Error      = "Table provisioningState is $($c.ProvisioningState); only Succeeded tables can be updated."
            }
            continue
        }

        $uri = "https://management.azure.com$($Context.ResourceId)/tables/$($c.TableName)?api-version=$apiVersion"

        $combinedProps = [ordered]@{}
        if ($c.PlanChanged)      { $combinedProps['plan']                 = $c.TargetPlan }
        if ($c.RetentionChanged) { $combinedProps['retentionInDays']      = ConvertTo-TableRetentionApiValue -Value $c.TargetInteractive }
        if ($c.TotalChanged)     { $combinedProps['totalRetentionInDays'] = ConvertTo-TableRetentionApiValue -Value $c.TargetTotal }
        $combinedBody = @{ properties = $combinedProps } | ConvertTo-Json -Depth 5

        $success    = $false
        $fallback   = $false
        $errorMsg   = $null
        $statusCode = $null

        try {
            $null = Invoke-AzRestWithRetry -Uri $uri -Headers $headers -Method Patch -Body $combinedBody -FollowAsync -AsyncTimeoutSeconds $AsyncTimeoutSeconds
            $success = $true
        }
        catch {
            $caughtError = $_
            $statusCode = Get-TableRetentionErrorStatusCode -ErrorRecord $caughtError
            $errorMsg = switch ($statusCode) {
                403 { 'Permission denied. Caller needs Microsoft.OperationalInsights/workspaces/tables/write (for example Log Analytics Contributor).' }
                409 { 'The table update was rejected by the service. Plan switches are limited to once per week per table.' }
                default { Get-TableRetentionErrorMessage -ErrorRecord $caughtError }
            }

            # Two-step fallback only makes sense when the combined PATCH carried
            # both a plan change and at least one retention field, and the error
            # was not a hard auth/throttle failure that the second call cannot fix.
            $hasPlanAndRetention = $c.PlanChanged -and ($c.RetentionChanged -or $c.TotalChanged)
            $recoverable = ($statusCode -ge 400 -and $statusCode -lt 500 -and $statusCode -ne 403 -and $statusCode -ne 401 -and $statusCode -ne 429)

            if ($hasPlanAndRetention -and $recoverable) {
                try {
                    $planBody = @{ properties = @{ plan = $c.TargetPlan } } | ConvertTo-Json -Depth 5
                    $null = Invoke-AzRestWithRetry -Uri $uri -Headers $headers -Method Patch -Body $planBody -FollowAsync -AsyncTimeoutSeconds $AsyncTimeoutSeconds

                    $retProps = [ordered]@{}
                    if ($c.RetentionChanged) { $retProps['retentionInDays']      = ConvertTo-TableRetentionApiValue -Value $c.TargetInteractive }
                    if ($c.TotalChanged)     { $retProps['totalRetentionInDays'] = ConvertTo-TableRetentionApiValue -Value $c.TargetTotal }
                    $retBody = @{ properties = $retProps } | ConvertTo-Json -Depth 5
                    $null = Invoke-AzRestWithRetry -Uri $uri -Headers $headers -Method Patch -Body $retBody -FollowAsync -AsyncTimeoutSeconds $AsyncTimeoutSeconds

                    $success = $true
                    $fallback = $true
                    $errorMsg = $null
                    $statusCode = $null
                }
                catch {
                    $fallbackCaughtError = $_
                    $statusCode = Get-TableRetentionErrorStatusCode -ErrorRecord $fallbackCaughtError
                    $fallbackError = switch ($statusCode) {
                        403 { 'Permission denied. Caller needs Microsoft.OperationalInsights/workspaces/tables/write (for example Log Analytics Contributor).' }
                        409 { 'The table update was rejected by the service. Plan switches are limited to once per week per table.' }
                        default { Get-TableRetentionErrorMessage -ErrorRecord $fallbackCaughtError }
                    }
                    $errorMsg = "Combined PATCH failed and fallback also failed: $fallbackError"
                }
            }
        }

        [PSCustomObject]@{
            TableName  = $c.TableName
            Action     = if ($success) { 'Applied' } else { 'Failed' }
            Success    = $success
            Fallback   = $fallback
            StatusCode = $statusCode
            Error      = $errorMsg
        }
    }
}

function Set-TableRetention {
    <#
    .SYNOPSIS
        Shared engine entry point. Validates the requested change, builds the
        change set, optionally previews it, applies (unless -PreviewOnly), and
        returns a summary result.
    .OUTPUTS
        PSCustomObject with ChangeSet (array), Results (array), and Summary
        (TotalCount, AppliedCount, SkippedCount, InvalidCount, FailedCount,
        FallbackCount).
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Context,
        [Parameter(Mandatory)][PSCustomObject[]]$Tables,
        [ValidateSet('Analytics', 'Basic')]
        [string]$TargetPlan,
        [Nullable[int]]$TotalRetentionInDays,
        [Nullable[int]]$RetentionInDays,
        [switch]$PreviewOnly,
        [int]$AsyncTimeoutSeconds = 300
    )

    $changeSetParams = @{ Tables = $Tables }
    if ($PSBoundParameters.ContainsKey('TargetPlan'))           { $changeSetParams['TargetPlan']           = $TargetPlan }
    if ($PSBoundParameters.ContainsKey('TotalRetentionInDays')) { $changeSetParams['TotalRetentionInDays'] = $TotalRetentionInDays }
    if ($PSBoundParameters.ContainsKey('RetentionInDays'))      { $changeSetParams['RetentionInDays']      = $RetentionInDays }

    $changeSet = @(Get-TableRetentionChangeSet @changeSetParams)

    $results = @()
    if (-not $PreviewOnly) {
        $pendingCount = @($changeSet | Where-Object Status -eq 'Pending').Count
        $target = "$pendingCount table(s) in workspace $($Context.WorkspaceName)"
        if ($pendingCount -gt 0 -and $PSCmdlet.ShouldProcess($target, 'Update table retention')) {
            $results = @(Invoke-TableRetentionApply -Context $Context -ChangeSet $changeSet -AsyncTimeoutSeconds $AsyncTimeoutSeconds)
        }
        else {
            # ShouldProcess vetoed or nothing pending: still emit per-item placeholders.
            $results = foreach ($c in $changeSet) {
                [PSCustomObject]@{
                    TableName  = $c.TableName
                    Action     = if ($c.Status -eq 'Pending') { 'NotApplied' } else { $c.Status }
                    Success    = ($c.Status -eq 'Skipped')
                    Fallback   = $false
                    StatusCode = $null
                    Error      = $c.Reason
                }
            }
        }
    }

    $appliedCount  = @($results | Where-Object { $_.Action -eq 'Applied' }).Count
    $skippedCount  = @($changeSet | Where-Object Status -eq 'Skipped').Count
    $invalidCount  = @($changeSet | Where-Object Status -eq 'Invalid').Count
    $failedCount   = @($results | Where-Object { $_.Action -eq 'Failed' }).Count
    $fallbackCount = @($results | Where-Object { $_.Fallback }).Count

    [PSCustomObject]@{
        ChangeSet = $changeSet
        Results   = $results
        Summary   = [PSCustomObject]@{
            TotalCount    = $changeSet.Count
            AppliedCount  = $appliedCount
            SkippedCount  = $skippedCount
            InvalidCount  = $invalidCount
            FailedCount   = $failedCount
            FallbackCount = $fallbackCount
        }
    }
}
