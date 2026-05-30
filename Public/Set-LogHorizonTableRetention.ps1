function Set-LogHorizonTableRetention {
    <#
    .SYNOPSIS
        Updates Azure Log Analytics table retention and/or plan for one or more
        tables in a Sentinel workspace, using the same engine as the Log Horizon
        interactive wizard.
    .DESCRIPTION
        Wraps Connect-Sentinel + the Set-TableRetention private engine. Supports
        single or bulk updates, validates target values against the documented
        Tables API bounds, previews via -WhatIf, and is gated by ShouldProcess.

        For interactive (hot) retention, pass -1 to mean "inherit workspace default".
        For total retention, pass -1 to mean "remove long-term retention".
    .EXAMPLE
        Set-LogHorizonTableRetention -SubscriptionId $sub -ResourceGroupName $rg `
            -WorkspaceName $ws -TableName 'SigninLogs' -TotalRetentionInDays 365 -WhatIf
    .EXAMPLE
        Set-LogHorizonTableRetention -SubscriptionId $sub -ResourceGroupName $rg `
            -WorkspaceName $ws -TableName 'AzureDiagnostics','VMConnection' `
            -TargetPlan Basic -TotalRetentionInDays 730 -Confirm
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$WorkspaceName,
        [Parameter(Mandatory)][string[]]$TableName,
        [ValidateSet('Analytics', 'Basic')]
        [string]$TargetPlan,
        # -1 means "remove long-term retention". Any other int is sent as-is.
        [int]$TotalRetentionInDays = [int]::MinValue,
        # -1 means "inherit workspace default".
        [int]$RetentionInDays = [int]::MinValue,
        [int]$AsyncTimeoutSeconds = 300
    )

    $ErrorActionPreference = 'Stop'

    $context = Connect-Sentinel -SubscriptionId $SubscriptionId `
                                -ResourceGroup $ResourceGroupName `
                                -WorkspaceName $WorkspaceName

    try {
        $retentionData = Get-TableRetention -Context $context
        $allTables = $retentionData.Tables
        $selected = @($allTables | Where-Object { $_.TableName -in $TableName })

        $missing = @($TableName | Where-Object { $_ -notin $selected.TableName })
        if ($missing.Count -gt 0) {
            Write-Warning "Tables not found in workspace: $($missing -join ', ')"
        }
        if ($selected.Count -eq 0) {
            throw 'No matching tables found in the workspace.'
        }

        $engineParams = @{
            Context             = $context
            Tables              = $selected
            AsyncTimeoutSeconds = $AsyncTimeoutSeconds
        }
        if ($PSBoundParameters.ContainsKey('TargetPlan')) { $engineParams['TargetPlan'] = $TargetPlan }
        if ($TotalRetentionInDays -ne [int]::MinValue) {
            $engineParams['TotalRetentionInDays'] = if ($TotalRetentionInDays -eq -1) { $null } else { $TotalRetentionInDays }
        }
        if ($RetentionInDays -ne [int]::MinValue) {
            $engineParams['RetentionInDays'] = if ($RetentionInDays -eq -1) { $null } else { $RetentionInDays }
        }

        if ($WhatIfPreference) {
            $engineParams['PreviewOnly'] = $true
        }

        if (-not $WhatIfPreference -and -not $PSCmdlet.ShouldProcess("$WorkspaceName ($($selected.Count) table(s))", 'Update table retention/type')) {
            return
        }

        $engineParams['Confirm'] = $false

        Set-TableRetention @engineParams
    }
    finally {
        if ($null -ne $context) {
            $context.ArmToken = $null
            $context.LaToken  = $null
        }
    }
}
