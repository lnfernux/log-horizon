function Get-TableUsage {
    <#
    .SYNOPSIS
        Queries the Usage table to get per-table ingestion volumes, billable
        status and plan-aware cost estimates.
    .DESCRIPTION
        Volumes are converted with 1 GB = 1000 MB to match Azure Monitor and
        Sentinel billing (GB is 10^9 bytes). IsFree is derived from
        Usage.IsBillable and only falls back to the classification database
        when the Usage rows carry no billable flag. Each observed plan is
        priced with its own rate: Analytics (PricePerGB), Basic
        (BasicPricePerGB) and Auxiliary / Data Lake (LakePricePerGB).
        Monthly extrapolation uses the observed data span (Usage keeps 90 days
        by default) so a longer -DaysBack does not dilute the estimate.
    .OUTPUTS
        Array of PSCustomObjects with per-table totals plus observed Usage.Plan
        breakdown data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Context,
        [ValidateRange(1, 365)][int]$DaysBack = 90,
        [decimal]$PricePerGB = 5.59,
        [decimal]$BasicPricePerGB = 1.15,
        [decimal]$LakePricePerGB = 0.20
    )

    # Fallback free list, used only when Usage rows carry no IsBillable value
    $dbPath = Join-Path $PSScriptRoot '..\Data\log-classifications.json'
    $freeTables = @((Get-Content $dbPath -Raw | ConvertFrom-Json) |
        Where-Object { $_.isFree -eq $true } |
        ForEach-Object { $_.tableName })

    $query = @"
Usage
| where TimeGenerated > ago(${DaysBack}d)
| extend ObservedPlan = iff(isempty(Plan), 'Unknown', Plan)
| summarize DataMB = sum(Quantity),
            UsageRows = count(),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
  by DataType, ObservedPlan, IsBillable
| sort by DataType asc, DataMB desc
"@

    $body = @{ query = $query } | ConvertTo-Json -Compress
    $headers = @{
        Authorization  = "Bearer $($Context.LaToken)"
        'Content-Type' = 'application/json'
    }

    $uri = "https://api.loganalytics.io/v1/workspaces/$($Context.WorkspaceId)/query"
    $response = Invoke-AzRestWithRetry -Uri $uri -Method Post -Headers $headers -Body $body

    $rows = @($response.tables[0].rows)

    Write-Verbose "Usage query returned $($rows.Count) table/plan/billable row(s) over last $DaysBack day(s)."

    $observedDays = Get-UsageObservedDays -Rows $rows -DaysBack $DaysBack
    $monthFactor  = 30.0 / $observedDays

    $priceByPlan = @{
        Analytics = $PricePerGB
        Basic     = $BasicPricePerGB
        Auxiliary = $LakePricePerGB
        Unknown   = $PricePerGB
    }

    $results = foreach ($group in ($rows | Group-Object { $_[0] })) {
        $tableName = [string]$group.Name

        # Collapse billable / non-billable rows into one entry per plan
        $planGroups = $group.Group | Group-Object { if ([string]::IsNullOrWhiteSpace([string]$_[1])) { 'Unknown' } else { [string]$_[1] } }
        $sawBillableFlag = $false
        $sawBillableRow  = $false

        $observedPlanBreakdown = foreach ($pg in $planGroups) {
            $plan = [string]$pg.Name
            $planMB = 0.0
            $planBillableMB = 0.0
            $planRows = [long]0

            foreach ($row in $pg.Group) {
                $mb = [double]$row[3]
                $planMB += $mb
                $planRows += [long]$row[4]

                $billable = ConvertTo-UsageBoolean -Value $row[2]
                if ($null -ne $billable) {
                    $sawBillableFlag = $true
                    if ($billable) { $planBillableMB += $mb; $sawBillableRow = $true }
                }
                elseif ($tableName -notin $freeTables) {
                    $planBillableMB += $mb
                }
            }

            $planDataGB = [math]::Round($planMB / 1000.0, 4)
            $planBillableGB = [math]::Round($planBillableMB / 1000.0, 4)
            $rate = if ($priceByPlan.ContainsKey($plan)) { $priceByPlan[$plan] } else { $PricePerGB }

            [PSCustomObject]@{
                Plan           = $plan
                DataGB         = $planDataGB
                BillableGB     = $planBillableGB
                MonthlyGB      = [math]::Round($planDataGB * $monthFactor, 2)
                MonthlyCostUSD = [math]::Round($planBillableGB * $monthFactor * $rate, 2)
                UsageRowCount  = $planRows
                RecordCount    = $planRows   # deprecated alias of UsageRowCount
            }
        }
        $observedPlanBreakdown = @($observedPlanBreakdown)

        $dataGB     = [math]::Round((($observedPlanBreakdown | Measure-Object -Property DataGB -Sum).Sum), 4)
        $billableGB = [math]::Round((($observedPlanBreakdown | Measure-Object -Property BillableGB -Sum).Sum), 4)
        $usageRows  = [long](($observedPlanBreakdown | Measure-Object -Property UsageRowCount -Sum).Sum)
        $monthlyGB  = [math]::Round($dataGB * $monthFactor, 2)

        if ($sawBillableFlag) {
            $isFree = -not $sawBillableRow
            $isFreeSource = 'usage'
        }
        else {
            $isFree = $tableName -in $freeTables
            $isFreeSource = 'database'
        }

        $cost = if ($isFree) { 0 } else { [math]::Round((($observedPlanBreakdown | Measure-Object -Property MonthlyCostUSD -Sum).Sum), 2) }
        $observedPlans = @($observedPlanBreakdown | ForEach-Object { $_.Plan } | Sort-Object -Unique)

        [PSCustomObject]@{
            TableName             = $tableName
            DataGB                = $dataGB
            BillableGB            = $billableGB
            MonthlyGB             = $monthlyGB
            UsageRowCount         = $usageRows
            RecordCount           = $usageRows   # deprecated alias of UsageRowCount
            EstMonthlyCostUSD     = $cost
            IsFree                = $isFree
            IsFreeSource          = $isFreeSource
            ObservedDays          = $observedDays
            ObservedPlans         = $observedPlans
            ObservedPlanCount     = $observedPlans.Count
            ObservedPlanBreakdown = @($observedPlanBreakdown | Sort-Object MonthlyGB -Descending)
        }
    }

    $results | Sort-Object DataGB -Descending
}

function Get-UsageObservedDays {
    <#
    .SYNOPSIS
        Returns the number of days actually covered by the Usage rows, capped
        at DaysBack and never below 1.
    #>
    [CmdletBinding()]
    param(
        [array]$Rows,
        [int]$DaysBack = 90
    )

    $first = $null
    $last  = $null
    foreach ($row in $Rows) {
        if ($row.Count -lt 7) { continue }
        $f = [datetime]::MinValue; $l = [datetime]::MinValue
        if (-not [datetime]::TryParse([string]$row[5], [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$f)) { continue }
        if (-not [datetime]::TryParse([string]$row[6], [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$l)) { continue }
        if ($null -eq $first -or $f -lt $first) { $first = $f }
        if ($null -eq $last  -or $l -gt $last)  { $last  = $l }
    }

    if ($null -eq $first -or $null -eq $last) { return $DaysBack }

    $span = [int][math]::Ceiling(($last - $first).TotalDays)
    if ($span -lt 1) { $span = 1 }
    if ($span -gt $DaysBack) { $span = $DaysBack }
    $span
}

function ConvertTo-UsageBoolean {
    <#
    .SYNOPSIS
        Normalises the IsBillable cell (bool, string or null) to a nullable bool.
    #>
    [CmdletBinding()]
    param([object]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value }
    $s = ([string]$Value).Trim()
    if ($s -eq '') { return $null }
    $parsed = $false
    if ([bool]::TryParse($s, [ref]$parsed)) { return $parsed }
    $null
}

