function Get-TableUsage {
    <#
    .SYNOPSIS
        Queries the Usage table to get per-table ingestion volumes.
    .OUTPUTS
        Array of PSCustomObjects with per-table totals plus observed Usage.Plan
        breakdown data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Context,
        [int]$DaysBack = 90,
        [decimal]$PricePerGB = 5.59
    )

    # Load free table list from classification DB
    $dbPath = Join-Path $PSScriptRoot '..\Data\log-classifications.json'
    $freeTables = @((Get-Content $dbPath -Raw | ConvertFrom-Json) |
        Where-Object { $_.isFree -eq $true } |
        ForEach-Object { $_.tableName })

    $query = @"
Usage
| where TimeGenerated > ago(${DaysBack}d)
| extend ObservedPlan = iff(isempty(Plan), 'Unknown', Plan)
| summarize DataGB = sum(Quantity) / 1024.0,
            RecordCount = count()
  by DataType, ObservedPlan
| sort by DataType asc, DataGB desc
"@

    $body = @{ query = $query } | ConvertTo-Json -Compress
    $headers = @{
        Authorization  = "Bearer $($Context.LaToken)"
        'Content-Type' = 'application/json'
    }

    $uri = "https://api.loganalytics.io/v1/workspaces/$($Context.WorkspaceId)/query"
    $response = Invoke-AzRestWithRetry -Uri $uri -Method Post -Headers $headers -Body $body

    $rows = $response.tables[0].rows

    Write-Verbose "Usage query returned $($rows.Count) table/plan row(s) over last $DaysBack day(s)."

    $monthFactor = 30.0 / $DaysBack

    $results = foreach ($group in ($rows | Group-Object { $_[0] })) {
        $tableName = [string]$group.Name
        $isFree = $tableName -in $freeTables

        # Preserve the existing one-row-per-table contract while carrying a
        # per-plan breakdown sourced from Usage.Plan.
        $observedPlanBreakdown = foreach ($row in $group.Group) {
            $plan = if ([string]::IsNullOrWhiteSpace([string]$row[1])) { 'Unknown' } else { [string]$row[1] }
            $dataGB = [math]::Round([double]$row[2], 4)
            $records = [long]$row[3]

            [PSCustomObject]@{
                Plan        = $plan
                DataGB      = $dataGB
                MonthlyGB   = [math]::Round($dataGB * $monthFactor, 2)
                RecordCount = $records
            }
        }

        $dataGB = [math]::Round((($observedPlanBreakdown | Measure-Object -Property DataGB -Sum).Sum), 4)
        $records = [long](($observedPlanBreakdown | Measure-Object -Property RecordCount -Sum).Sum)
        $monthlyGB = [math]::Round($dataGB * $monthFactor, 2)
        $cost = if ($isFree) { 0 } else { [math]::Round($monthlyGB * $PricePerGB, 2) }
        $observedPlans = @($observedPlanBreakdown | ForEach-Object { $_.Plan } | Sort-Object -Unique)

        [PSCustomObject]@{
            TableName             = $tableName
            DataGB                = $dataGB
            MonthlyGB             = $monthlyGB
            RecordCount           = $records
            EstMonthlyCostUSD     = $cost
            IsFree                = $isFree
            ObservedPlans         = $observedPlans
            ObservedPlanCount     = $observedPlans.Count
            ObservedPlanBreakdown = @($observedPlanBreakdown | Sort-Object MonthlyGB -Descending)
        }
    }

    $results | Sort-Object DataGB -Descending
}
