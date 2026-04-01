function Get-TableUsage {
    <#
    .SYNOPSIS
        Queries the Usage table and _BilledSize to get per-table ingestion volumes.
    .OUTPUTS
        Array of PSCustomObjects: TableName, DataGB, RecordCount, EstMonthlyCostUSD
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Context,
        [int]$DaysBack = 90,
        [decimal]$PricePerGB = 5.59
    )

    $freeTables = @(
        'SecurityAlert', 'SecurityIncident', 'AzureActivity',
        'OfficeActivity', 'SentinelHealth', 'SentinelAudit'
    )

    $query = @"
Usage
| where TimeGenerated > ago(${DaysBack}d)
| where IsBillable == true
| summarize DataGB = sum(Quantity) / 1024.0,
            RecordCount = sum(ResourceUri == ResourceUri)
  by DataType
| sort by DataGB desc
"@

    $body = @{ query = $query } | ConvertTo-Json -Compress
    $headers = @{
        Authorization  = "Bearer $($Context.LaToken)"
        'Content-Type' = 'application/json'
    }

    $uri = "https://api.loganalytics.io/v1/workspaces/$($Context.WorkspaceId)/query"
    $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body -ErrorAction Stop

    $columns = $response.tables[0].columns
    $rows    = $response.tables[0].rows

    $results = foreach ($row in $rows) {
        $tableName = $row[0]
        $dataGB    = [math]::Round([double]$row[1], 4)
        $records   = [long]$row[2]

        $isFree    = $tableName -in $freeTables
        $monthFactor = 30.0 / $DaysBack
        $monthlyGB = [math]::Round($dataGB * $monthFactor, 2)
        $cost      = if ($isFree) { 0 } else { [math]::Round($monthlyGB * $PricePerGB, 2) }

        [PSCustomObject]@{
            TableName        = $tableName
            DataGB           = $dataGB
            MonthlyGB        = $monthlyGB
            RecordCount      = $records
            EstMonthlyCostUSD = $cost
            IsFree           = $isFree
        }
    }

    $results
}
