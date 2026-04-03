function Export-Report {
    <#
    .SYNOPSIS
        Exports the analysis report to JSON or Markdown file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Analysis,
        [Parameter(Mandatory)][ValidateSet('json', 'markdown')][string]$Format,
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$WorkspaceName,
        [PSCustomObject]$DefenderXDR
    )

    $moduleVersion = (Import-PowerShellDataFile "$PSScriptRoot\..\LogHorizon.psd1").ModuleVersion

    # Validate output path
    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    if (-not (Test-Path -Path (Split-Path -Path $resolvedPath -Parent) -IsValid)) {
        throw "Invalid output path: $OutputPath"
    }

    # Helper function to prevent XSS and Markdown injection
    function ConvertTo-SafeMarkdown([string]$Text) {
        if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
        return $Text -replace '([\\`*_{}[\]()#+-.!])', '\$1' -replace '<', '&lt;' -replace '>', '&gt;'
    }
    
    $safeWorkspaceName = ConvertTo-SafeMarkdown $WorkspaceName

    switch ($Format) {
        'json' {
            $export = [ordered]@{
                metadata = [ordered]@{
                    tool      = 'Log Horizon'
                    version   = $moduleVersion
                    workspace = $safeWorkspaceName
                    generated = (Get-Date -Format 'o')
                }
                summary              = $Analysis.Summary
                tableAnalysis        = $Analysis.TableAnalysis
                recommendations      = $Analysis.Recommendations
                keywordGaps          = $Analysis.KeywordGaps
                correlationExcluded  = $Analysis.CorrelationExcluded
                correlationIncluded  = $Analysis.CorrelationIncluded
                socRecommendations   = $Analysis.SocRecommendations
            }
            if ($DefenderXDR) {
                $export.defenderXDR = [ordered]@{
                    totalXDRRules    = $DefenderXDR.TotalXDRRules
                    xdrTableCoverage = $DefenderXDR.XDRTableCoverage
                }
            }

            $export | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding utf8
            Write-Output "JSON report written to $OutputPath"
        }

        'markdown' {
            $sb = [System.Text.StringBuilder]::new()
            $s = $Analysis.Summary

            [void]$sb.AppendLine('# Log Horizon - Sentinel Log Analysis Report')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("**Workspace:** $safeWorkspaceName  ")
            [void]$sb.AppendLine("**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC' -AsUTC)  ")
            [void]$sb.AppendLine('')

            # Summary
            [void]$sb.AppendLine('## Summary')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("| Metric | Value |")
            [void]$sb.AppendLine("| --- | --- |")
            [void]$sb.AppendLine("| Total Tables | $($s.TotalTables) |")
            [void]$sb.AppendLine("| Primary Sources | $($s.PrimaryCount) |")
            [void]$sb.AppendLine("| Secondary Sources | $($s.SecondaryCount) |")
            [void]$sb.AppendLine("| Total Ingestion | $($s.TotalMonthlyGB) GB/mo |")
            [void]$sb.AppendLine("| Est. Monthly Cost | `$$($s.TotalMonthlyCost) |")
            [void]$sb.AppendLine("| Active Rules | $($s.EnabledRules) |")
            [void]$sb.AppendLine("| Hunting Queries | $($s.HuntingQueries) |")
            [void]$sb.AppendLine("| Coverage | $($s.CoveragePercent)% |")
            [void]$sb.AppendLine("| Potential Savings | `$$($s.EstTotalSavings) |")
            [void]$sb.AppendLine('')

            # Table analysis
            [void]$sb.AppendLine('## Table Analysis')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("| Table | Class | GB/mo | Cost/mo | Rules | Hunting | Assessment |")
            [void]$sb.AppendLine("| --- | --- | ---: | ---: | ---: | ---: | --- |")

            $sorted = $Analysis.TableAnalysis | Sort-Object EstMonthlyCostUSD -Descending
            foreach ($t in $sorted) {
                [void]$sb.AppendLine(
                    "| $($t.TableName) | $($t.Classification) | $($t.MonthlyGB) | `$$($t.EstMonthlyCostUSD) " +
                    "| $($t.AnalyticsRules) | $($t.HuntingQueries) | $($t.Assessment) |"
                )
            }
            [void]$sb.AppendLine('')

            # Recommendations
            if ($Analysis.Recommendations.Count -gt 0) {
                [void]$sb.AppendLine('## Recommendations')
                [void]$sb.AppendLine('')

                $num = 1
                foreach ($rec in $Analysis.Recommendations) {
                    $icon = switch ($rec.Priority) {
                        'High'   { '🔴' }
                        'Medium' { '🟡' }
                        'Low'    { '🔵' }
                    }
                    [void]$sb.AppendLine("### $num. $icon $($rec.Title)")
                    [void]$sb.AppendLine('')
                    [void]$sb.AppendLine("**Priority:** $($rec.Priority)  ")
                    [void]$sb.AppendLine("**Type:** $($rec.Type)  ")
                    [void]$sb.AppendLine("**Current Cost:** `$$($rec.CurrentCost)/mo  ")
                    if ($rec.EstSavingsUSD -gt 0) {
                        [void]$sb.AppendLine("**Est. Savings:** `$$($rec.EstSavingsUSD)/mo  ")
                    }
                    [void]$sb.AppendLine('')
                    [void]$sb.AppendLine($rec.Detail)
                    [void]$sb.AppendLine('')
                    $num++
                }
            }

            # Keyword gaps
            if ($Analysis.KeywordGaps.Count -gt 0) {
                [void]$sb.AppendLine('## Missing Log Sources (Keyword Matches)')
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine("| Table | Connector | Classification | Keyword |")
                [void]$sb.AppendLine("| --- | --- | --- | --- |")
                foreach ($kg in $Analysis.KeywordGaps) {
                    [void]$sb.AppendLine("| $($kg.TableName) | $($kg.Connector) | $($kg.Classification) | $($kg.MatchedKeyword) |")
                }
                [void]$sb.AppendLine('')
            }

            $sb.ToString() | Set-Content -Path $OutputPath -Encoding utf8
            Write-Output "Markdown report written to $OutputPath"
        }
    }
}
