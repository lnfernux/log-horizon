function Write-Report {
    <#
    .SYNOPSIS
        Renders the Log Horizon analysis report using Spectre.Console via
        PwshSpectreConsole for polished terminal output with an interactive menu.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Analysis,
        [string]$WorkspaceName,
        [PSCustomObject]$DefenderXDR,
        [string]$ExportFormat,
        [string]$ExportPath
    )

    # Banner
    Write-LogHorizonBanner

    # Dashboard (always shown first)
    Write-Dashboard -Analysis $Analysis -WorkspaceName $WorkspaceName

    # Interactive menu loop
    Write-InteractiveMenu -Analysis $Analysis -WorkspaceName $WorkspaceName `
                          -DefenderXDR $DefenderXDR `
                          -ExportFormat $ExportFormat -ExportPath $ExportPath
}

# Banner
function Write-LogHorizonBanner {
    $art = @'
[dodgerblue2]
            ██╗      ██████╗  ██████╗
            ██║     ██╔═══██╗██╔════╝
            ██║     ██║   ██║██║  ███╗
            ██║     ██║   ██║██║   ██║
            ███████╗╚██████╔╝╚██████╔╝
            ╚══════╝ ╚═════╝  ╚═════╝[/]
[deepskyblue1]    ██╗  ██╗ ██████╗ ██████╗ ██╗███████╗ ██████╗ ███╗   ██╗
    ██║  ██║██╔═══██╗██╔══██╗██║╚══███╔╝██╔═══██╗████╗  ██║
    ███████║██║   ██║██████╔╝██║  ███╔╝ ██║   ██║██╔██╗ ██║
    ██╔══██║██║   ██║██╔══██╗██║ ███╔╝  ██║   ██║██║╚██╗██║
    ██║  ██║╚██████╔╝██║  ██║██║███████╗╚██████╔╝██║ ╚████║
    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝[/]
[grey]       ⚙  Microsoft Sentinel SIEM Log Source Analyzer  ⚙[/]
[dim]              created by infernux.no[/]
'@

    Write-SpectreHost $art
    Write-SpectreHost ""
}

# Dashboard
function Write-Dashboard {
    param(
        [PSCustomObject]$Analysis,
        [string]$WorkspaceName
    )

    $s = $Analysis.Summary

    # Overview panel
    $filled = [math]::Floor($s.CoveragePercent / 10)
    $empty  = 10 - $filled
    $coverageColor = if ($s.CoveragePercent -ge 60) { 'green' } elseif ($s.CoveragePercent -ge 30) { 'yellow' } else { 'red' }
    $bar = "[${coverageColor}]$('█' * $filled)[/][grey]$('░' * $empty)[/] $($s.CoveragePercent)%"

    $overviewLines = @(
        "[bold]Workspace:[/]        [deepskyblue1]$(Get-SpectreEscapedText $WorkspaceName)[/]"
        "[bold]Scanned:[/]          $(Get-Date -Format 'yyyy-MM-dd')"
        ""
        "[bold]Tables:[/]           $($s.TotalTables)  [dim]([green]$($s.PrimaryCount) primary[/] [yellow]$($s.SecondaryCount) secondary[/]$(if ($s.UnknownCount -gt 0) { " [red]$($s.UnknownCount) unknown[/]" }))[/]"
        "[bold]Ingestion:[/]        $($s.TotalMonthlyGB) GB/mo"
        "[bold]Est. Cost:[/]        [bold]`$$($s.TotalMonthlyCost)/mo[/] [dim]@ `$$($s.PricePerGB)/GB[/]"
        "[bold]Rules:[/]            $($s.EnabledRules) active  |  [bold]Hunting:[/] $($s.HuntingQueries)"
        "[bold]Coverage:[/]         $bar"
    )

    if ($s.EstTotalSavings -gt 0) {
        $overviewLines += "[bold]Savings Potential:[/] [green]`$$($s.EstTotalSavings)/mo[/]"
    }

    $overviewText = $overviewLines -join "`n"
    $overviewText | Format-SpectrePanel -Header "[dodgerblue2] OVERVIEW [/]" -Border Rounded -Color DodgerBlue2

    Write-SpectreHost ""

    # Top 10 sources table
    $top = $Analysis.TableAnalysis |
        Sort-Object EstMonthlyCostUSD -Descending |
        Select-Object -First 10

    $table = @()
    $rank = 0
    foreach ($t in $top) {
        $rank++

        $clsMarkup = switch ($t.Classification) {
            'primary'   { '[green]PRIMARY[/]' }
            'secondary' { '[yellow]SECONDARY[/]' }
            default     { '[red]UNKNOWN[/]' }
        }

        $assessMarkup = switch ($t.Assessment) {
            'High Value'       { '[green]High Value[/]' }
            'Good Value'       { '[green]Good Value[/]' }
            'Missing Coverage' { '[yellow]Missing Coverage[/]' }
            'Optimize'         { '[yellow]Optimize[/]' }
            'Low Value'        { '[red]Low Value[/]' }
            'Underutilized'    { '[grey]Underutilized[/]' }
            'Free Tier'        { '[deepskyblue1]Free[/]' }
            default            { '[grey]-[/]' }
        }

        $costStr = if ($t.IsFree) { '[deepskyblue1]FREE[/]' } else { "`$$($t.EstMonthlyCostUSD)" }

        $table += [PSCustomObject]@{
            '#'          = $rank
            'Table'      = Get-SpectreEscapedText $t.TableName
            'GB/mo'      = $t.MonthlyGB
            'Cost/mo'    = $costStr
            'Class'      = $clsMarkup
            'Rules'      = $t.TotalCoverage
            'Assessment' = $assessMarkup
        }
    }

    $table | Format-SpectreTable -Border Rounded -Color DeepSkyBlue1 -HeaderColor DodgerBlue2 -AllowMarkup

    Write-SpectreHost ""
    Write-SpectreHost "[dim]  Showing top 10 by cost. Use menu below to see all tables.[/]"
    Write-SpectreHost ""
}

# Interactive menu
function Write-InteractiveMenu {
    param(
        [PSCustomObject]$Analysis,
        [string]$WorkspaceName,
        [PSCustomObject]$DefenderXDR,
        [string]$ExportFormat,
        [string]$ExportPath
    )

    $menuItems = [ordered]@{
        'View Recommendations'          = 'recommendations'
        'View Detection Assessment'     = 'detection'
        'View SOC Optimization'         = 'soc'
        'View All Tables'               = 'tables'
    }

    if ($DefenderXDR) {
        $menuItems['View Defender XDR Analysis'] = 'xdr'
    }

    $menuItems['Export Report']       = 'export'
    $menuItems['Quit']                = 'quit'

    $continue = $true
    while ($continue) {
        Write-SpectreRule -Title "[dodgerblue2]MENU[/]" -Color DodgerBlue2
        Write-SpectreHost ""

        $choice = Read-SpectreSelection -Title "Select a view:" `
                    -Choices @($menuItems.Keys) `
                    -Color DodgerBlue2

        $action = $menuItems[$choice]

        Write-SpectreHost ""

        switch ($action) {
            'recommendations' { Write-Recommendations -Analysis $Analysis }
            'detection'       { Write-DetectionAssessment -Analysis $Analysis }
            'soc'             { Write-SocOptimization -Analysis $Analysis }
            'tables'          { Write-AllTables -Analysis $Analysis }
            'xdr'             { Write-XDRAnalysis -Analysis $Analysis -DefenderXDR $DefenderXDR }
            'export'          {
                Invoke-ExportFromMenu -Analysis $Analysis `
                                      -WorkspaceName $WorkspaceName `
                                      -DefenderXDR $DefenderXDR `
                                      -ExportFormat $ExportFormat `
                                      -ExportPath $ExportPath
            }
            'quit'            { $continue = $false }
        }

        if ($continue -and $action -ne 'export') {
            Write-SpectreHost ""
            Read-SpectrePause -Message "[dim]Press [bold]Enter[/] to return to menu...[/]"
        }
    }

    Write-SpectreHost ""
    Write-SpectreHost "[dim]Log Horizon v0.2.0 | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC' -AsUTC)[/]"
    Write-SpectreHost ""
}

# Recommendations
function Write-Recommendations {
    param([PSCustomObject]$Analysis)

    if ($Analysis.Recommendations.Count -eq 0) {
        Write-SpectreHost "[green]No recommendations - your workspace looks well-optimized![/]"
        return
    }

    # High first, then Medium, then Low, savings desc within each
    $prioOrder = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2 }
    $sorted = $Analysis.Recommendations |
        Sort-Object { $prioOrder[$_.Priority] }, { -$_.EstSavingsUSD }

    $maxShow = [math]::Min(10, $sorted.Count)

    $lines = @("[bold]Recommendations[/] [dim](sorted by priority, top $maxShow)[/]", "")

    for ($i = 0; $i -lt $maxShow; $i++) {
        $rec = $sorted[$i]

        $prioIcon = switch ($rec.Priority) {
            'High'   { '[red]HIGH[/]' }
            'Medium' { '[yellow]MED[/]' }
            'Low'    { '[deepskyblue1]LOW[/]' }
        }

        $savings = if ($rec.EstSavingsUSD -gt 0) { "  [green]~`$$($rec.EstSavingsUSD)/mo savings[/]" } else { '' }
        $num = ($i + 1).ToString().PadLeft(2)

        $lines += "[bold]$num.[/] $prioIcon  [bold]$(Get-SpectreEscapedText $rec.Title)[/]$savings"
        $lines += "      [dim]$(Get-SpectreEscapedText $rec.Detail)[/]"
        $lines += ""
    }

    if ($sorted.Count -gt 10) {
        $lines += "[dim]... and $($sorted.Count - 10) more. Export report for full list.[/]"
    }

    $body = $lines -join "`n"
    $body | Format-SpectrePanel -Header "[dodgerblue2] RECOMMENDATIONS [/]" -Border Rounded -Color DodgerBlue2
}

# Detection assessment
function Write-DetectionAssessment {
    param([PSCustomObject]$Analysis)

    $lines = @()

    # Well covered
    $wellCovered = $Analysis.TableAnalysis |
        Where-Object { $_.Classification -eq 'primary' -and $_.TotalCoverage -ge 3 } |
        Group-Object Category

    if ($wellCovered) {
        $lines += "[green][bold]Well Covered[/][/]"
        foreach ($grp in $wellCovered) {
            $tableList = ($grp.Group | ForEach-Object { $_.TableName }) -join ', '
            $totalRules = ($grp.Group | Measure-Object TotalCoverage -Sum).Sum
            $lines += "  [green]●[/] $(Get-SpectreEscapedText $grp.Name): $(Get-SpectreEscapedText $tableList) [dim]($totalRules rules)[/]"
        }
        $lines += ""
    }

    # Gaps (1-2 rules)
    $gaps = $Analysis.TableAnalysis |
        Where-Object { $_.Classification -eq 'primary' -and -not $_.IsFree -and $_.TotalCoverage -lt 3 -and $_.TotalCoverage -ge 1 }

    if ($gaps) {
        $lines += "[yellow][bold]Gaps Detected[/][/]"
        foreach ($g in $gaps) {
            $lines += "  [yellow]●[/] $(Get-SpectreEscapedText $g.TableName) - $($g.MonthlyGB) GB/mo, only $($g.TotalCoverage) rule(s)"
        }
        $lines += ""
    }

    # Zero detections
    $noCoverage = $Analysis.TableAnalysis |
        Where-Object { $_.Classification -eq 'primary' -and -not $_.IsFree -and $_.TotalCoverage -eq 0 }

    if ($noCoverage) {
        $lines += "[red][bold]Primary Sources With Zero Detections[/][/]"
        foreach ($n in $noCoverage) {
            $lines += "  [red]●[/] $(Get-SpectreEscapedText $n.TableName) - $(Get-SpectreEscapedText $n.Category)"
        }
        $lines += ""
    }

    # Keyword gaps
    if ($Analysis.KeywordGaps.Count -gt 0) {
        $lines += "[red][bold]Not Ingesting (recommended based on keywords)[/][/]"
        foreach ($kg in $Analysis.KeywordGaps) {
            $lines += "  [red]●[/] $(Get-SpectreEscapedText $kg.TableName) - $(Get-SpectreEscapedText $kg.Description)"
        }
        $lines += ""
    }

    if ($lines.Count -eq 0) {
        $lines += "[green]All primary sources have adequate detection coverage.[/]"
    }

    $body = $lines -join "`n"
    $body | Format-SpectrePanel -Header "[dodgerblue2] DETECTION ASSESSMENT [/]" -Border Rounded -Color DodgerBlue2
}

# SOC optimization
function Write-SocOptimization {
    param([PSCustomObject]$Analysis)

    if (-not $Analysis.SocRecommendations -or $Analysis.SocRecommendations.Count -eq 0) {
        Write-SpectreHost "[dim]No SOC optimization recommendations available.[/]"
        return
    }

    $table = @()
    $num = 0
    foreach ($sr in $Analysis.SocRecommendations) {
        $num++
        $stateMarkup = switch ($sr.State) {
            'Active' { '[yellow]Active[/]' }
            default  { '[dim]Inactive[/]' }
        }

        $table += [PSCustomObject]@{
            '#'       = $num
            'State'   = $stateMarkup
            'Title'   = Get-SpectreEscapedText $sr.Title
        }
    }

    $table | Format-SpectreTable -Border Rounded -Color DodgerBlue2 -HeaderColor DodgerBlue2 -AllowMarkup
    Write-SpectreHost "[dim]  $($Analysis.SocRecommendations.Count) total Microsoft SOC optimization recommendations.[/]"
}

# All tables
function Write-AllTables {
    param([PSCustomObject]$Analysis)

    $sorted = $Analysis.TableAnalysis | Sort-Object EstMonthlyCostUSD -Descending

    $table = @()
    $rank = 0
    foreach ($t in $sorted) {
        $rank++

        $clsMarkup = switch ($t.Classification) {
            'primary'   { '[green]PRIMARY[/]' }
            'secondary' { '[yellow]SECONDARY[/]' }
            default     { '[red]UNKNOWN[/]' }
        }

        $assessMarkup = switch ($t.Assessment) {
            'High Value'       { '[green]High Value[/]' }
            'Good Value'       { '[green]Good Value[/]' }
            'Missing Coverage' { '[yellow]Missing Coverage[/]' }
            'Optimize'         { '[yellow]Optimize[/]' }
            'Low Value'        { '[red]Low Value[/]' }
            'Underutilized'    { '[grey]Underutilized[/]' }
            'Free Tier'        { '[deepskyblue1]Free[/]' }
            default            { '[grey]-[/]' }
        }

        $costStr = if ($t.IsFree) { '[deepskyblue1]FREE[/]' } else { "`$$($t.EstMonthlyCostUSD)" }

        $table += [PSCustomObject]@{
            '#'          = $rank
            'Table'      = Get-SpectreEscapedText $t.TableName
            'GB/mo'      = $t.MonthlyGB
            'Cost/mo'    = $costStr
            'Class'      = $clsMarkup
            'Rules'      = $t.AnalyticsRules
            'Hunting'    = $t.HuntingQueries
            'Assessment' = $assessMarkup
        }
    }

    $table | Format-SpectreTable -Border Rounded -Color DodgerBlue2 -HeaderColor DodgerBlue2 -AllowMarkup
    Write-SpectreHost "[dim]  $($sorted.Count) total tables.[/]"
}

# Defender XDR analysis
function Write-XDRAnalysis {
    param(
        [PSCustomObject]$Analysis,
        [PSCustomObject]$DefenderXDR
    )

    if (-not $DefenderXDR) {
        Write-SpectreHost "[dim]Defender XDR data not available. Re-run with -IncludeDefenderXDR.[/]"
        return
    }

    $lines = @(
        "[bold]Custom Detections:[/] $($DefenderXDR.TotalXDRRules) rules"
    )

    $xdrStreaming = $Analysis.TableAnalysis | Where-Object IsXDRStreaming
    if ($xdrStreaming) {
        $streamingNames = ($xdrStreaming | ForEach-Object { Get-SpectreEscapedText $_.TableName }) -join ', '
        $lines += "[bold]Streaming to Sentinel:[/] $streamingNames"
    }

    $xdrRecs = $Analysis.Recommendations | Where-Object Type -eq 'XDROptimize'
    if ($xdrRecs) {
        $lines += ""
        $lines += "[yellow][bold]Optimization Opportunities:[/][/]"
        foreach ($xr in $xdrRecs) {
            $lines += "  [yellow]>[/] $(Get-SpectreEscapedText $xr.Title)"
            $lines += "    [dim]$(Get-SpectreEscapedText $xr.Detail)[/]"
        }
    }

    $body = $lines -join "`n"
    $body | Format-SpectrePanel -Header "[dodgerblue2] DEFENDER XDR [/]" -Border Rounded -Color DodgerBlue2
}

# Export from menu
function Invoke-ExportFromMenu {
    param(
        [PSCustomObject]$Analysis,
        [string]$WorkspaceName,
        [PSCustomObject]$DefenderXDR,
        [string]$ExportFormat,
        [string]$ExportPath
    )

    # If format wasn't pre-selected, ask the user
    if (-not $ExportFormat) {
        $formatChoice = Read-SpectreSelection -Title "Export format:" `
                          -Choices @('JSON', 'Markdown', 'Cancel') `
                          -Color DodgerBlue2

        if ($formatChoice -eq 'Cancel') { return }
        $ExportFormat = $formatChoice.ToLower()
    }

    if (-not $ExportPath) {
        $ext = switch ($ExportFormat) { 'json' { '.json' } 'markdown' { '.md' } }
        $ExportPath = "log-horizon-report-$(Get-Date -Format 'yyyyMMdd-HHmmss')$ext"
    }

    Export-Report -Analysis $Analysis `
                  -Format $ExportFormat `
                  -OutputPath $ExportPath `
                  -WorkspaceName $WorkspaceName `
                  -DefenderXDR $DefenderXDR

    Write-SpectreHost "[green]Report exported to [bold]$(Get-SpectreEscapedText $ExportPath)[/][/]"
}
