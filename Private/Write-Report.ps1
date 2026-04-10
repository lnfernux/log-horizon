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
    Write-Dashboard -Analysis $Analysis -WorkspaceName $WorkspaceName -DefenderXDR $DefenderXDR

    # Auto-export when -Output was specified (before showing menu)
    if ($ExportFormat) {
        if (-not $ExportPath) { $ExportPath = $PWD.Path }
        Export-Report -Analysis $Analysis `
                      -Format $ExportFormat `
                      -OutputPath $ExportPath `
                      -WorkspaceName $WorkspaceName `
                      -DefenderXDR $DefenderXDR
        Write-SpectreHost "[green]Report exported to [bold]$(Get-SafeEscapedText $ExportPath)[/][/]"
        Write-SpectreHost ""
    }

    # Interactive menu loop
    Write-InteractiveMenu -Analysis $Analysis -WorkspaceName $WorkspaceName `
                          -DefenderXDR $DefenderXDR `
                          -ExportFormat $ExportFormat -ExportPath $ExportPath
}

function Get-ConsoleWidth {
    [CmdletBinding()]
    param()
    try { $Host.UI.RawUI.WindowSize.Width } catch { 120 }
}

function Test-ConsoleSize {
    [CmdletBinding()]
    param(
        [int]$MinimumWidth = 120,
        [int]$MinimumHeight = 30
    )

    try {
        $size = $Host.UI.RawUI.WindowSize
        return ($size.Width -ge $MinimumWidth -and $size.Height -ge $MinimumHeight)
    }
    catch {
        return $true
    }
}

function Invoke-ConsoleSizeCheck {
    param(
        [int]$MinimumWidth = 120,
        [int]$MinimumHeight = 30
    )

    if (Test-ConsoleSize -MinimumWidth $MinimumWidth -MinimumHeight $MinimumHeight) {
        return
    }

    $current = $null
    try { $current = $Host.UI.RawUI.WindowSize } catch { }

    $currentWidth = if ($current) { $current.Width } else { '?' }
    $currentHeight = if ($current) { $current.Height } else { '?' }

    Write-SpectreHost "[yellow]:warning: Terminal is $currentWidth x $currentHeight. Recommended minimum is $MinimumWidth x $MinimumHeight for clean table/menu rendering.[/]"
    Write-SpectreHost "[dim]Resize the terminal, then press Enter to continue.[/]"
    Read-SpectrePause -Message ""
}

function Get-SafeEscapedText {
    [CmdletBinding()]
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '-' }
    Get-SpectreEscapedText $Value
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
        [string]$WorkspaceName,
        [PSCustomObject]$DefenderXDR
    )

    $s = $Analysis.Summary

    # Overview panel
    $filled = [math]::Floor($s.CoveragePercent / 10)
    $empty  = 10 - $filled
    $coverageColor = if ($s.CoveragePercent -ge 60) { 'green' } elseif ($s.CoveragePercent -ge 30) { 'yellow' } else { 'red' }
    $bar = "[${coverageColor}]$('█' * $filled)[/][grey]$('░' * $empty)[/] $($s.CoveragePercent)%"

    $overviewLines = @(
        "[bold]Workspace:[/]        [deepskyblue1]$(Get-SafeEscapedText $WorkspaceName)[/]"
        "[bold]Scanned:[/]          $(Get-Date -Format 'yyyy-MM-dd')"
        ""
        "[bold]Tables:[/]           $($s.TotalTables)  [dim]([green]$($s.PrimaryCount) primary[/] [yellow]$($s.SecondaryCount) secondary[/]$(if ($s.UnknownCount -gt 0) { " [red]$($s.UnknownCount) unknown[/]" }))[/]"
        "[bold]Ingestion:[/]        $($s.TotalMonthlyGB) GB/mo"
        "[bold]Est. Cost:[/]        [bold]`$$($s.TotalMonthlyCost)/mo[/] [dim]@ `$$($s.PricePerGB)/GB[/]"
        "[bold]Rules:[/]            $($s.EnabledRules) active  |  [bold]Hunting:[/] $($s.HuntingQueries)$(if ($s.DontCorrCount -gt 0) { "  |  [yellow]$($s.DontCorrCount) excluded from correlation[/]" })"
        "[bold]Coverage:[/]         $bar"
    )

    if ($s.RetentionChecked -gt 0) {
        $retColor = if ($s.RetentionNonCompliant -eq 0) { 'green' } elseif ($s.RetentionNonCompliant -le 5) { 'yellow' } else { 'red' }
        $overviewLines += "[bold]Retention:[/]        [${retColor}]$($s.RetentionCompliant) of $($s.RetentionChecked) Analytics tables >= 90d[/]"
        if ($s.RetentionImprovable -gt 0) {
            $overviewLines += "                    [dim]$($s.RetentionImprovable) table(s) could benefit from extended retention[/]"
        }
    }
    if ($s.WorkspaceRetentionDays -gt 0 -and $s.WorkspaceRetentionDays -lt 90) {
        $overviewLines += "[bold yellow]:warning: Workspace default retention is $($s.WorkspaceRetentionDays)d - increase to 90d[/]"
    }

    if ($s.TablesWithTransforms -gt 0 -or $s.SplitTables -gt 0) {
        $transformParts = @()
        if ($s.TablesWithTransforms -gt 0) { $transformParts += "[deepskyblue1]$($s.TablesWithTransforms) table(s) with transforms[/]" }
        if ($s.SplitTables -gt 0) { $transformParts += "[yellow]$($s.SplitTables) split table(s)[/]" }
        if ($s.TransformDCRs -gt 0) { $transformParts += "[dim]$($s.TransformDCRs) DCR(s)[/]" }
        $overviewLines += "[bold]Transforms:[/]       $($transformParts -join '  |  ')"
    }

    if ($s.EstTotalSavings -gt 0) {
        $overviewLines += "[bold]Savings Potential:[/] [green]`$$($s.EstTotalSavings)/mo[/]"
    }

    if ($s.DetectionRulesAnalyzed -gt 0) {
        $overviewLines += "[bold]Rule Quality:[/]     [deepskyblue1]$($s.DetectionRulesAnalyzed) analyzed[/] | [yellow]$($s.NoisyRulesDetected) noisy[/] | [dim]$($s.AutoClosedIncidents) auto-closed incidents[/]"
    }

    if ($DefenderXDR) {
        $cdrCorrelated = if ($Analysis.DetectionAnalyzer -and $Analysis.DetectionAnalyzer.Summary.CustomDetectionRules -gt 0) {
            " | [dim]$($Analysis.DetectionAnalyzer.Summary.CDRCorrelatedIncidents) with incidents[/]"
        } else { '' }
        $xdrStreamed = @($Analysis.TableAnalysis | Where-Object IsXDRStreaming)
        $xdrStreamingCount = $xdrStreamed.Count
        $tierParts = @()
        $analyticsTierCount = @($xdrStreamed | Where-Object { $_.XDRState -eq 'Analytics' }).Count
        $basicTierCount     = @($xdrStreamed | Where-Object { $_.XDRState -eq 'Basic' }).Count
        $dataLakeTierCount  = @($xdrStreamed | Where-Object { $_.XDRState -eq 'Auxiliary' }).Count
        if ($analyticsTierCount -gt 0) { $tierParts += "$analyticsTierCount analytics" }
        if ($basicTierCount -gt 0)     { $tierParts += "$basicTierCount basic" }
        if ($dataLakeTierCount -gt 0)  { $tierParts += "$dataLakeTierCount data lake" }
        $tierDetail = if ($tierParts.Count -gt 0) { " ($($tierParts -join ', '))" } else { '' }
        $notStreamedCount = $Analysis.XdrChecker.Summary.NotStreamedCount
        $notStreamedPart = if ($notStreamedCount -gt 0) { " | [dim]$notStreamedCount not streamed[/]" } else { '' }
        $overviewLines += "[bold]Defender XDR:[/]     [deepskyblue1]$($DefenderXDR.TotalXDRRules) custom detections[/]${cdrCorrelated} | [dim]$xdrStreamingCount streaming tables${tierDetail}[/]${notStreamedPart}"
    }

    if ($s.XdrCheckerIssues -gt 0) {
        $overviewLines += "[bold]XDR Checker:[/]      [yellow]$($s.XdrCheckerIssues) advisory issue(s)[/] | [dim]target $($s.XdrAdvisoryRetention)d retention path[/]"
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
            'Table'      = Get-SafeEscapedText $t.TableName
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
        'View Detection Analyzer'       = 'detanalyzer'
        'View SOC Optimization'         = 'soc'
        'View Retention Assessment'     = 'retention'
        'View Data Transforms'          = 'transforms'
        'View Split KQL Suggestions'    = 'splitkql'
        'Evaluate specific table (KQL)' = 'tableKql'
        'View All Tables'               = 'tables'
    }

    $menuItems['Export Report']       = 'export'
    $menuItems['Quit']                = 'quit'

    $continue = $true
    while ($continue) {
        Invoke-ConsoleSizeCheck
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
            'detanalyzer'     { Write-DetectionAnalyzer -Analysis $Analysis }
            'soc'             { Write-SocOptimization -Analysis $Analysis }
            'retention'       { Write-RetentionAssessment -Analysis $Analysis }
            'transforms'      { Write-DataTransforms -Analysis $Analysis }
            'splitkql'        { Write-SplitKqlSuggestions -Analysis $Analysis }
            'tableKql'        { Write-TableKqlSuggestion -Analysis $Analysis }
            'tables'          { Write-AllTables -Analysis $Analysis }
            'export'          {
                Invoke-ExportFromMenu -Analysis $Analysis `
                                      -WorkspaceName $WorkspaceName `
                                      -DefenderXDR $DefenderXDR `
                                      -ExportFormat $ExportFormat `
                                      -ExportPath $ExportPath
            }
            'quit'            { $continue = $false }
        }
    }

    $moduleVersion = (Import-PowerShellDataFile "$PSScriptRoot\..\LogHorizon.psd1").ModuleVersion
    Write-SpectreHost ""
    Write-SpectreHost "[dim]Log Horizon v${moduleVersion} | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC' -AsUTC)[/]"
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

    $initialMax = 10
    $showCount = [math]::Min($initialMax, $sorted.Count)

    $lines = @("[bold]Recommendations[/] [dim](sorted by priority, showing $showCount of $($sorted.Count))[/]", "")

    for ($i = 0; $i -lt $showCount; $i++) {
        $rec = $sorted[$i]

        $prioIcon = switch ($rec.Priority) {
            'High'   { '[red]HIGH[/]' }
            'Medium' { '[yellow]MED[/]' }
            'Low'    { '[deepskyblue1]LOW[/]' }
        }

        $savings = if ($rec.EstSavingsUSD -gt 0) { "  [green]~`$$($rec.EstSavingsUSD)/mo savings[/]" } else { '' }
        $num = ($i + 1).ToString().PadLeft(2)

        $lines += "[bold]$num.[/] $prioIcon  [bold]$(Get-SafeEscapedText $rec.Title)[/]$savings"
        $lines += "      [dim]$(Get-SafeEscapedText $rec.Detail)[/]"
        $lines += ""
    }

    $remaining = $sorted.Count - $initialMax
    if ($remaining -gt 0) {
        $lines += "[dim]... and $remaining more below.[/]"
    }

    $body = $lines -join "`n"
    $body | Format-SpectrePanel -Header "[dodgerblue2] RECOMMENDATIONS [/]" -Border Rounded -Color DodgerBlue2

    # Offer to expand if there are more
    if ($remaining -gt 0) {
        Write-SpectreHost ""
        $pick = Read-SpectreSelection -Title "[deepskyblue1]Show all recommendations?[/]" -Choices @("Show all $($sorted.Count) recommendations", 'Back') -Color DodgerBlue2

        if ($pick -ne 'Back') {
            $allLines = @("[bold]All Recommendations[/] [dim]($($sorted.Count) total)[/]", "")

            for ($i = 0; $i -lt $sorted.Count; $i++) {
                $rec = $sorted[$i]

                $prioIcon = switch ($rec.Priority) {
                    'High'   { '[red]HIGH[/]' }
                    'Medium' { '[yellow]MED[/]' }
                    'Low'    { '[deepskyblue1]LOW[/]' }
                }

                $savings = if ($rec.EstSavingsUSD -gt 0) { "  [green]~`$$($rec.EstSavingsUSD)/mo savings[/]" } else { '' }
                $num = ($i + 1).ToString().PadLeft(2)

                $allLines += "[bold]$num.[/] $prioIcon  [bold]$(Get-SafeEscapedText $rec.Title)[/]$savings"
                $allLines += "      [dim]$(Get-SafeEscapedText $rec.Detail)[/]"
                $allLines += ""
            }

            $allBody = $allLines -join "`n"
            $allBody | Format-SpectrePanel -Header "[dodgerblue2] ALL RECOMMENDATIONS [/]" -Border Rounded -Color DodgerBlue2
        }
    }
}

# Detection assessment
function Write-DetectionAssessment {
    param([PSCustomObject]$Analysis)

    $lines = @()

    # Well covered
    $wellCovered = $Analysis.TableAnalysis |
        Where-Object { $_.Classification -eq 'primary' -and $_.EffectiveCoverage -ge 3 } |
        Group-Object Category

    if ($wellCovered) {
        $lines += "[green][bold]Well Covered[/][/]"
        foreach ($grp in $wellCovered) {
            $tableList = ($grp.Group | ForEach-Object { $_.TableName }) -join ', '
            $totalRules = ($grp.Group | Measure-Object EffectiveCoverage -Sum).Sum
            $lines += "  [green]●[/] $(Get-SafeEscapedText $grp.Name): $(Get-SafeEscapedText $tableList) [dim]($totalRules rules)[/]"
        }
        $lines += ""
    }

    # Gaps (1-2 rules)
    $gaps = $Analysis.TableAnalysis |
        Where-Object { $_.Classification -eq 'primary' -and -not $_.IsFree -and $_.EffectiveCoverage -lt 3 -and $_.EffectiveCoverage -ge 1 }

    if ($gaps) {
        $lines += "[yellow][bold]Gaps Detected[/][/]"
        foreach ($g in $gaps) {
            $lines += "  [yellow]●[/] $(Get-SafeEscapedText $g.TableName) - $($g.MonthlyGB) GB/mo, only $($g.EffectiveCoverage) rule(s)"
        }
        $lines += ""
    }

    # Zero detections
    $noCoverage = $Analysis.TableAnalysis |
        Where-Object { $_.Classification -eq 'primary' -and -not $_.IsFree -and $_.EffectiveCoverage -eq 0 }

    if ($noCoverage) {
        $lines += "[red][bold]Primary Sources With Zero Detections[/][/]"
        foreach ($n in $noCoverage) {
            $lines += "  [red]●[/] $(Get-SafeEscapedText $n.TableName) - $(Get-SafeEscapedText $n.Category)"
        }
        $lines += ""
    }

    # Keyword gaps
    if ($Analysis.KeywordGaps.Count -gt 0) {
        $lines += "[red][bold]Not Ingesting (recommended based on keywords)[/][/]"
        foreach ($kg in $Analysis.KeywordGaps) {
            $lines += "  [red]●[/] $(Get-SafeEscapedText $kg.TableName) - $(Get-SafeEscapedText $kg.Description)"
        }
        $lines += ""
    }

    # Correlation excluded rules
    if ($Analysis.CorrelationExcluded -and $Analysis.CorrelationExcluded.Count -gt 0) {
        $lines += "[yellow][bold]Rules Excluded From Correlation (#DONT_CORR#)[/][/]"
        foreach ($cr in $Analysis.CorrelationExcluded) {
            $tables = if ($cr.Tables) { ($cr.Tables -join ', ') } else { '-' }
            $lines += "  [yellow]●[/] $(Get-SafeEscapedText $cr.RuleName)  [dim]$(Get-SafeEscapedText $cr.Kind) | Tables: $(Get-SafeEscapedText $tables)[/]"
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

    # Split active vs inactive, sort by title within each group
    $active   = $Analysis.SocRecommendations | Where-Object { $_.State -eq 'Active' } | Sort-Object Title
    $inactive = $Analysis.SocRecommendations | Where-Object { $_.State -ne 'Active' } | Sort-Object Title

    # Detect console width to decide whether to show Detail column
    $showDetail = ((Get-ConsoleWidth) -ge 121)

    # Show active recommendations
    if ($active.Count -gt 0) {
        $table = @()
        $num = 0
        foreach ($sr in $active) {
            $num++
            if ($showDetail) {
                $detail = Get-SocRecommendationDetail -Recommendation $sr
                $table += [PSCustomObject]@{
                    '#'      = $num
                    'Title'  = Get-SafeEscapedText $sr.Title
                    'Detail' = Get-SafeEscapedText ($detail.Length -gt 120 ? $detail.Substring(0, 117) + '...' : $detail)
                }
            } else {
                $table += [PSCustomObject]@{
                    '#'      = $num
                    'Title'  = Get-SafeEscapedText $sr.Title
                }
            }
        }
        $table | Format-SpectreTable -Border Rounded -Color DodgerBlue2 -HeaderColor DodgerBlue2
        Write-SpectreHost "[dim]  $($active.Count) active recommendation(s). $($inactive.Count) inactive hidden.[/]"
    }
    else {
        Write-SpectreHost "[green]No active SOC optimization recommendations.[/]"
        Write-SpectreHost "[dim]  $($inactive.Count) inactive recommendation(s) hidden.[/]"
    }

    Write-SpectreHost ""

    # Drill-down menu
    $choices = @('Back', 'Show inactive') + (1..$active.Count | ForEach-Object { "$_" })
    $pick = Read-SpectreSelection -Title "[deepskyblue1]Enter a number for details, Show inactive, or Back:[/]" -Choices $choices

    if ($pick -eq 'Show inactive' -and $inactive.Count -gt 0) {
        Write-SpectreHost ""
        $inactiveTable = @()
        $inum = 0
        foreach ($sr in $inactive) {
            $inum++
            if ($showDetail) {
                $detail = Get-SocRecommendationDetail -Recommendation $sr
                $inactiveTable += [PSCustomObject]@{
                    '#'      = $inum
                    'Title'  = Get-SafeEscapedText $sr.Title
                    'Detail' = Get-SafeEscapedText ($detail.Length -gt 120 ? $detail.Substring(0, 117) + '...' : $detail)
                }
            } else {
                $inactiveTable += [PSCustomObject]@{
                    '#'      = $inum
                    'Title'  = Get-SafeEscapedText $sr.Title
                }
            }
        }
        $inactiveTable | Format-SpectreTable -Border Rounded -Color Grey -HeaderColor Grey
        Write-SpectreHost "[dim]  $($inactive.Count) inactive recommendation(s).[/]"
    }
    elseif ($pick -ne 'Back' -and $pick -ne 'Show inactive') {
        $idx = [int]$pick - 1
        $rec = $active[$idx]
        Write-SocRecommendationDrillDown -Recommendation $rec
    }
}

function Get-SocRecommendationDetail {
    param([PSCustomObject]$Recommendation)

    if ($Recommendation.Description) {
        return $Recommendation.Description
    }
    if ($Recommendation.Suggestions -and $Recommendation.Suggestions.Count -gt 0) {
        $first = $Recommendation.Suggestions | Select-Object -First 1
        if ($first.Title) { return $first.Title }
        if ($first.Action) { return $first.Action }
    }
    ''
}

function Write-SocRecommendationDrillDown {
    param([PSCustomObject]$Recommendation)

    $rec = $Recommendation
    Write-SpectreHost ""
    Write-SpectreHost "[dodgerblue2]$(Get-SafeEscapedText $rec.Title)[/]"
    if ($rec.Description) {
        Write-SpectreHost "[white]$(Get-SafeEscapedText $rec.Description)[/]"
    }
    if ($rec.Suggestions -and $rec.Suggestions.Count -gt 0) {
        Write-SpectreHost ""
        Write-SpectreHost "[deepskyblue1]Suggestions:[/]"
        foreach ($s in $rec.Suggestions) {
            $title = if ($s.Title) { $s.Title } else { $s.TypeId }
            Write-SpectreHost "  [yellow]>[/] [white]$(Get-SafeEscapedText $title)[/]"
            if ($s.Description) {
                Write-SpectreHost "    [dim]$(Get-SafeEscapedText $s.Description)[/]"
            }
            if ($s.Action) {
                Write-SpectreHost "    [green]Action:[/] [white]$(Get-SafeEscapedText $s.Action)[/]"
            }
        }
    }
    if ($rec.AdditionalProperties) {
        Write-SpectreHost ""
        Write-SpectreHost "[deepskyblue1]Additional context:[/]"
        foreach ($key in $rec.AdditionalProperties.PSObject.Properties.Name) {
            Write-SpectreHost "  [dim]${key}:[/] [white]$(Get-SafeEscapedText "$($rec.AdditionalProperties.$key)")[/]"
        }
    }
    Write-SpectreHost ""
}

# Data transforms
function Write-DataTransforms {
    param([PSCustomObject]$Analysis)

    $transforms = $Analysis.DataTransforms
    $tablesWithTransforms = @($Analysis.TableAnalysis | Where-Object { $_.HasTransform })
    $splitTables = @($Analysis.TableAnalysis | Where-Object { $_.IsSplitTable })

    if ((-not $transforms -or $transforms.Transforms.Count -eq 0) -and $splitTables.Count -eq 0) {
        Write-SpectreHost "[dim]No ingest-time transforms or split tables detected.[/]"
        return
    }

    # Overview panel
    $lines = @()
    $lines += "[bold]DCRs with transforms:[/]  $($transforms.RelevantDCRs.Count) of $($transforms.TotalDCRs) total"
    $lines += "[bold]Tables with transforms:[/] $($tablesWithTransforms.Count)"
    $lines += "[bold]Split tables (_SPLT_CL):[/]  $($splitTables.Count)"

    # Type breakdown
    if ($transforms.Transforms.Count -gt 0) {
        $typeGroups = $transforms.Transforms | Group-Object TransformType | Sort-Object Count -Descending
        $typeSummary = ($typeGroups | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ', '
        $lines += "[bold]Transform types:[/]      $typeSummary"
    }
    $lines += ""

    $body = $lines -join "`n"
    $body | Format-SpectrePanel -Header "[dodgerblue2] DATA TRANSFORMS [/]" -Border Rounded -Color DodgerBlue2
    Write-SpectreHost ""

    # Split tables section
    if ($splitTables.Count -gt 0) {
        $splitRows = @()
        foreach ($t in $splitTables) {
            $parentEntry = $Analysis.TableAnalysis | Where-Object { $_.TableName -eq $t.ParentTable } | Select-Object -First 1
            $parentGBStr = if ($parentEntry) { "$($parentEntry.MonthlyGB)" } else { '-' }

            $splitRows += [PSCustomObject]@{
                'Split Table'  = Get-SafeEscapedText $t.TableName
                'Parent'       = Get-SafeEscapedText $t.ParentTable
                'Split GB/mo'  = $t.MonthlyGB
                'Parent GB/mo' = $parentGBStr
                'Plan'         = if ($t.TablePlan) { $t.TablePlan } else { 'Data Lake' }
            }
        }

        $splitRows | Format-SpectreTable -Border Rounded -Color Yellow -HeaderColor Yellow
        Write-SpectreHost ""
    }

    # Transform detail table
    if ($transforms.Transforms.Count -gt 0) {
        $table = @()
        foreach ($t in $transforms.Transforms) {
            $kqlPreview = $t.TransformKql
            if ($kqlPreview.Length -gt 80) {
                $kqlPreview = $kqlPreview.Substring(0, 77) + '...'
            }

            $typeMarkup = switch ($t.TransformType) {
                'Filter'        { '[red]Filter[/]' }
                'ColumnRemoval' { '[yellow]ColumnRemoval[/]' }
                'Projection'    { '[yellow]Projection[/]' }
                'Enrichment'    { '[green]Enrichment[/]' }
                'Aggregation'   { '[deepskyblue1]Aggregation[/]' }
                default         { '[grey]Custom[/]' }
            }

            $table += [PSCustomObject]@{
                'Table'     = Get-SafeEscapedText $t.OutputTable
                'Type'      = $typeMarkup
                'DCR'       = Get-SafeEscapedText ($t.DCRName.Length -gt 30 ? $t.DCRName.Substring(0, 27) + '...' : $t.DCRName)
                'Transform' = Get-SafeEscapedText $kqlPreview
            }
        }

        $table | Format-SpectreTable -Border Rounded -Color DodgerBlue2 -HeaderColor DodgerBlue2 -AllowMarkup
    }

    Write-SpectreHost ""

    # Drill-down submenu
    if ($transforms.Transforms.Count -gt 0) {
        $choices = @('Back') + @($transforms.Transforms | ForEach-Object { $_.OutputTable } | Select-Object -Unique | Sort-Object)
        $pick = Read-SpectreSelection -Title "[deepskyblue1]Select a table for full KQL, or Back:[/]" -Choices $choices -Color DodgerBlue2

        if ($pick -ne 'Back') {
            $tableTransforms = @($transforms.Transforms | Where-Object { $_.OutputTable -eq $pick })
            foreach ($tt in $tableTransforms) {
                Write-SpectreHost ""
                Write-SpectreHost "[dodgerblue2][bold]$($tt.OutputTable)[/] — $($tt.TransformType) via $(Get-SafeEscapedText $tt.DCRName)[/]"
                Write-SpectreHost ""
                Write-SpectreHost "[deepskyblue1]KQL:[/]"
                Write-SpectreHost "[dim]$(Get-SafeEscapedText $tt.TransformKql)[/]"
            }
        }
    }
}

# Split KQL suggestions
function Write-SplitKqlSuggestions {
    param([PSCustomObject]$Analysis)

    $splitRecs = @($Analysis.Recommendations | Where-Object { $_.Type -eq 'SplitCandidate' -and $_.SplitSuggestion })

    if ($splitRecs.Count -eq 0) {
        Write-SpectreHost "[dim]No split KQL suggestions available. Tables must be high-volume primary sources with detections and no existing transforms.[/]"
        return
    }

    # Overview
    $lines = @()
    $lines += "[bold]Split candidates:[/] $($splitRecs.Count) table(s)"
    $withKql = @($splitRecs | Where-Object { $_.SplitSuggestion.SplitKql })
    $lines += "[bold]With split KQL:[/]  $($withKql.Count) table(s) have a generated split suggestion"
    $lines += ""
    $body = $lines -join "`n"
    $body | Format-SpectrePanel -Header "[dodgerblue2] SPLIT KQL SUGGESTIONS [/]" -Border Rounded -Color DodgerBlue2
    Write-SpectreHost ""

    # Summary table
    $table = @()
    foreach ($rec in $splitRecs) {
        $s = $rec.SplitSuggestion
        $sourceMarkup = switch ($s.Source) {
            'knowledge-base' { '[green]Knowledge Base[/]' }
            'rule-analysis'  { '[deepskyblue1]Rule Analysis[/]' }
            'combined'       { '[green]Combined[/]' }
            default          { '[grey]None[/]' }
        }

        $table += [PSCustomObject]@{
            'Table'       = Get-SafeEscapedText $rec.TableName
            'GB/mo'       = ($Analysis.TableAnalysis | Where-Object TableName -eq $rec.TableName).MonthlyGB
            'Rules'       = $s.RuleCount
            'Fields'      = "$($s.RuleFields.Count) rule + $($s.HighValueFields.Count) KB"
            'Source'      = $sourceMarkup
            'Est Savings' = "`$$($rec.EstSavingsUSD)/mo"
        }
    }

    $table | Format-SpectreTable -Border Rounded -Color DodgerBlue2 -HeaderColor DodgerBlue2 -AllowMarkup
    Write-SpectreHost ""

    # Drill-down
    $choices = @('Back') + @($splitRecs | ForEach-Object { $_.TableName })
    $pick = Read-SpectreSelection -Title "[deepskyblue1]Select a table for full KQL suggestion, or Back:[/]" -Choices $choices -Color DodgerBlue2

    if ($pick -ne 'Back') {
        $rec = $splitRecs | Where-Object { $_.TableName -eq $pick } | Select-Object -First 1
        $s = $rec.SplitSuggestion

        Write-SpectreHost ""
        Write-SpectreHost "[dodgerblue2][bold]$($rec.TableName)[/] — Split KQL Suggestion[/]"

        if ($s.Description) {
            Write-SpectreHost "[dim]$(Get-SafeEscapedText $s.Description)[/]"
        }
        Write-SpectreHost ""

        # Show split KQL
        if ($s.SplitKql) {
            Write-SpectreHost "[bold]Split Transform KQL[/] [dim](condition-only — the portal prepends 'source | where' automatically)[/]"
            Write-SpectreHost "[deepskyblue1]$(Get-SafeEscapedText $s.SplitKql)[/]"
            Write-SpectreHost ""
        }

        # Show projection KQL
        if ($s.ProjectKql) {
            Write-SpectreHost "[bold]Column Reduction KQL[/] [dim](keeps only detection-relevant fields)[/]"
            Write-SpectreHost "[deepskyblue1]$(Get-SafeEscapedText $s.ProjectKql)[/]"
            Write-SpectreHost ""
        }

        # Show field analysis
        if ($s.RuleFields.Count -gt 0) {
            $ruleFieldStr = ($s.RuleFields | Select-Object -First 20) -join ', '
            Write-SpectreHost "[bold]Fields from analytics rules ($($s.RuleFields.Count)):[/]"
            Write-SpectreHost "  [white]$(Get-SafeEscapedText $ruleFieldStr)[/]"
            Write-SpectreHost ""
        }

        if ($s.HighValueFields.Count -gt 0) {
            $hvFieldStr = ($s.HighValueFields | Select-Object -First 20) -join ', '
            Write-SpectreHost "[bold]Fields from knowledge base ($($s.HighValueFields.Count)):[/]"
            Write-SpectreHost "  [white]$(Get-SafeEscapedText $hvFieldStr)[/]"
            Write-SpectreHost ""
        }

        Write-SpectreHost "[dim]Source: $($s.Source) | $($s.RuleCount) rule(s) | $($s.ConditionCount) condition(s) extracted[/]"
    }
}

# Generate KQL for specific table
function Write-TableKqlSuggestion {
    param([PSCustomObject]$Analysis)

    $allTables = @($Analysis.TableAnalysis | Sort-Object TableName)
    if ($allTables.Count -eq 0) { return }

    $choices = @('Back') + @($allTables | ForEach-Object { $_.TableName })
    $pick = Read-SpectreSelection -Title "Type to search or select a table to evaluate KQL suggestions:" `
                                  -Choices $choices `
                                  -Color DodgerBlue2 `
                                  -EnableSearch

    if ($pick -ne 'Back') {
        $table = $allTables | Where-Object { $_.TableName -eq $pick } | Select-Object -First 1
        $s = $table.SplitSuggestion

        Write-SpectreHost ""
        Write-SpectreHost "[dodgerblue2][bold]$($table.TableName)[/] — Target Field and KQL Evaluation[/]"

        if (-not $s -or $s.Source -eq 'none') {
            Write-SpectreHost "[dim]No KQL suggestions could be automatically generated for this table (no knowledge-base hits or mapped analytics rules).[/]"
            return
        }

        if ($s.Description) {
            Write-SpectreHost "[dim]$(Get-SafeEscapedText $s.Description)[/]"
        }
        Write-SpectreHost ""

        # Show split KQL
        if ($s.SplitKql) {
            Write-SpectreHost "[bold]Split Transform KQL[/] [dim](condition-only — the portal prepends 'source | where' automatically)[/]"
            Write-SpectreHost "[deepskyblue1]$(Get-SafeEscapedText $s.SplitKql)[/]"
            Write-SpectreHost ""
        }

        # Show projection KQL
        if ($s.ProjectKql) {
            Write-SpectreHost "[bold]Column Reduction KQL[/] [dim](keeps only detection-relevant fields)[/]"
            Write-SpectreHost "[deepskyblue1]$(Get-SafeEscapedText $s.ProjectKql)[/]"
            Write-SpectreHost ""
        }

        # Show field analysis
        if ($s.RuleFields.Count -gt 0) {
            $ruleFieldStr = ($s.RuleFields | Sort-Object) -join ', '
            Write-SpectreHost "[bold]Fields from analytics rules ($($s.RuleFields.Count)):[/]"
            Write-SpectreHost "  [white]$(Get-SafeEscapedText $ruleFieldStr)[/]"
            Write-SpectreHost ""
        }

        if ($s.HighValueFields.Count -gt 0) {
            $hvFieldStr = ($s.HighValueFields | Sort-Object) -join ', '
            Write-SpectreHost "[bold]Fields from knowledge base ($($s.HighValueFields.Count)):[/]"
            Write-SpectreHost "  [white]$(Get-SafeEscapedText $hvFieldStr)[/]"
            Write-SpectreHost ""
        }

        Write-SpectreHost "[dim]Source: $($s.Source) | $($s.RuleCount) mapped rule(s) | $($s.ConditionCount) condition(s) extracted[/]"
    }
}

# All tables
function Write-AllTables {
    param([PSCustomObject]$Analysis)

    $width = Get-ConsoleWidth
    $showRetention = ($width -ge 140)
    $showHunting   = ($width -ge 120)

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

        # Retention column: green >= recommended, yellow >= 90 but below recommended, red < 90
        $retStr = if ($null -eq $t.ActualRetentionDays) {
            '[grey]-[/]'
        } elseif ($t.RetentionCompliant -eq $false) {
            "[red]$($t.ActualRetentionDays)d[/]"
        } elseif ($t.RetentionCanImprove) {
            "[yellow]$($t.ActualRetentionDays)d[/]"
        } elseif ($t.RetentionCompliant) {
            "[green]$($t.ActualRetentionDays)d[/]"
        } else {
            "[grey]$($t.ActualRetentionDays)d[/]"
        }
        if ($t.TablePlan -and $t.TablePlan -ne 'Analytics') {
            $retStr += " [dim]($($t.TablePlan))[/]"
        }

        $row = [ordered]@{
            '#'          = $rank
            'Table'      = Get-SafeEscapedText $t.TableName
            'GB/mo'      = $t.MonthlyGB
            'Cost/mo'    = $costStr
            'Class'      = $clsMarkup
            'Rules'      = $t.AnalyticsRules
        }
        if ($showHunting)   { $row['Hunting']   = $t.HuntingQueries }
        if ($showRetention) { $row['Retention'] = $retStr }
        $row['Assessment'] = $assessMarkup

        $table += [PSCustomObject]$row
    }

    $table | Format-SpectreTable -Border Rounded -Color DodgerBlue2 -HeaderColor DodgerBlue2 -AllowMarkup
    Write-SpectreHost "[dim]  $($sorted.Count) total tables.[/]"
}

# Retention assessment
function Write-RetentionAssessment {
    param([PSCustomObject]$Analysis)

    $s = $Analysis.Summary
    if ($s.RetentionChecked -eq 0) {
        Write-SpectreHost "[dim]No retention data available. Tables API may not have returned results.[/]"
        return
    }

    # Tables with category recommendation above 90d (regardless of current retention)
    $extendedRecTables = @($Analysis.TableAnalysis |
        Where-Object { $_.RecommendedRetentionDays -gt 90 -and $null -ne $_.RetentionCompliant })

    # XDR streaming tables not already covered by the extended list (advisory: 365d)
    $extendedNames = @($extendedRecTables | ForEach-Object { $_.TableName })
    $xdrAdvisoryTables = @($Analysis.TableAnalysis | Where-Object {
        $_.IsXDRStreaming -and
        $_.TableName -notin $extendedNames -and
        $null -ne $_.ActualRetentionDays -and
        $_.ActualRetentionDays -lt 365
    })

    # XDR streaming tables with no data lake forwarding at all (skip Auxiliary — already in data lake)
    $xdrNoDataLake = @($Analysis.TableAnalysis | Where-Object {
        $_.IsXDRStreaming -and
        $_.XDRState -ne 'Auxiliary' -and
        $null -ne $_.ArchiveRetentionInDays -and
        $_.ArchiveRetentionInDays -eq 0
    })

    # Known XDR tables not ingested into the workspace at all
    $xdrNotStreamed = @()
    if ($Analysis.XdrChecker -and $Analysis.XdrChecker.Findings) {
        $xdrNotStreamed = @($Analysis.XdrChecker.Findings | Where-Object Type -eq 'NotStreaming')
    }

    $totalExtended = $extendedRecTables.Count + $xdrAdvisoryTables.Count + $xdrNotStreamed.Count

    # Overview panel
    $lines = @()
    if ($s.WorkspaceRetentionDays -gt 0) {
        $wsColor = if ($s.WorkspaceRetentionDays -ge 90) { 'green' } else { 'red' }
        $lines += "[bold]Workspace Default:[/] [${wsColor}]$($s.WorkspaceRetentionDays)d[/]$(if ($s.WorkspaceRetentionDays -lt 90) { ' [yellow](increase to 90d)[/]' })"
    }
    $lines += "[bold]Baseline (>=90d):[/]  [green]$($s.RetentionCompliant)[/] of $($s.RetentionChecked) Analytics tables"
    if ($s.RetentionNonCompliant -gt 0) {
        $lines += "[bold]Below Baseline:[/]   [red]$($s.RetentionNonCompliant)[/] table(s) below 90d"
    }
    if ($totalExtended -gt 0) {
        $lines += "[bold]Extended (>90d):[/]  [deepskyblue1]$totalExtended[/] table(s) recommended for extended retention"
        if ($xdrAdvisoryTables.Count -gt 0) {
            $lines += "                    [dim]includes $($xdrAdvisoryTables.Count) XDR streaming table(s) — advisory target: 365d[/]"
        }
        if ($xdrNotStreamed.Count -gt 0) {
            $lines += "                    [dim]includes $($xdrNotStreamed.Count) XDR table(s) not yet streamed to Sentinel[/]"
        }
    }
    if ($xdrNoDataLake.Count -gt 0) {
        $lines += "[bold]No Data Lake:[/]    [yellow]$($xdrNoDataLake.Count)[/] XDR streaming table(s) not forwarded to Data Lake tier"
    }
    $lines += ""

    $body = $lines -join "`n"
    $body | Format-SpectrePanel -Header "[dodgerblue2] RETENTION OVERVIEW [/]" -Border Rounded -Color DodgerBlue2
    Write-SpectreHost ""

    # Non-compliant tables (below 90d)
    $nonCompliant = $Analysis.TableAnalysis |
        Where-Object { $_.RetentionCompliant -eq $false } |
        Sort-Object ActualRetentionDays

    if ($nonCompliant.Count -gt 0) {
        $table = @()
        foreach ($t in $nonCompliant) {
            $shortfall = 90 - $t.ActualRetentionDays
            $planStr = if ($t.TablePlan) { $t.TablePlan } else { '-' }

            $table += [PSCustomObject]@{
                'Table'     = Get-SafeEscapedText $t.TableName
                'Plan'      = $planStr
                'Current'   = "$($t.ActualRetentionDays)d"
                'Baseline'  = '90d'
                'Shortfall' = "[red]+${shortfall}d needed[/]"
            }
        }

        $table | Format-SpectreTable -Border Rounded -Color Red -HeaderColor Red -AllowMarkup
        Write-SpectreHost ""
    } else {
        Write-SpectreHost "[green]All Analytics tables meet the 90-day baseline.[/]"
        Write-SpectreHost ""
    }

    Write-SpectreHost "[dim]  Baseline: 90 days. Extended recommendations based on a combined set of industry standards, regulatory baselines, and security best practices.[/]"
    Write-SpectreHost ""

    # Submenu
    $choices = @('Back')
    if ($totalExtended -gt 0) {
        $choices = @("Show extended retention recommendations ($totalExtended tables)", 'Back')
    }

    $pick = Read-SpectreSelection -Title "[deepskyblue1]Select an option:[/]" -Choices $choices -Color DodgerBlue2

    if ($pick -ne 'Back') {
        Write-SpectreHost ""

        $impTable = @()

        foreach ($t in ($extendedRecTables | Sort-Object RecommendedRetentionDays -Descending)) {
            $currentStr = if ($null -ne $t.ActualRetentionDays) { "$($t.ActualRetentionDays)d" } else { '-' }
            $statusMarkup = if ($null -ne $t.ActualRetentionDays -and $t.ActualRetentionDays -ge $t.RecommendedRetentionDays) {
                '[green]Met[/]'
            } elseif ($t.RetentionCompliant) {
                '[yellow]Baseline only[/]'
            } else {
                '[red]Below baseline[/]'
            }

            $tableLabel = if ($t.IsXDRStreaming) { "$(Get-SafeEscapedText $t.TableName) [dim](XDR)[/]" } else { Get-SafeEscapedText $t.TableName }
            $impTable += [PSCustomObject]@{
                'Table'       = $tableLabel
                'Category'    = Get-SafeEscapedText $t.Category
                'Current'     = $currentStr
                'Recommended' = "[deepskyblue1]$($t.RecommendedRetentionDays)d[/]"
                'Status'      = $statusMarkup
            }
        }

        # XDR advisory tables appended at the end
        foreach ($t in ($xdrAdvisoryTables | Sort-Object ActualRetentionDays)) {
            $currentStr = if ($null -ne $t.ActualRetentionDays) { "$($t.ActualRetentionDays)d" } else { '-' }
            $impTable += [PSCustomObject]@{
                'Table'       = "$(Get-SafeEscapedText $t.TableName) [dim](XDR)[/]"
                'Category'    = Get-SafeEscapedText $t.Category
                'Current'     = $currentStr
                'Recommended' = '[yellow]365d[/]'
                'Status'      = '[yellow]XDR advisory[/]'
            }
        }

        # XDR tables not streamed to Sentinel at all
        foreach ($f in ($xdrNotStreamed | Sort-Object TableName)) {
            $impTable += [PSCustomObject]@{
                'Table'       = "$(Get-SafeEscapedText $f.TableName) [dim](XDR)[/]"
                'Category'    = 'Defender XDR'
                'Current'     = '[dim]XDR only (30d)[/]'
                'Recommended' = '[yellow]365d[/]'
                'Status'      = '[dim]Not streaming[/]'
            }
        }

        $impTable | Format-SpectreTable -Border Rounded -Color DodgerBlue2 -HeaderColor DodgerBlue2 -AllowMarkup

        Write-SpectreHost ""
        Write-SpectreHost "[deepskyblue1][bold]Tip:[/] Use the Data Lake (Auxiliary) tier for retention beyond 90 days.[/]"
        Write-SpectreHost "[dim]  Keep 90 days in the Analytics tier for active hunting and detections,[/]"
        Write-SpectreHost "[dim]  then archive to the Data Lake tier for long-term compliance retention.[/]"
        Write-SpectreHost "[dim]  Data Lake storage costs ~95% less than Analytics tier ingestion.[/]"
        if ($xdrAdvisoryTables.Count -gt 0) {
            Write-SpectreHost "[dim]  XDR streaming tables: advisory target is 365 days for long-term investigation capability.[/]"
        }
        if ($xdrNotStreamed.Count -gt 0) {
            Write-SpectreHost "[dim]  XDR tables not yet streamed can be ingested into Analytics or directly to Data Lake tier.[/]"
        }
    }
}

function Write-DetectionAnalyzer {
    param([PSCustomObject]$Analysis)

    if (-not $Analysis.DetectionAnalyzer -or $Analysis.DetectionAnalyzer.RuleMetrics.Count -eq 0) {
        Write-SpectreHost "[dim]Detection Analyzer data not available. Re-run with -IncludeDetectionAnalyzer.[/]"
        return
    }

    # Scored rules sorted by noisiness, then unscored (CDRs without incidents) at the end
    $scored = @($Analysis.DetectionAnalyzer.RuleMetrics | Where-Object { $null -ne $_.NoisinessScore } | Sort-Object NoisinessScore -Descending)
    $unscored = @($Analysis.DetectionAnalyzer.RuleMetrics | Where-Object { $null -eq $_.NoisinessScore })
    $metrics = @($scored) + @($unscored)
    $displayMetrics = @($metrics | Select-Object -First 15)

    $table = @()
    foreach ($r in $displayMetrics) {
        $scoreMarkup = if ($null -eq $r.NoisinessScore) {
            "[dim]N/A[/]"
        } elseif ($r.NoisinessScore -ge 70) {
            "[red]$($r.NoisinessScore)[/]"
        } elseif ($r.NoisinessScore -ge 50) {
            "[yellow]$($r.NoisinessScore)[/]"
        } else {
            "[green]$($r.NoisinessScore)[/]"
        }

        $kindMarkup = switch ($r.RuleKind) {
            'CustomDetection' { '[deepskyblue1]CDR[/]' }
            'NRT'             { '[yellow]NRT[/]' }
            default           { $r.RuleKind }
        }

        $table += [PSCustomObject]@{
            'Rule'        = Get-SafeEscapedText $r.RuleName
            'Kind'        = $kindMarkup
            'Incidents'   = $r.IncidentsTotal
            'AutoClose%'  = [math]::Round(($r.AutoCloseRatio * 100), 1)
            'FalsePos%'   = [math]::Round(($r.FalsePositiveRatio * 100), 1)
            'Score'       = $scoreMarkup
        }
    }

    $table | Format-SpectreTable -Border Rounded -Color DodgerBlue2 -HeaderColor DodgerBlue2 -AllowMarkup
    Write-SpectreHost "[dim]  Showing top $($displayMetrics.Count) of $($metrics.Count) rules by noisiness score.[/]"

    $cdrSummary = $Analysis.DetectionAnalyzer.Summary
    if ($cdrSummary.CustomDetectionRules -gt 0) {
        Write-SpectreHost "[dim]  Includes $($cdrSummary.CustomDetectionRules) Defender XDR custom detection rule(s), $($cdrSummary.CDRCorrelatedIncidents) with correlated incidents.[/]"
    }
    Write-SpectreHost ""

    # Scoring formula explanation
    $formulaLines = @(
        "[bold]How is the Noisiness Score calculated?[/]"
        ""
        "  Score = (Volume_percentile [dim]x[/] [deepskyblue1]35%[/]) + (AutoClose_percentile [dim]x[/] [deepskyblue1]40%[/]) + (FalsePos_percentile [dim]x[/] [deepskyblue1]25%[/])"
        ""
        "  Each percentile ranks a rule relative to all analyzed rules (0-100)."
        "  [red]>= 70[/] = noisy   [yellow]>= 50[/] = watch   [green]< 50[/] = healthy"
        "  [dim]N/A[/] = no correlated incidents found (listing only)"
    )
    ($formulaLines -join "`n") | Format-SpectrePanel -Header "[dodgerblue2] SCORING FORMULA [/]" -Border Rounded -Color DodgerBlue2
    Write-SpectreHost ""

    # Submenu loop: Back / Show all / Browse details
    $submenuContinue = $true
    while ($submenuContinue) {
        $choices = @('Back')
        if ($metrics.Count -gt 15) {
            $choices += "Show all $($metrics.Count) rules"
        }
        $choices += 'Browse rule details'

        $pick = Read-SpectreSelection -Title "[deepskyblue1]Select an option:[/]" `
                                      -Choices $choices `
                                      -Color DodgerBlue2

        switch ($pick) {
            'Back' { $submenuContinue = $false }

            { $_ -like 'Show all *' } {
                Write-SpectreHost ""
                $fullTable = @()
                foreach ($r in $metrics) {
                    $scoreMarkup = if ($null -eq $r.NoisinessScore) {
                        "[dim]N/A[/]"
                    } elseif ($r.NoisinessScore -ge 70) {
                        "[red]$($r.NoisinessScore)[/]"
                    } elseif ($r.NoisinessScore -ge 50) {
                        "[yellow]$($r.NoisinessScore)[/]"
                    } else {
                        "[green]$($r.NoisinessScore)[/]"
                    }

                    $kindMarkup = switch ($r.RuleKind) {
                        'CustomDetection' { '[deepskyblue1]CDR[/]' }
                        'NRT'             { '[yellow]NRT[/]' }
                        default           { $r.RuleKind }
                    }

                    $fullTable += [PSCustomObject]@{
                        'Rule'        = Get-SafeEscapedText $r.RuleName
                        'Kind'        = $kindMarkup
                        'Incidents'   = $r.IncidentsTotal
                        'AutoClose%'  = [math]::Round(($r.AutoCloseRatio * 100), 1)
                        'FalsePos%'   = [math]::Round(($r.FalsePositiveRatio * 100), 1)
                        'Score'       = $scoreMarkup
                    }
                }
                $fullTable | Format-SpectreTable -Border Rounded -Color DodgerBlue2 -HeaderColor DodgerBlue2 -AllowMarkup
                Write-SpectreHost ""
            }

            'Browse rule details' {
                $browseContinue = $true
                while ($browseContinue) {
                    $ruleChoiceMap = @{}
                    foreach ($r in $metrics) {
                        $display = Get-SafeEscapedText $r.RuleName
                        $ruleChoiceMap[$display] = $r.RuleName
                    }

                    $ruleChoices = @('Back') + @($ruleChoiceMap.Keys)
                    $rulePick = Read-SpectreSelection -Title "[deepskyblue1]Select a rule for details:[/]" `
                                                      -Choices $ruleChoices `
                                                      -Color DodgerBlue2

                    if ($rulePick -eq 'Back') {
                        $browseContinue = $false
                    } else {
                        $selectedRuleName = $ruleChoiceMap[$rulePick]
                        $selected = $metrics | Where-Object { $_.RuleName -eq $selectedRuleName } | Select-Object -First 1
                        if ($selected) {
                            Write-DetectionAnalyzerRuleDetail -RuleMetric $selected
                        }
                    }
                }
            }
        }
    }
}

function Write-DetectionAnalyzerRuleDetail {
    param([PSCustomObject]$RuleMetric)

    $selected = $RuleMetric
    Write-SpectreHost ""

    $kindLabel = if ($selected.RuleKind -eq 'CustomDetection') { 'Custom Detection (CDR)' } else { $selected.RuleKind }
    $sourceLabel = if ($selected.Source) { $selected.Source } else { 'Sentinel' }

    $detailLines = @(
        "[bold]$(Get-SafeEscapedText $selected.RuleName)[/]  [dim]($kindLabel | $sourceLabel)[/]"
        ""
    )

    # CDR-specific properties
    if ($selected.RuleKind -eq 'CustomDetection') {
        $enabledStr = if ($selected.Enabled) { '[green]Enabled[/]' } else { '[red]Disabled[/]' }
        $detailLines += "[bold]Status:[/]           $enabledStr"
        if ($selected.Frequency) {
            $detailLines += "[bold]Frequency:[/]        $($selected.Frequency)"
        }
        if ($selected.Tables -and $selected.Tables.Count -gt 0) {
            $detailLines += "[bold]Tables Queried:[/]   $(($selected.Tables | ForEach-Object { Get-SafeEscapedText $_ }) -join ', ')"
        }
        $detailLines += ""
    }

    if ($selected.IncidentsTotal -gt 0) {
        $detailLines += "[bold]Incidents:[/]        $($selected.IncidentsTotal) total  |  $($selected.IncidentsClosed) closed  |  $($selected.IncidentsAutoClosed) auto-closed"
        $detailLines += "[bold]True Positive:[/]    $($selected.TruePositiveClosed)  |  [bold]False Positive:[/] $($selected.FalsePositiveClosed)  |  [bold]Benign:[/] $($selected.BenignPositiveClosed)"
        $detailLines += "[bold]Auto-Close Ratio:[/] $([math]::Round($selected.AutoCloseRatio * 100, 1))%  |  [bold]False Pos Ratio:[/] $([math]::Round($selected.FalsePositiveRatio * 100, 1))%"
        if ($null -ne $selected.AvgCloseMinutes) {
            $detailLines += "[bold]Avg Close Time:[/]   $($selected.AvgCloseMinutes) minutes"
        }
        $detailLines += ""
        if ($null -ne $selected.NoisinessScore) {
            $scoreColor = if ($selected.NoisinessScore -ge 70) { 'red' } elseif ($selected.NoisinessScore -ge 50) { 'yellow' } else { 'green' }
            $detailLines += "[bold]Noisiness Score:[/]  [${scoreColor}]$($selected.NoisinessScore)[/]"
            $detailLines += "[dim]  Volume %ile: $($selected.PercentileVolume)  |  AutoClose %ile: $($selected.PercentileAutoClose)  |  FalsePos %ile: $($selected.PercentileFalsePositive)[/]"
        }
    } else {
        $detailLines += "[dim]No correlated incidents found. Noisiness score not available.[/]"
    }

    if ($selected.LinkedAutomationRules -and $selected.LinkedAutomationRules.Count -gt 0) {
        $detailLines += ""
        $detailLines += "[bold]Auto-close automation:[/] $(Get-SafeEscapedText ($selected.LinkedAutomationRules -join ', '))"
    }
    ($detailLines -join "`n") | Format-SpectrePanel -Header "[dodgerblue2] RULE DETAIL [/]" -Border Rounded -Color DodgerBlue2
}

function Write-XDRChecker {
    param([PSCustomObject]$Analysis)

    if (-not $Analysis.XdrChecker) {
        Write-SpectreHost "[dim]XDR Checker data is not available.[/]"
        return
    }

    $findings = @($Analysis.XdrChecker.Findings)
    $streamedTableCount = 0
    if ($Analysis.XdrChecker.Summary -and $null -ne $Analysis.XdrChecker.Summary.StreamedTableCount) {
        $streamedTableCount = [int]$Analysis.XdrChecker.Summary.StreamedTableCount
    }

    if ($streamedTableCount -eq 0) {
        Write-SpectreHost "[yellow]No Defender XDR tables appear to be streamed into this Sentinel workspace.[/]"
        Write-SpectreHost "[dim]XDR checker cannot validate forwarding/retention posture until XDR table forwarding is configured.[/]"
        return
    }

    if ($findings.Count -eq 0) {
        Write-SpectreHost "[green]No XDR checker findings for the currently streamed XDR tables.[/]"
        Write-SpectreHost "[dim]Streamed XDR tables detected: $streamedTableCount[/]"
        return
    }

    $table = @()
    foreach ($f in $findings) {
        $severity = switch ($f.Severity) {
            'Medium'      { '[yellow]Medium[/]' }
            'High'        { '[red]High[/]' }
            'Information' { '[dim]Info[/]' }
            default       { '[deepskyblue1]Low[/]' }
        }

        $table += [PSCustomObject]@{
            'Table'    = Get-SafeEscapedText $f.TableName
            'Type'     = Get-SafeEscapedText $f.Type
            'Severity' = $severity
            'Detail'   = Get-SafeEscapedText $f.Detail
        }
    }

    $table | Format-SpectreTable -Border Rounded -Color DodgerBlue2 -HeaderColor DodgerBlue2 -AllowMarkup
    $notStreamedCount = if ($Analysis.XdrChecker.Summary.NotStreamedCount) { [int]$Analysis.XdrChecker.Summary.NotStreamedCount } else { 0 }
    Write-SpectreHost "[dim]  Streamed XDR tables: $streamedTableCount | Not streamed: $notStreamedCount[/]"
    Write-SpectreHost "[dim]  Advisory retention target: $($Analysis.XdrChecker.Summary.AdvisoryRetentionDays) days in Data Lake for XDR-related logs.[/]"
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
                          -Choices @('JSON', 'Markdown', 'HTML', 'Cancel') `
                          -Color DodgerBlue2

        if ($formatChoice -eq 'Cancel') { return }
        $ExportFormat = $formatChoice.ToLower()
    }

    if (-not $ExportPath) {
        $ExportPath = $PWD.Path
    }

    Export-Report -Analysis $Analysis `
                  -Format $ExportFormat `
                  -OutputPath $ExportPath `
                  -WorkspaceName $WorkspaceName `
                  -DefenderXDR $DefenderXDR

    Write-SpectreHost "[green]Report exported to [bold]$(Get-SafeEscapedText $ExportPath)[/][/]"
}
