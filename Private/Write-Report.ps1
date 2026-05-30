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
        [string]$ExportPath,
        [PSCustomObject]$Context
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
                          -ExportFormat $ExportFormat -ExportPath $ExportPath `
                          -Context $Context
}

function Get-ConsoleWidth {
    [CmdletBinding()]
    param()
    try { $Host.UI.RawUI.WindowSize.Width } catch { Write-Verbose 'Unable to determine console width. Falling back to 120.'; 120 }
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
    try { $current = $Host.UI.RawUI.WindowSize } catch { Write-Verbose 'Unable to determine current console size.' }

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

function Get-TablePlanDisplay {
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSCustomObject]$Table)

    $configuredPlan = if (-not [string]::IsNullOrWhiteSpace($Table.TablePlan)) {
        Get-SafeEscapedText $Table.TablePlan
    } else {
        $null
    }

    $observedPlans = if ($Table.ObservedKnownPlans) {
        @($Table.ObservedKnownPlans)
    } elseif ($Table.ObservedPlans) {
        @($Table.ObservedPlans | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -ne 'Unknown' })
    } else {
        @()
    }

    $observedPlans = @($observedPlans | Sort-Object -Unique)
    if ($observedPlans.Count -eq 0) {
        return $(if ($configuredPlan) { $configuredPlan } else { '[grey]-[/]' })
    }

    if ($configuredPlan -and $observedPlans.Count -eq 1 -and $observedPlans[0] -eq $Table.TablePlan) {
        return $configuredPlan
    }

    $observedDisplay = ($observedPlans | ForEach-Object { Get-SafeEscapedText $_ }) -join ', '
    if ($configuredPlan) {
        return "$configuredPlan [dim](obs: $observedDisplay)[/]"
    }

    return "[dim]Observed:[/] $observedDisplay"
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

    $summary = $Analysis.Summary

    # Overview panel
    $filled = [math]::Floor($summary.CoveragePercent / 10)
    $empty  = 10 - $filled
    $coverageColor = if ($summary.CoveragePercent -ge 60) { 'green' } elseif ($summary.CoveragePercent -ge 30) { 'yellow' } else { 'red' }
    $bar = "[${coverageColor}]$('█' * $filled)[/][grey]$('░' * $empty)[/] $($summary.CoveragePercent)%"

    $overviewLines = @(
        "[bold]Workspace:[/]        [deepskyblue1]$(Get-SafeEscapedText $WorkspaceName)[/]"
        "[bold]Scanned:[/]          $(Get-Date -Format 'yyyy-MM-dd')"
        ""
        "[bold]Tables:[/]           $($summary.TotalTables)  [dim]([green]$($summary.PrimaryCount) primary[/] [yellow]$($summary.SecondaryCount) secondary[/]$(if ($summary.UnknownCount -gt 0) { " [red]$($summary.UnknownCount) unknown[/]" }))[/]"
        "[bold]Ingestion:[/]        $($summary.TotalMonthlyGB) GB/mo"
        "[bold]Est. Cost:[/]        [bold]`$$($summary.TotalMonthlyCost)/mo[/] [dim]@ `$$($summary.PricePerGB)/GB[/]"
        "[bold]Rules:[/]            $($summary.EnabledRules) active  |  [bold]Hunting:[/] $($summary.HuntingQueries)$(if ($summary.DontCorrCount -gt 0) { "  |  [yellow]$($summary.DontCorrCount) excluded from correlation[/]" })"
        "[bold]Coverage:[/]         $bar"
    )

    if ($summary.RetentionChecked -gt 0) {
        $retColor = if ($summary.RetentionNonCompliant -eq 0) { 'green' } elseif ($summary.RetentionNonCompliant -le 5) { 'yellow' } else { 'red' }
        $overviewLines += "[bold]Retention:[/]        [${retColor}]$($summary.RetentionCompliant) of $($summary.RetentionChecked) Analytics tables >= 90d[/]"
        if ($summary.RetentionImprovable -gt 0) {
            $overviewLines += "                    [dim]$($summary.RetentionImprovable) table(s) could benefit from extended retention[/]"
        }
    }
    if ($summary.WorkspaceRetentionDays -gt 0 -and $summary.WorkspaceRetentionDays -lt 90) {
        $overviewLines += "[bold yellow]:warning: Workspace default retention is $($summary.WorkspaceRetentionDays)d - increase to 90d[/]"
    }

    if ($summary.TablesWithTransforms -gt 0 -or $summary.SplitTables -gt 0) {
        $transformParts = @()
        if ($summary.TablesWithTransforms -gt 0) { $transformParts += "[deepskyblue1]$($summary.TablesWithTransforms) table(s) with transforms[/]" }
        if ($summary.SplitTables -gt 0) { $transformParts += "[yellow]$($summary.SplitTables) split table(s)[/]" }
        if ($summary.TransformDCRs -gt 0) { $transformParts += "[dim]$($summary.TransformDCRs) DCR(s)[/]" }
        $overviewLines += "[bold]Transforms:[/]       $($transformParts -join '  |  ')"
    }

    if ($summary.EstTotalSavings -gt 0) {
        $overviewLines += "[bold]Savings Potential:[/] [green]`$$($summary.EstTotalSavings)/mo[/]"
    }

    if ($summary.DetectionRulesAnalyzed -gt 0) {
        $overviewLines += "[bold]Rule Quality:[/]     [deepskyblue1]$($summary.DetectionRulesAnalyzed) analyzed[/] | [yellow]$($summary.NoisyRulesDetected) noisy[/] | [dim]$($summary.AutoClosedIncidents) auto-closed incidents[/]"
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
            'Plans'      = Get-TablePlanDisplay -Table $t
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
        [string]$ExportPath,
        [PSCustomObject]$Context
    )

    $menuItems = [ordered]@{
        'View Recommendations'          = 'recommendations'
        'View Detection Assessment'     = 'detection'
        'View Detection Analyzer'       = 'detanalyzer'
        'View SOC Optimization'         = 'soc'
        'View Retention Assessment'     = 'retention'
        'View Data Transforms'          = 'transforms'
        'Log Tuning / Transforms'       = 'logtuning'
        'View All Tables'               = 'tables'
    }

    if ($Context) {
        $menuItems['Manage table retention and type'] = 'manageretention'
    }

    $menuItems['Export Report']       = 'export'
    $menuItems['Quit']                = 'quit'

    $script:LogHorizonSkipNextHomeRedraw = $false
    $continue = $true
    $isFirstMenuRender = $true
    while ($continue) {
        Invoke-ConsoleSizeCheck
        $skipHomeRedraw = $false
        if ($script:LogHorizonSkipNextHomeRedraw) {
            $skipHomeRedraw = $true
            $script:LogHorizonSkipNextHomeRedraw = $false
        }

        if (-not $isFirstMenuRender -and -not $skipHomeRedraw) {
            Clear-LogHorizonScreen
            Write-LogHorizonBanner
            Write-Dashboard -Analysis $Analysis -WorkspaceName $WorkspaceName -DefenderXDR $DefenderXDR
        }
        $isFirstMenuRender = $false

        Write-SpectreRule -Title "[dodgerblue2]MENU[/]" -Color DodgerBlue2
        Write-SpectreHost ""

        $choice = Read-SpectreSelection -Title "Select a view:" `
                    -Choices @($menuItems.Keys) `
                    -Color DodgerBlue2

        $action = $menuItems[$choice]

        Write-SpectreHost ""

        switch ($action) {
            'recommendations' { Write-RecommendationView -Analysis $Analysis }
            'detection'       { Write-DetectionAssessment -Analysis $Analysis }
            'detanalyzer'     { Write-DetectionAnalyzer -Analysis $Analysis }
            'soc'             { Write-SocOptimization -Analysis $Analysis }
            'retention'       { Write-RetentionAssessment -Analysis $Analysis }
            'transforms'      { Write-DataTransformView -Analysis $Analysis }
            'logtuning'       { Write-LogTuningMenu -Analysis $Analysis -Context $Context }
            'tables'          { Write-TableInventory -Analysis $Analysis }
            'manageretention' { Invoke-ManageRetentionWizard -Analysis $Analysis -Context $Context }
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
function Write-RecommendationView {
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

    # Cost-value matrix: classification rows x assessment columns
    $assessmentOrder = @('High Value', 'Good Value', 'Missing Coverage', 'Optimize', 'Low Value', 'Underutilized', 'Free Tier')
    $classRows = @('primary', 'secondary')
    $matrixTable = @()

    foreach ($cls in $classRows) {
        $subset = $Analysis.TableAnalysis | Where-Object { $_.Classification -eq $cls }
        $row = [ordered]@{
            'Classification' = if ($cls -eq 'primary') { '[green]Primary[/]' } else { '[grey]Secondary[/]' }
        }
        foreach ($assess in $assessmentOrder) {
            $count = ($subset | Where-Object { $_.Assessment -eq $assess }).Count
            $cellValue = if ($count -eq 0) { '[dim]-[/]' }
                elseif ($assess -in @('Missing Coverage', 'Low Value', 'Optimize')) { "[yellow]$count[/]" }
                elseif ($assess -in @('High Value', 'Good Value', 'Free Tier')) { "[green]$count[/]" }
                else { "$count" }
            $row[$assess] = $cellValue
        }
        $total = ($subset | Measure-Object).Count
        $row['Total'] = "[bold]$total[/]"
        $matrixTable += [PSCustomObject]$row
    }

    # Totals row
    $allTables = $Analysis.TableAnalysis
    $totalsRow = [ordered]@{ 'Classification' = '[bold]Total[/]' }
    foreach ($assess in $assessmentOrder) {
        $count = ($allTables | Where-Object { $_.Assessment -eq $assess }).Count
        $totalsRow[$assess] = "[bold]$count[/]"
    }
    $totalsRow['Total'] = "[bold]$(($allTables | Measure-Object).Count)[/]"
    $matrixTable += [PSCustomObject]$totalsRow

    $matrixTable | Format-SpectreTable -Border Rounded -Color DodgerBlue2 -HeaderColor DodgerBlue2 -AllowMarkup
    Write-SpectreHost ""

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

    # Submenu loop for drill-down tables
    $submenuContinue = $true
    while ($submenuContinue) {
        $choices = @('Show primary tables', 'Show secondary tables', 'Back')
        $pick = Read-SpectreSelection -Title "[deepskyblue1]Select an option:[/]" `
                    -Choices $choices `
                    -Color DodgerBlue2

        switch ($pick) {
            'Back' { $submenuContinue = $false }
            default {
                $classification = if ($pick -eq 'Show primary tables') { 'primary' } else { 'secondary' }
                Write-DetectionAssessmentTable -TableAnalysis $Analysis.TableAnalysis -Classification $classification
            }
        }
    }
}

function Write-DetectionAssessmentTable {
    param(
        [array]$TableAnalysis,
        [string]$Classification
    )

    $width = Get-ConsoleWidth
    $showHunting = ($width -ge 120)

    $filtered = $TableAnalysis |
        Where-Object { $_.Classification -eq $Classification } |
        Sort-Object EstMonthlyCostUSD -Descending

    if ($filtered.Count -eq 0) {
        Write-SpectreHost "[dim]No $Classification tables found.[/]"
        return
    }

    $table = @()
    $rank = 0
    foreach ($t in $filtered) {
        $rank++

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

        $row = [ordered]@{
            '#'              = $rank
            'Table'          = Get-SafeEscapedText $t.TableName
            'GB/mo'          = $t.MonthlyGB
            'Cost/mo'        = $costStr
            'Cost Tier'      = $t.CostTier
            'Detection Tier' = $t.DetectionTier
            'Rules'          = $t.AnalyticsRules
        }
        if ($showHunting) { $row['Hunting'] = $t.HuntingQueries }
        $row['Assessment'] = $assessMarkup

        $table += [PSCustomObject]$row
    }

    $label = if ($Classification -eq 'primary') { 'PRIMARY' } else { 'SECONDARY' }
    $table | Format-SpectreTable -Border Rounded -Color DodgerBlue2 -HeaderColor DodgerBlue2 -AllowMarkup
    Write-SpectreHost "[dim]  $($filtered.Count) $label tables.[/]"
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
function Write-DataTransformView {
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

# Log Tuning / Transforms sub-menu
function Write-LogTuningMenu {
    param(
        [PSCustomObject]$Analysis,
        [PSCustomObject]$Context
    )

    # Help text explaining the three transform types
    $helpLines = @(
        "[bold]Log Tuning / Transforms[/]"
        ""
        "Reduce Sentinel ingestion costs by shaping data at ingest time. Filter and split transforms can be"
        "configured directly in the Defender portal (Configuration > Tables) or via Data Collection Rules (DCRs)."
        "Three approaches are available, and can be combined:"
        ""
        "[bold yellow]Row Splitting (WHERE):[/]  Route security-relevant rows to Analytics tier; send the rest to the Data lake tier."
        "                       Reduces Analytics ingestion cost while keeping all data available for compliance and investigations."
        ""
        "[bold yellow]Column Reduction (PROJECT):[/]  Remove unused columns at ingest time via DCR transform."
        "                              Reduces per-row storage cost proportional to columns removed."
        ""
        "[bold yellow]Combined (WHERE + PROJECT):[/]  Apply both row splitting AND column reduction for maximum savings."
        ""
        "[dim]Tip: Use 'Live Data' for tuning based on YOUR deployed rules. Use 'Knowledge Base' for community-driven recommendations.[/]"
    )
    ($helpLines -join "`n") | Format-SpectrePanel -Header "[dodgerblue2] LOG TUNING GUIDE [/]" -Border Rounded -Color DodgerBlue2
    Write-SpectreHost ""

    $subContinue = $true
    while ($subContinue) {
        $subMenu = [ordered]@{
            'Log tuning suggestions (live data)'      = 'live'
            'Log tuning suggestions (knowledge base)'  = 'kb'
            'Evaluate specific table'                  = 'evaluate'
            'Back'                                     = 'back'
        }

        $subChoice = Read-SpectreSelection -Title "[deepskyblue1]Select a tuning mode:[/]" `
                        -Choices @($subMenu.Keys) `
                        -Color DodgerBlue2

        $subAction = $subMenu[$subChoice]
        Write-SpectreHost ""

        switch ($subAction) {
            'live'     { Write-LiveTuningView -Analysis $Analysis }
            'kb'       { Write-SplitKqlSuggestionView -Analysis $Analysis }
            'evaluate' { Write-TableEvaluation -Analysis $Analysis -Context $Context }
            'back'     { $subContinue = $false }
        }
    }
}

# Live data tuning suggestions
function Write-LiveTuningView {
    param([PSCustomObject]$Analysis)

    $liveTuning = @($Analysis.LiveTuningAnalysis | Where-Object { $_.RuleCount -gt 0 })

    if ($liveTuning.Count -eq 0) {
        Write-SpectreHost "[dim]No live tuning suggestions available. Your deployed rules must reference at least one table.[/]"
        return
    }

    # Overview panel
    $totalSavings = ($liveTuning | Measure-Object EstFilterSavings -Sum).Sum + ($liveTuning | Measure-Object EstProjectSavings -Sum).Sum
    $tablesWithSchema = @($liveTuning | Where-Object { $_.SchemaColumnCount -gt 0 }).Count
    $overviewLines = @(
        "[bold]Tables with rules:[/]   $($liveTuning.Count)"
        "[bold]With schema data:[/]    $tablesWithSchema [dim](unused field analysis available)[/]"
        "[bold]Est. total savings:[/]  [green]`$$([math]::Round($totalSavings, 2))/mo[/] [dim](combined filter + project potential)[/]"
    )
    ($overviewLines -join "`n") | Format-SpectrePanel -Header "[dodgerblue2] LIVE DATA TUNING [/]" -Border Rounded -Color DodgerBlue2
    Write-SpectreHost ""

    # Summary table
    $table = @()
    foreach ($lt in ($liveTuning | Sort-Object EstMonthlyCostUSD -Descending)) {
        $unusedStr = if ($lt.SchemaColumnCount -gt 0) { "$($lt.UnusedFieldCount) of $($lt.SchemaColumnCount)" } else { '[dim]-[/]' }
        $filterStr = if ($lt.EstFilterSavings -gt 0) { "[green]`$$($lt.EstFilterSavings)[/]" } else { '[dim]-[/]' }
        $projectStr = if ($lt.EstProjectSavings -gt 0) { "[green]`$$($lt.EstProjectSavings)[/]" } else { '[dim]-[/]' }

        $table += [PSCustomObject]@{
            'Table'           = Get-SafeEscapedText $lt.TableName
            'GB/mo'           = $lt.MonthlyGB
            'Rules'           = $lt.RuleCount
            'Fields Used'     = $lt.FieldCount
            'Unused Cols'     = $unusedStr
            'Filter Savings'  = $filterStr
            'Project Savings' = $projectStr
        }
    }

    $table | Format-SpectreTable -Border Rounded -Color DodgerBlue2 -HeaderColor DodgerBlue2 -AllowMarkup
    Write-SpectreHost ""

    # Drill-down
    $choices = @('Back') + @($liveTuning | Sort-Object EstMonthlyCostUSD -Descending | ForEach-Object { $_.TableName })
    $pick = Read-SpectreSelection -Title "[deepskyblue1]Select a table for tuning KQL, or Back:[/]" -Choices $choices -Color DodgerBlue2 -EnableSearch

    if ($pick -ne 'Back') {
        $lt = $liveTuning | Where-Object { $_.TableName -eq $pick } | Select-Object -First 1
        Write-LiveTuningDetail -TuningEntry $lt
    }
}

function Write-LiveTuningDetail {
    param([PSCustomObject]$TuningEntry)

    $lt = $TuningEntry
    Write-SpectreHost ""
    Write-SpectreHost "[dodgerblue2][bold]$($lt.TableName)[/] — Live Data Tuning[/]"
    Write-SpectreHost "[dim]Based on $($lt.RuleCount) deployed rule(s) and hunting queries[/]"
    Write-SpectreHost ""

    # Per-table sub-menu
    $detailContinue = $true
    while ($detailContinue) {
        $detailMenu = [ordered]@{}
        if ($lt.FilterKql)   { $detailMenu['View WHERE filter KQL'] = 'filter' }
        if ($lt.ProjectKql)  { $detailMenu['View column reduction KQL'] = 'project' }
        if ($lt.CombinedKql) { $detailMenu['View combined KQL'] = 'combined' }
        $detailMenu['View field-by-rule breakdown'] = 'fields'
        $detailMenu['Back'] = 'back'

        $detailChoice = Read-SpectreSelection -Title "[deepskyblue1]Select a view:[/]" -Choices @($detailMenu.Keys) -Color DodgerBlue2
        $detailAction = $detailMenu[$detailChoice]
        Write-SpectreHost ""

        switch ($detailAction) {
            'filter' {
                Write-SpectreHost "[bold]Row Filter KQL[/] [dim](condition-only — portal prepends 'source | where')[/]"
                Write-SpectreHost "[deepskyblue1]$(Get-SafeEscapedText $lt.FilterKql)[/]"
                if ($lt.EstFilterSavings -gt 0) {
                    Write-SpectreHost "[dim]Estimated savings: ~`$$($lt.EstFilterSavings)/mo[/]"
                }
                Write-SpectreHost ""
            }
            'project' {
                Write-SpectreHost "[bold]Column Reduction KQL[/] [dim](full DCR transform syntax)[/]"
                Write-SpectreHost "[deepskyblue1]$(Get-SafeEscapedText $lt.ProjectKql)[/]"
                if ($lt.EstProjectSavings -gt 0) {
                    Write-SpectreHost "[dim]Estimated savings: ~`$$($lt.EstProjectSavings)/mo[/]"
                }
                Write-SpectreHost ""
            }
            'combined' {
                Write-SpectreHost "[bold]Combined KQL[/] [dim](filter rows + reduce columns)[/]"
                Write-SpectreHost "[deepskyblue1]$(Get-SafeEscapedText $lt.CombinedKql)[/]"
                $totalEst = $lt.EstFilterSavings + $lt.EstProjectSavings
                if ($totalEst -gt 0) {
                    Write-SpectreHost "[dim]Estimated combined savings: ~`$$([math]::Round($totalEst, 2))/mo[/]"
                }
                Write-SpectreHost ""
            }
            'fields' {
                Write-SpectreHost "[bold]Field-by-Rule Breakdown[/]"
                Write-SpectreHost ""

                # Show which rules use which fields
                foreach ($rd in $lt.RuleDetails) {
                    $fieldStr = ($rd.Fields | Select-Object -First 15) -join ', '
                    if ($rd.Fields.Count -gt 15) { $fieldStr += ", ... (+$($rd.Fields.Count - 15) more)" }
                    Write-SpectreHost "  [white]$(Get-SafeEscapedText $rd.RuleName)[/]"
                    Write-SpectreHost "    [dim]$fieldStr[/]"
                }
                Write-SpectreHost ""

                # Show used vs unused fields summary
                Write-SpectreHost "[bold]Fields used by rules ($($lt.FieldCount)):[/]"
                $usedStr = ($lt.UsedFields | Select-Object -First 25) -join ', '
                if ($lt.UsedFields.Count -gt 25) { $usedStr += ", ... (+$($lt.UsedFields.Count - 25) more)" }
                Write-SpectreHost "  [green]$(Get-SafeEscapedText $usedStr)[/]"

                if ($lt.UnusedFields.Count -gt 0) {
                    Write-SpectreHost ""
                    Write-SpectreHost "[bold]Unused schema columns ($($lt.UnusedFieldCount)):[/]"
                    $unusedStr = ($lt.UnusedFields | Select-Object -First 25) -join ', '
                    if ($lt.UnusedFields.Count -gt 25) { $unusedStr += ", ... (+$($lt.UnusedFields.Count - 25) more)" }
                    Write-SpectreHost "  [yellow]$(Get-SafeEscapedText $unusedStr)[/]"
                }
                Write-SpectreHost ""
            }
            'back' { $detailContinue = $false }
        }
    }
}

# Enhanced table evaluation
function Write-TableEvaluation {
    param(
        [PSCustomObject]$Analysis,
        [PSCustomObject]$Context
    )

    $allTables = @($Analysis.TableAnalysis | Sort-Object TableName)
    if ($allTables.Count -eq 0) { return }

    $choices = @('Back') + @($allTables | ForEach-Object { $_.TableName })
    $pick = Read-SpectreSelection -Title "Type to search or select a table to evaluate:" `
                                  -Choices $choices `
                                  -Color DodgerBlue2 `
                                  -EnableSearch

    if ($pick -eq 'Back') { return }

    $table = $allTables | Where-Object { $_.TableName -eq $pick } | Select-Object -First 1
    $splitSuggestion = $table.SplitSuggestion

    # Get live tuning data for this table if available
    $liveEntry = $Analysis.LiveTuningAnalysis | Where-Object { $_.TableName -eq $pick } | Select-Object -First 1

    Write-SpectreHost ""
    Write-SpectreHost "[dodgerblue2][bold]$($table.TableName)[/] — Comprehensive Table Evaluation[/]"
    Write-SpectreHost ""

    # Overview info
    $infoLines = @(
        "[bold]Category:[/]       $(Get-SafeEscapedText $table.Category)"
        "[bold]Classification:[/] $($table.Classification)"
        "[bold]Ingestion:[/]      $($table.MonthlyGB) GB/mo  |  [bold]Cost:[/] `$$($table.EstMonthlyCostUSD)/mo"
        "[bold]Plan:[/]           $(if ($table.TablePlan) { $table.TablePlan } else { 'Unknown' })"
        "[bold]Rules:[/]          $($table.AnalyticsRules) analytics  |  $($table.HuntingQueries) hunting$(if ($table.XDRRules -gt 0) { "  |  $($table.XDRRules) XDR" })"
    )

    if ($table.ObservedPlanSummary) {
        $infoLines += "[bold]Observed plans:[/] $(Get-SafeEscapedText $table.ObservedPlanSummary)"
    }

    if ($table.SchemaColumns -and $table.SchemaColumns.Count -gt 0) {
        $usedCount = if ($liveEntry) { $liveEntry.FieldCount } elseif ($splitSuggestion -and $splitSuggestion.AllFields) { $splitSuggestion.AllFields.Count } else { 0 }
        $infoLines += "[bold]Schema columns:[/]  $($table.SchemaColumns.Count) total  |  $usedCount used by rules"
    }

    ($infoLines -join "`n") | Format-SpectrePanel -Header "[dodgerblue2] TABLE OVERVIEW [/]" -Border Rounded -Color DodgerBlue2
    Write-SpectreHost ""

    # Field usage matrix (if we have live tuning data)
    if ($liveEntry -and $liveEntry.RuleDetails.Count -gt 0) {
        Write-SpectreHost "[bold]Field Usage Matrix[/]"
        Write-SpectreHost ""

        # Build matrix: show each field and which rules reference it
        $fieldRuleMap = @{}
        foreach ($rd in $liveEntry.RuleDetails) {
            foreach ($f in $rd.Fields) {
                if (-not $fieldRuleMap.ContainsKey($f)) {
                    $fieldRuleMap[$f] = [System.Collections.Generic.List[string]]::new()
                }
                $fieldRuleMap[$f].Add($rd.RuleName)
            }
        }

        $matrixRows = @()
        foreach ($field in ($fieldRuleMap.Keys | Sort-Object)) {
            $rules = $fieldRuleMap[$field]
            $ruleStr = ($rules | Select-Object -First 3) -join ', '
            if ($rules.Count -gt 3) { $ruleStr += " +$($rules.Count - 3) more" }

            $matrixRows += [PSCustomObject]@{
                'Field'      = Get-SafeEscapedText $field
                'Rule Count' = $rules.Count
                'Rules'      = Get-SafeEscapedText $ruleStr
            }
        }

        if ($matrixRows.Count -gt 0) {
            $matrixRows | Sort-Object 'Rule Count' -Descending |
                Select-Object -First 20 |
                Format-SpectreTable -Border Rounded -Color DodgerBlue2 -HeaderColor DodgerBlue2
        }

        # Coverage summary
        if ($table.SchemaColumns -and $table.SchemaColumns.Count -gt 0) {
            $coveragePct = [math]::Round(($liveEntry.FieldCount / $table.SchemaColumns.Count) * 100, 0)
            $coverageColor = if ($coveragePct -ge 50) { 'green' } elseif ($coveragePct -ge 25) { 'yellow' } else { 'red' }
            Write-SpectreHost "[$coverageColor][bold]$($liveEntry.FieldCount) of $($table.SchemaColumns.Count)[/] schema columns are referenced by your rules ($coveragePct% coverage)[/]"
        }
        Write-SpectreHost ""
    }

    # Tuning recommendation
    $recommendation = 'No automated tuning recommendation available for this table.'
    if ($liveEntry) {
        if ($liveEntry.ConditionCount -gt 0 -and $liveEntry.UnusedFieldCount -gt 5) {
            $recommendation = "[bold green]Recommended: Combined (filter + project)[/] — $($liveEntry.ConditionCount) filter condition(s) available and $($liveEntry.UnusedFieldCount) unused columns can be removed."
        }
        elseif ($liveEntry.ConditionCount -gt 0) {
            $recommendation = "[bold yellow]Recommended: Row splitting (WHERE)[/] — $($liveEntry.ConditionCount) filter condition(s) from deployed rules."
        }
        elseif ($liveEntry.UnusedFieldCount -gt 5) {
            $recommendation = "[bold yellow]Recommended: Column reduction (PROJECT)[/] — $($liveEntry.UnusedFieldCount) unused columns can be removed."
        }
        else {
            $recommendation = "[dim]Low tuning potential for this table based on current rule coverage.[/]"
        }
    }
    elseif ($splitSuggestion -and $splitSuggestion.Source -ne 'none') {
        $recommendation = "[bold yellow]Recommended: Use knowledge-base suggestion (source: $($splitSuggestion.Source))[/]"
    }

    Write-SpectreHost "[bold]Tuning Recommendation:[/]"
    Write-SpectreHost "  $recommendation"
    Write-SpectreHost ""

    # KQL generation sub-menu
    $evalContinue = $true
    while ($evalContinue) {
        $evalMenu = [ordered]@{}

        # Prefer live tuning KQL if available
        $kqlSource = if ($liveEntry) { $liveEntry } else { $null }

        if ($kqlSource -and $kqlSource.FilterKql)    { $evalMenu['View WHERE filter KQL'] = 'filter' }
        elseif ($splitSuggestion -and $splitSuggestion.SplitKql)                 { $evalMenu['View WHERE filter KQL (KB)'] = 'kbfilter' }

        if ($kqlSource -and $kqlSource.ProjectKql)   { $evalMenu['View column reduction KQL'] = 'project' }
        elseif ($splitSuggestion -and $splitSuggestion.ProjectKql)               { $evalMenu['View column reduction KQL (KB)'] = 'kbproject' }

        if ($kqlSource -and $kqlSource.CombinedKql)  { $evalMenu['View combined KQL'] = 'combined' }

        if ($liveEntry -and $liveEntry.RuleDetails.Count -gt 0) {
            $evalMenu['View field-by-rule breakdown'] = 'fields'
        }

        if ($Context) {
            $evalMenu['Manage retention/type for this table'] = 'updateretention'
        }

        $evalMenu['Back'] = 'back'

        if ($evalMenu.Count -le 1) {
            Write-SpectreHost "[dim]No KQL suggestions could be automatically generated for this table.[/]"
            break
        }

        $evalChoice = Read-SpectreSelection -Title "[deepskyblue1]Select a view:[/]" -Choices @($evalMenu.Keys) -Color DodgerBlue2
        $evalAction = $evalMenu[$evalChoice]
        Write-SpectreHost ""

        switch ($evalAction) {
            'filter' {
                Write-SpectreHost "[bold]Row Filter KQL[/] [dim](condition-only — portal prepends 'source | where')[/]"
                Write-SpectreHost "[deepskyblue1]$(Get-SafeEscapedText $kqlSource.FilterKql)[/]"
                Write-SpectreHost ""
            }
            'kbfilter' {
                Write-SpectreHost "[bold]Split Transform KQL[/] [dim](from knowledge base, condition-only)[/]"
                Write-SpectreHost "[deepskyblue1]$(Get-SafeEscapedText $splitSuggestion.SplitKql)[/]"
                Write-SpectreHost ""
            }
            'project' {
                Write-SpectreHost "[bold]Column Reduction KQL[/] [dim](full DCR transform syntax)[/]"
                Write-SpectreHost "[deepskyblue1]$(Get-SafeEscapedText $kqlSource.ProjectKql)[/]"
                Write-SpectreHost ""
            }
            'kbproject' {
                Write-SpectreHost "[bold]Column Reduction KQL[/] [dim](from knowledge base)[/]"
                Write-SpectreHost "[deepskyblue1]$(Get-SafeEscapedText $splitSuggestion.ProjectKql)[/]"
                Write-SpectreHost ""
            }
            'combined' {
                Write-SpectreHost "[bold]Combined KQL[/] [dim](filter rows + reduce columns)[/]"
                Write-SpectreHost "[deepskyblue1]$(Get-SafeEscapedText $kqlSource.CombinedKql)[/]"
                Write-SpectreHost ""
            }
            'fields' {
                foreach ($rd in $liveEntry.RuleDetails) {
                    $fieldStr = ($rd.Fields | Select-Object -First 15) -join ', '
                    if ($rd.Fields.Count -gt 15) { $fieldStr += ", ... (+$($rd.Fields.Count - 15) more)" }
                    Write-SpectreHost "  [white]$(Get-SafeEscapedText $rd.RuleName)[/]"
                    Write-SpectreHost "    [dim]$fieldStr[/]"
                }
                Write-SpectreHost ""
            }
            'updateretention' {
                Invoke-ManageRetentionWizard -Analysis $Analysis -Context $Context -TableNames @($table.TableName)
            }
            'back' { $evalContinue = $false }
        }
    }
}

# Split KQL suggestions (knowledge base path)
function Write-SplitKqlSuggestionView {
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
    $body | Format-SpectrePanel -Header "[dodgerblue2] KNOWLEDGE BASE TUNING [/]" -Border Rounded -Color DodgerBlue2
    Write-SpectreHost ""

    # Summary table
    $table = @()
    foreach ($rec in $splitRecs) {
        $splitSuggestion = $rec.SplitSuggestion
        $sourceMarkup = switch ($splitSuggestion.Source) {
            'knowledge-base'   { '[green]Knowledge Base[/]' }
            'rule-analysis'    { '[deepskyblue1]Rule Analysis[/]' }
            'combined'         { '[green]Combined[/]' }
            'community-stats'  { '[yellow]Community Stats[/]' }
            'category-defaults' { '[yellow]Category Defaults[/]' }
            'universal'        { '[dim]Universal Fallback[/]' }
            default            { '[grey]None[/]' }
        }

        $fieldsSummary = "$($splitSuggestion.RuleFields.Count) rule + $($splitSuggestion.HighValueFields.Count) KB"
        if ($splitSuggestion.FallbackFields -and $splitSuggestion.FallbackFields.Count -gt 0) {
            $fieldsSummary += " + $($splitSuggestion.FallbackFields.Count) fallback"
        }

        $table += [PSCustomObject]@{
            'Table'       = Get-SafeEscapedText $rec.TableName
            'GB/mo'       = ($Analysis.TableAnalysis | Where-Object TableName -eq $rec.TableName).MonthlyGB
            'Rules'       = $splitSuggestion.RuleCount
            'Fields'      = $fieldsSummary
            'Source'      = $sourceMarkup
            'Est Savings' = "`$$($rec.EstSavingsUSD)/mo"
        }
    }

    $table | Format-SpectreTable -Border Rounded -Color DodgerBlue2 -HeaderColor DodgerBlue2 -AllowMarkup
    Write-SpectreHost ""

    # Drill-down
    $choices = @('Back') + @($splitRecs | ForEach-Object { $_.TableName })
    $pick = Read-SpectreSelection -Title "[deepskyblue1]Select a table for tuning KQL, or Back:[/]" -Choices $choices -Color DodgerBlue2

    if ($pick -ne 'Back') {
        $rec = $splitRecs | Where-Object { $_.TableName -eq $pick } | Select-Object -First 1
        $splitSuggestion = $rec.SplitSuggestion

        Write-SpectreHost ""
        Write-SpectreHost "[dodgerblue2][bold]$($rec.TableName)[/] — Knowledge Base Tuning[/]"

        if ($splitSuggestion.Description) {
            Write-SpectreHost "[dim]$(Get-SafeEscapedText $splitSuggestion.Description)[/]"
        }
        Write-SpectreHost ""

        # Sub-menu for KB drill-down
        $kbContinue = $true
        while ($kbContinue) {
            $kbMenu = [ordered]@{}
            if ($splitSuggestion.SplitKql)   { $kbMenu['View WHERE filter KQL'] = 'filter' }
            if ($splitSuggestion.ProjectKql) { $kbMenu['View column reduction KQL'] = 'project' }
            $kbMenu['View field analysis'] = 'fields'
            $kbMenu['Back'] = 'back'

            $kbChoice = Read-SpectreSelection -Title "[deepskyblue1]Select a view:[/]" -Choices @($kbMenu.Keys) -Color DodgerBlue2
            $kbAction = $kbMenu[$kbChoice]
            Write-SpectreHost ""

            switch ($kbAction) {
                'filter' {
                    Write-SpectreHost "[bold]Split Transform KQL[/] [dim](condition-only — the portal prepends 'source | where' automatically)[/]"
                    Write-SpectreHost "[deepskyblue1]$(Get-SafeEscapedText $splitSuggestion.SplitKql)[/]"
                    if ($rec.EstSavingsUSD -gt 0) {
                        Write-SpectreHost "[dim]Estimated savings: ~`$$($rec.EstSavingsUSD)/mo[/]"
                    }
                    Write-SpectreHost ""
                }
                'project' {
                    Write-SpectreHost "[bold]Column Reduction KQL[/] [dim](keeps only detection-relevant fields)[/]"
                    Write-SpectreHost "[deepskyblue1]$(Get-SafeEscapedText $splitSuggestion.ProjectKql)[/]"
                    Write-SpectreHost ""
                }
                'fields' {
                    if ($splitSuggestion.RuleFields.Count -gt 0) {
                        $ruleFieldStr = ($splitSuggestion.RuleFields | Select-Object -First 20) -join ', '
                        Write-SpectreHost "[bold]Fields from analytics rules ($($splitSuggestion.RuleFields.Count)):[/]"
                        Write-SpectreHost "  [white]$(Get-SafeEscapedText $ruleFieldStr)[/]"
                        Write-SpectreHost ""
                    }

                    if ($splitSuggestion.HighValueFields.Count -gt 0) {
                        $hvFieldStr = ($splitSuggestion.HighValueFields | Select-Object -First 20) -join ', '
                        Write-SpectreHost "[bold]Fields from knowledge base ($($splitSuggestion.HighValueFields.Count)):[/]"
                        Write-SpectreHost "  [white]$(Get-SafeEscapedText $hvFieldStr)[/]"
                        Write-SpectreHost ""
                    }

                    if ($splitSuggestion.FallbackFields -and $splitSuggestion.FallbackFields.Count -gt 0) {
                        $fbFieldStr = ($splitSuggestion.FallbackFields | Select-Object -First 20) -join ', '
                        Write-SpectreHost "[bold]Fields from fallback ($($splitSuggestion.FallbackFields.Count)) [dim](source: $($splitSuggestion.FallbackSource))[/]:[/]"
                        Write-SpectreHost "  [yellow]$(Get-SafeEscapedText $fbFieldStr)[/]"
                        Write-SpectreHost ""
                    }

                    Write-SpectreHost "[dim]Source: $($splitSuggestion.Source) | $($splitSuggestion.RuleCount) rule(s) | $($splitSuggestion.ConditionCount) condition(s) extracted[/]"
                    Write-SpectreHost ""
                }
                'back' { $kbContinue = $false }
            }
        }
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
        $splitSuggestion = $table.SplitSuggestion

        Write-SpectreHost ""
        Write-SpectreHost "[dodgerblue2][bold]$($table.TableName)[/] — Target Field and KQL Evaluation[/]"

        if (-not $splitSuggestion -or $splitSuggestion.Source -eq 'none') {
            Write-SpectreHost "[dim]No KQL suggestions could be automatically generated for this table (no knowledge-base hits or mapped analytics rules).[/]"
            return
        }

        if ($splitSuggestion.Description) {
            Write-SpectreHost "[dim]$(Get-SafeEscapedText $splitSuggestion.Description)[/]"
        }
        Write-SpectreHost ""

        # Show split KQL
        if ($splitSuggestion.SplitKql) {
            Write-SpectreHost "[bold]Split Transform KQL[/] [dim](condition-only — the portal prepends 'source | where' automatically)[/]"
            Write-SpectreHost "[deepskyblue1]$(Get-SafeEscapedText $splitSuggestion.SplitKql)[/]"
            Write-SpectreHost ""
        }

        # Show projection KQL
        if ($splitSuggestion.ProjectKql) {
            Write-SpectreHost "[bold]Column Reduction KQL[/] [dim](keeps only detection-relevant fields)[/]"
            Write-SpectreHost "[deepskyblue1]$(Get-SafeEscapedText $splitSuggestion.ProjectKql)[/]"
            Write-SpectreHost ""
        }

        # Show field analysis
        if ($splitSuggestion.RuleFields.Count -gt 0) {
            $ruleFieldStr = ($splitSuggestion.RuleFields | Sort-Object) -join ', '
            Write-SpectreHost "[bold]Fields from analytics rules ($($splitSuggestion.RuleFields.Count)):[/]"
            Write-SpectreHost "  [white]$(Get-SafeEscapedText $ruleFieldStr)[/]"
            Write-SpectreHost ""
        }

        if ($splitSuggestion.HighValueFields.Count -gt 0) {
            $hvFieldStr = ($splitSuggestion.HighValueFields | Sort-Object) -join ', '
            Write-SpectreHost "[bold]Fields from knowledge base ($($splitSuggestion.HighValueFields.Count)):[/]"
            Write-SpectreHost "  [white]$(Get-SafeEscapedText $hvFieldStr)[/]"
            Write-SpectreHost ""
        }

        Write-SpectreHost "[dim]Source: $($splitSuggestion.Source) | $($splitSuggestion.RuleCount) mapped rule(s) | $($splitSuggestion.ConditionCount) condition(s) extracted[/]"
    }
}

# All tables
function Write-TableInventory {
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

        $row = [ordered]@{
            '#'          = $rank
            'Table'      = Get-SafeEscapedText $t.TableName
            'Plans'      = Get-TablePlanDisplay -Table $t
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

    $summary = $Analysis.Summary
    if ($summary.RetentionChecked -eq 0) {
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
    if ($summary.WorkspaceRetentionDays -gt 0) {
        $wsColor = if ($summary.WorkspaceRetentionDays -ge 90) { 'green' } else { 'red' }
        $lines += "[bold]Workspace Default:[/] [${wsColor}]$($summary.WorkspaceRetentionDays)d[/]$(if ($summary.WorkspaceRetentionDays -lt 90) { ' [yellow](increase to 90d)[/]' })"
    }
    $lines += "[bold]Baseline (>=90d):[/]  [green]$($summary.RetentionCompliant)[/] of $($summary.RetentionChecked) Analytics tables"
    if ($summary.RetentionNonCompliant -gt 0) {
        $lines += "[bold]Below Baseline:[/]   [red]$($summary.RetentionNonCompliant)[/] table(s) below 90d"
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

            $table += [PSCustomObject]@{
                'Table'     = Get-SafeEscapedText $t.TableName
                'Plans'     = Get-TablePlanDisplay -Table $t
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
                'Plans'       = Get-TablePlanDisplay -Table $t
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
                'Plans'       = Get-TablePlanDisplay -Table $t
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
                'Plans'       = '[grey]-[/]'
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

    # Coverage stats panel
    $detectionSummary = $Analysis.DetectionAnalyzer.Summary
    if ($null -ne $detectionSummary.TotalTables -and $detectionSummary.TotalTables -gt 0) {
        $consoleW = Get-ConsoleWidth
        # Dynamic bar width: scale with terminal, floor 10, cap 30
        $barWidth = [math]::Max(10, [math]::Min(30, [math]::Floor(($consoleW - 60) * 0.5)))
        $detFill   = [math]::Max([math]::Round(($detectionSummary.DetectionCoveragePct / 100) * $barWidth), 0)
        $huntFill  = [math]::Max([math]::Round(($detectionSummary.HuntingCoveragePct / 100) * $barWidth), 0)
        $combFill  = [math]::Max([math]::Round(($detectionSummary.CombinedCoveragePct / 100) * $barWidth), 0)

        $detBar  = "[deepskyblue1]$([string]::new([char]0x2588, $detFill))[/][dim]$([string]::new([char]0x2591, $barWidth - $detFill))[/]"
        $huntBar = "[green]$([string]::new([char]0x2588, $huntFill))[/][dim]$([string]::new([char]0x2591, $barWidth - $huntFill))[/]"
        $combBar = "[yellow]$([string]::new([char]0x2588, $combFill))[/][dim]$([string]::new([char]0x2591, $barWidth - $combFill))[/]"

        # GB-weighted coverage bars
        $detGBFill  = [math]::Max([math]::Round(($detectionSummary.DetectionCoverageGBPct / 100) * $barWidth), 0)
        $huntGBFill = [math]::Max([math]::Round(($detectionSummary.HuntingCoverageGBPct / 100) * $barWidth), 0)
        $combGBFill = [math]::Max([math]::Round(($detectionSummary.CombinedCoverageGBPct / 100) * $barWidth), 0)

        $detGBBar  = "[deepskyblue1]$([string]::new([char]0x2588, $detGBFill))[/][dim]$([string]::new([char]0x2591, $barWidth - $detGBFill))[/]"
        $huntGBBar = "[green]$([string]::new([char]0x2588, $huntGBFill))[/][dim]$([string]::new([char]0x2591, $barWidth - $huntGBFill))[/]"
        $combGBBar = "[yellow]$([string]::new([char]0x2588, $combGBFill))[/][dim]$([string]::new([char]0x2591, $barWidth - $combGBFill))[/]"

        if ($consoleW -ge 120) {
            # Full layout with aligned labels
            $coverageLines = @(
                "[bold]Ingestion Coverage[/] [dim]($($detectionSummary.TotalTables) tables, $($detectionSummary.TotalAllGB) GB/month)[/]"
                ""
                "  Detection (Analytics/CDR)  $detBar  [deepskyblue1]$($detectionSummary.DetectionCoveragePct)%[/] [dim]($($detectionSummary.TablesWithDetection)/$($detectionSummary.TotalTables) tables)[/]"
                "  Hunting Queries            $huntBar  [green]$($detectionSummary.HuntingCoveragePct)%[/] [dim]($($detectionSummary.TablesWithHunting)/$($detectionSummary.TotalTables) tables)[/]"
                "  Combined                   $combBar  [yellow]$($detectionSummary.CombinedCoveragePct)%[/] [dim]($($detectionSummary.TablesWithCombined)/$($detectionSummary.TotalTables) tables)[/]"
                ""
                "[bold]Volume Coverage[/] [dim](GB with detections / total GB)[/]"
                ""
                "  Detection (Analytics/CDR)  $detGBBar  [deepskyblue1]$($detectionSummary.DetectionCoverageGBPct)%[/] [dim]($($detectionSummary.DetectionCoverageGB)/$($detectionSummary.TotalAllGB) GB)[/]"
                "  Hunting Queries            $huntGBBar  [green]$($detectionSummary.HuntingCoverageGBPct)%[/] [dim]($($detectionSummary.HuntingCoverageGB)/$($detectionSummary.TotalAllGB) GB)[/]"
                "  Combined                   $combGBBar  [yellow]$($detectionSummary.CombinedCoverageGBPct)%[/] [dim]($($detectionSummary.CombinedCoverageGB)/$($detectionSummary.TotalAllGB) GB)[/]"
                ""
                "  Avg detections per table:  [bold]$($detectionSummary.AvgDetectionsPerTable)[/] [dim](analytics + CDR rules)[/]"
            )
        } else {
            # Compact layout with shorter labels
            $coverageLines = @(
                "[bold]Coverage[/] [dim]($($detectionSummary.TotalTables) tables, $($detectionSummary.TotalAllGB) GB/mo)[/]"
                ""
                "  Detection  $detBar  [deepskyblue1]$($detectionSummary.DetectionCoveragePct)%[/] [dim]($($detectionSummary.TablesWithDetection)/$($detectionSummary.TotalTables))[/]"
                "  Hunting    $huntBar  [green]$($detectionSummary.HuntingCoveragePct)%[/] [dim]($($detectionSummary.TablesWithHunting)/$($detectionSummary.TotalTables))[/]"
                "  Combined   $combBar  [yellow]$($detectionSummary.CombinedCoveragePct)%[/] [dim]($($detectionSummary.TablesWithCombined)/$($detectionSummary.TotalTables))[/]"
                ""
                "[bold]Volume[/] [dim](GB coverage)[/]"
                ""
                "  Detection  $detGBBar  [deepskyblue1]$($detectionSummary.DetectionCoverageGBPct)%[/] [dim]($($detectionSummary.DetectionCoverageGB)/$($detectionSummary.TotalAllGB) GB)[/]"
                "  Hunting    $huntGBBar  [green]$($detectionSummary.HuntingCoverageGBPct)%[/] [dim]($($detectionSummary.HuntingCoverageGB)/$($detectionSummary.TotalAllGB) GB)[/]"
                "  Combined   $combGBBar  [yellow]$($detectionSummary.CombinedCoverageGBPct)%[/] [dim]($($detectionSummary.CombinedCoverageGB)/$($detectionSummary.TotalAllGB) GB)[/]"
                ""
                "  Avg detections/table: [bold]$($detectionSummary.AvgDetectionsPerTable)[/]"
            )
        }
        ($coverageLines -join "`n") | Format-SpectrePanel -Header "[dodgerblue2] DETECTION COVERAGE [/]" -Border Rounded -Color DodgerBlue2
        Write-SpectreHost ""
    }

    # Scored rules sorted by noisiness, then unscored (CDRs without incidents) at the end
    $scored = @($Analysis.DetectionAnalyzer.RuleMetrics | Where-Object { $null -ne $_.NoisinessScore } | Sort-Object NoisinessScore -Descending)
    $unscored = @($Analysis.DetectionAnalyzer.RuleMetrics | Where-Object { $null -eq $_.NoisinessScore })
    $metrics = @($scored) + @($unscored)
    $displayMetrics = @($metrics | Select-Object -First 15)

    $width = Get-ConsoleWidth
    $showKind = ($width -ge 100)
    # Reserve space for table borders + other columns; remaining goes to rule name
    $maxNameLen = if ($width -ge 140) { 80 } elseif ($width -ge 120) { 55 } elseif ($width -ge 100) { 40 } else { 30 }

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

        $displayName = $r.RuleName
        if ($displayName.Length -gt $maxNameLen) {
            $displayName = $displayName.Substring(0, $maxNameLen - 3) + '...'
        }

        $row = [ordered]@{
            'Rule'        = Get-SafeEscapedText $displayName
        }
        if ($showKind) { $row['Kind'] = $kindMarkup }
        $row['Incidents']   = $r.IncidentsTotal
        $row['AutoClose%']  = [math]::Round(($r.AutoCloseRatio * 100), 1)
        $row['FalsePos%']   = [math]::Round(($r.FalsePositiveRatio * 100), 1)
        $row['Score']       = $scoreMarkup

        $table += [PSCustomObject]$row
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
        ""
        "  [dim]A high score does not conclusively mean a detection is bad -- it is an[/]"
        "  [dim]indicator that the rule may warrant closer review.[/]"
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
                $allWidth = Get-ConsoleWidth
                $allShowKind = ($allWidth -ge 100)
                $allMaxNameLen = if ($allWidth -ge 140) { 80 } elseif ($allWidth -ge 120) { 55 } elseif ($allWidth -ge 100) { 40 } else { 30 }
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

                    $displayName = $r.RuleName
                    if ($displayName.Length -gt $allMaxNameLen) {
                        $displayName = $displayName.Substring(0, $allMaxNameLen - 3) + '...'
                    }

                    $row = [ordered]@{
                        'Rule'        = Get-SafeEscapedText $displayName
                    }
                    if ($allShowKind) { $row['Kind'] = $kindMarkup }
                    $row['Incidents']   = $r.IncidentsTotal
                    $row['AutoClose%']  = [math]::Round(($r.AutoCloseRatio * 100), 1)
                    $row['FalsePos%']   = [math]::Round(($r.FalsePositiveRatio * 100), 1)
                    $row['Score']       = $scoreMarkup

                    $fullTable += [PSCustomObject]$row
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

# Interactive wizard input helpers.
function Read-LogHorizonTextInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [string]$DefaultAnswer
    )

    $hostPrompt = if ($PSBoundParameters.ContainsKey('DefaultAnswer')) {
        "$Prompt [$DefaultAnswer]"
    }
    else {
        $Prompt
    }

    $value = Read-Host $hostPrompt
    if ([string]::IsNullOrWhiteSpace($value) -and $PSBoundParameters.ContainsKey('DefaultAnswer')) {
        return $DefaultAnswer
    }

    return $value
}

function Clear-LogHorizonScreen {
    [CmdletBinding()]
    param()

    try {
        Clear-Host
    }
    catch {
        Write-Verbose 'Unable to clear console window.'
    }
}

function Get-LogHorizonMinimumColdRetentionValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Analysis,
        [Parameter(Mandatory)][PSCustomObject[]]$Tables,
        [Nullable[int]]$RetentionInDays
    )

    $workspaceRetention = $null
    if ($Analysis.Summary -and $null -ne $Analysis.Summary.WorkspaceRetentionDays -and $Analysis.Summary.WorkspaceRetentionDays -gt 0) {
        $workspaceRetention = [int]$Analysis.Summary.WorkspaceRetentionDays
    }

    $effectiveHotValues = foreach ($table in $Tables) {
        if ($PSBoundParameters.ContainsKey('RetentionInDays')) {
            if ($null -ne $RetentionInDays) {
                [int]$RetentionInDays
                continue
            }

            if ($null -ne $workspaceRetention) {
                [int]$workspaceRetention
                continue
            }
        }

        if ($null -ne $table.ActualInteractiveRetentionDays) {
            [int]$table.ActualInteractiveRetentionDays
            continue
        }

        if ($null -ne $table.RetentionInDays) {
            [int]$table.RetentionInDays
            continue
        }

        if ($null -ne $workspaceRetention) {
            [int]$workspaceRetention
        }
    }

    $knownHotValues = @($effectiveHotValues | Where-Object { $null -ne $_ })
    if ($knownHotValues.Count -eq 0) {
        return $null
    }

    return ([int](($knownHotValues | Measure-Object -Maximum).Maximum) + 1)
}

function Get-LogHorizonColdRetentionHint {
    [CmdletBinding()]
    param([Nullable[int]]$MinimumValue)

    $longTermValues = '1095,1460,1826,2191,2556,2922,3288,3653,4018,4383'
    if ($null -eq $MinimumValue -or $MinimumValue -le 4) {
        return "4-730 or $longTermValues"
    }

    if ($MinimumValue -le 730) {
        return "$MinimumValue-730 or $longTermValues"
    }

    return $longTermValues
}

# Interactive wizard selection and apply helpers.
function Show-LogHorizonManagedTableList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]]$Tables,
        [string]$Title = 'Selected table(s)'
    )

    if ($Tables.Count -eq 0) {
        Write-SpectreHost "[yellow]No tables selected.[/]"
        return
    }

    Write-SpectreHost "[bold]$Title[/]"
    $rows = foreach ($t in ($Tables | Sort-Object TableName)) {
        [PSCustomObject]@{
            'Table' = Get-SafeEscapedText $t.TableName
            'Plan'  = if ($t.TablePlan) { $t.TablePlan } else { '-' }
            'Hot'   = if ($null -ne $t.ActualInteractiveRetentionDays) { "$($t.ActualInteractiveRetentionDays) d" } else { 'inherit' }
            'Cold'  = if ($null -ne $t.ActualRetentionDays) { "$($t.ActualRetentionDays) d" } else { 'inherit' }
        }
    }

    $rows | Format-SpectreTable -Border Rounded -Color DodgerBlue2 -HeaderColor DodgerBlue2
    Write-SpectreHost ""
}

function Select-LogHorizonTablesFromList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]]$Tables,
        [string]$Title = '[deepskyblue1]Select table(s) from list:[/]'
    )

    if ($Tables.Count -eq 0) {
        return @()
    }

    $selectedNames = New-Object System.Collections.Generic.List[string]
    $selecting = $true
    while ($selecting) {
        Clear-LogHorizonScreen

        $menu = [ordered]@{}
        $remaining = @($Tables | Where-Object { $_.TableName -notin $selectedNames })
        if ($remaining.Count -gt 0) {
            $menu['Add a table'] = 'add'
        }
        if ($selectedNames.Count -gt 0) {
            $menu['Remove a table'] = 'remove'
            $menu['Done'] = 'done'
        }
        $menu['Cancel'] = 'cancel'

        Write-SpectreHost "[dim]Current selection: $(if ($selectedNames.Count -gt 0) { $selectedNames -join ', ' } else { '(none)' })[/]"
        $choice = Read-SpectreSelection -Title $Title -Choices @($menu.Keys) -Color DodgerBlue2
        switch ($menu[$choice]) {
            'add' {
                $addChoices = @($remaining | ForEach-Object { $_.TableName }) + @('Back')
                $addChoice = Read-SpectreSelection -Title '[deepskyblue1]Add table:[/]' -Choices $addChoices -Color DodgerBlue2 -EnableSearch
                if ($addChoice -and $addChoice -ne 'Back' -and $addChoice -notin $selectedNames) {
                    $selectedNames.Add($addChoice) | Out-Null
                }
            }
            'remove' {
                $removeChoices = @($selectedNames) + @('Back')
                $removeChoice = Read-SpectreSelection -Title '[deepskyblue1]Remove table:[/]' -Choices $removeChoices -Color DodgerBlue2 -EnableSearch
                if ($removeChoice -and $removeChoice -ne 'Back') {
                    $selectedNames.Remove($removeChoice) | Out-Null
                }
            }
            'done' {
                $selecting = $false
            }
            'cancel' {
                return @()
            }
        }
        Write-SpectreHost ''
    }

    return @($Tables | Where-Object { $_.TableName -in $selectedNames })
}

function Get-LogHorizonTypeSwitchableTableSet {
    [CmdletBinding()]
    param([Parameter(Mandatory)][PSCustomObject[]]$Tables)

    return @($Tables | Where-Object { Test-TableSupportsBasicPlan -Table $_ } | Sort-Object TableName)
}

function Invoke-LogHorizonManagedTableUpdate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Analysis,
        [Parameter(Mandatory)][PSCustomObject]$Context,
        [Parameter(Mandatory)][PSCustomObject[]]$Tables,
        [string]$TargetPlan,
        [Nullable[int]]$TotalRetentionInDays,
        [Nullable[int]]$RetentionInDays
    )

    $changeSetParams = @{ Tables = $Tables }
    if ($PSBoundParameters.ContainsKey('TargetPlan')) { $changeSetParams['TargetPlan'] = $TargetPlan }
    if ($PSBoundParameters.ContainsKey('TotalRetentionInDays')) { $changeSetParams['TotalRetentionInDays'] = $TotalRetentionInDays }
    if ($PSBoundParameters.ContainsKey('RetentionInDays')) { $changeSetParams['RetentionInDays'] = $RetentionInDays }

    try {
        $changeSet = @(Get-TableRetentionChangeSet @changeSetParams)
    }
    catch {
        Write-SpectreHost "[red]Validation failed: $($_.Exception.Message)[/]"
        return
    }

    Write-SpectreHost ""
    Format-TableRetentionPreview -ChangeSet $changeSet | Format-SpectreTable -Border Rounded -Color DodgerBlue2 -HeaderColor DodgerBlue2 -AllowMarkup
    Write-SpectreHost ""

    $pending = @($changeSet | Where-Object Status -eq 'Pending').Count
    if ($pending -eq 0) {
        Write-SpectreHost "[yellow]No pending changes after validation.[/]"
        return
    }

    $confirm = Read-SpectreSelection -Title "Apply $pending change(s)?" -Choices @('No, cancel', "Yes, apply $pending change(s)") -Color DodgerBlue2
    if ($confirm -notlike 'Yes*') {
        Write-SpectreHost "[dim]Cancelled.[/]"
        return
    }

    Write-SpectreHost ""
    Write-SpectreHost "[deepskyblue1]Applying...[/]"
    $results = @(Invoke-TableRetentionApply -Context $Context -ChangeSet $changeSet)

    $resultRows = foreach ($r in $results) {
        [PSCustomObject]@{
            'Table'    = $r.TableName
            'Action'   = if ($r.Success) { '[green]' + $r.Action + '[/]' } else { '[red]' + $r.Action + '[/]' }
            'Fallback' = if ($r.Fallback) { 'yes' } else { '' }
            'Detail'   = if ($r.Error) { $r.Error } else { '' }
        }
    }
    $resultRows | Format-SpectreTable -Border Rounded -Color DodgerBlue2 -HeaderColor DodgerBlue2 -AllowMarkup
    Write-SpectreHost ""

    $applied  = @($results | Where-Object { $_.Action -eq 'Applied' }).Count
    $failed   = @($results | Where-Object { $_.Action -eq 'Failed' }).Count
    $fallback = @($results | Where-Object { $_.Fallback }).Count
    Write-SpectreHost "[bold]$applied applied, $failed failed, $fallback used fallback.[/]"

    $affected = @($results | Where-Object { $_.Success } | ForEach-Object { $_.TableName })
    if ($affected.Count -gt 0) {
        try {
            $refresh = Get-TableRetention -Context $Context
            foreach ($name in $affected) {
                $live = $refresh.Tables | Where-Object TableName -eq $name | Select-Object -First 1
                if (-not $live) { continue }
                $row = $Analysis.TableAnalysis | Where-Object TableName -eq $name | Select-Object -First 1
                if ($row) {
                    $row.TablePlan = $live.Plan
                    $row.PSObject.Properties['ActualInteractiveRetentionDays'] | ForEach-Object { if ($_) { $_.Value = $live.RetentionInDays } }
                    $row.PSObject.Properties['ArchiveRetentionInDays']         | ForEach-Object { if ($_) { $_.Value = $live.ArchiveRetentionInDays } }
                    $row.PSObject.Properties['ActualRetentionDays']            | ForEach-Object { if ($_) { $_.Value = $live.TotalRetentionInDays } }
                    $row.PSObject.Properties['TableSubType']                   | ForEach-Object { if ($_) { $_.Value = $live.TableSubType } }
                    $row.PSObject.Properties['RetentionCompliant']             | ForEach-Object { if ($_) { $_.Value = if ($live.Plan -eq 'Analytics') { $live.TotalRetentionInDays -ge 90 } else { $null } } }
                    $row.PSObject.Properties['RetentionCanImprove']            | ForEach-Object { if ($_) { $_.Value = if ($row.RetentionCompliant -and $row.RecommendedRetentionDays -gt 90) { $live.TotalRetentionInDays -lt $row.RecommendedRetentionDays } else { $false } } }
                }
            }
            Write-SpectreHost "[dim]In-memory analysis refreshed for $($affected.Count) table(s).[/]"
        }
        catch {
            Write-SpectreHost "[yellow]Could not refresh post-apply state: $($_.Exception.Message)[/]"
        }
    }

    $script:LogHorizonSkipNextHomeRedraw = $true
    Write-SpectreHost ""
}

function Invoke-ManageTableRetentionFlow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Analysis,
        [Parameter(Mandatory)][PSCustomObject]$Context,
        [Parameter(Mandatory)][PSCustomObject[]]$AllTables,
        [PSCustomObject[]]$PreselectedTables
    )

    Clear-LogHorizonScreen

    $selectedTables = @()
    if ($PreselectedTables -and $PreselectedTables.Count -gt 0) {
        $selectedTables = @($PreselectedTables)
    }
    else {
        $retentionMenu = [ordered]@{
            'Select all Analytics tables with retention under 90 days' = 'under90'
            'Select all Analytics tables' = 'analytics'
            'Select table(s) from list' = 'list'
            'Back' = 'back'
        }
        $choice = Read-SpectreSelection -Title '[deepskyblue1]Change retention for table(s):[/]' -Choices @($retentionMenu.Keys) -Color DodgerBlue2
        switch ($retentionMenu[$choice]) {
            'under90' {
                $selectedTables = @($AllTables | Where-Object { $_.TablePlan -eq 'Analytics' -and $null -ne $_.ActualRetentionDays -and $_.ActualRetentionDays -lt 90 })
            }
            'analytics' {
                $selectedTables = @($AllTables | Where-Object { $_.TablePlan -eq 'Analytics' })
            }
            'list' {
                $selectedTables = @(Select-LogHorizonTablesFromList -Tables $AllTables)
            }
            'back' {
                return
            }
        }
    }

    if ($selectedTables.Count -eq 0) {
        Write-SpectreHost '[yellow]No tables matched the selection.[/]'
        return
    }

    Clear-LogHorizonScreen
    Show-LogHorizonManagedTableList -Tables $selectedTables -Title "$($selectedTables.Count) table(s) selected"

    $changeArgs = @{}
    $hotEligible = (@($selectedTables | Where-Object { $_.TablePlan -eq 'Analytics' }).Count -eq $selectedTables.Count)
    if ($hotEligible) {
        $changeHot = Read-SpectreSelection -Title 'Change hot retention?' -Choices @('No change', 'Set value', 'Inherit workspace default') -Color DodgerBlue2
        if ($changeHot -eq 'Set value') {
            $rawHot = Read-LogHorizonTextInput -Prompt 'Enter hot retention (4-730 days):'
            $hotDays = 0
            if (-not [int]::TryParse($rawHot, [ref]$hotDays)) {
                Write-SpectreHost '[red]Invalid hot retention value.[/]'
                return
            }
            $changeArgs['RetentionInDays'] = $hotDays
        }
        elseif ($changeHot -eq 'Inherit workspace default') {
            $changeArgs['RetentionInDays'] = $null
        }
    }
    else {
        Write-SpectreHost '[dim]Hot retention can only be changed when all selected tables are Analytics.[/]'
    }

    $changeCold = Read-SpectreSelection -Title 'Change cold retention?' -Choices @('No change', 'Set value', 'Remove long-term retention') -Color DodgerBlue2
    if ($changeCold -eq 'Set value') {
        $minimumColdParams = @{ Analysis = $Analysis; Tables = $selectedTables }
        if ($changeArgs.ContainsKey('RetentionInDays')) {
            $minimumColdParams['RetentionInDays'] = $changeArgs['RetentionInDays']
        }
        $minimumColdRetention = Get-LogHorizonMinimumColdRetentionValue @minimumColdParams
        $coldRetentionHint = Get-LogHorizonColdRetentionHint -MinimumValue $minimumColdRetention
        $coldPrompt = if ($null -ne $minimumColdRetention) {
            "Enter cold retention / totalRetentionInDays (must be greater than hot retention; current minimum is $minimumColdRetention d. Valid values: $coldRetentionHint)"
        }
        else {
            "Enter cold retention / totalRetentionInDays ($coldRetentionHint)"
        }

        $rawCold = Read-LogHorizonTextInput -Prompt $coldPrompt
        $coldDays = 0
        if (-not [int]::TryParse($rawCold, [ref]$coldDays)) {
            Write-SpectreHost '[red]Invalid cold retention value.[/]'
            return
        }

        if (-not (Test-TotalRetentionValue -Value $coldDays)) {
            Write-SpectreHost "[red]Invalid cold retention value. Valid values for this selection are $coldRetentionHint.[/]"
            return
        }

        if ($null -ne $minimumColdRetention -and $coldDays -lt $minimumColdRetention) {
            $effectiveHotRetention = $minimumColdRetention - 1
            Write-SpectreHost "[red]Cold retention must be greater than hot retention. The highest effective hot retention in this selection is $effectiveHotRetention d, so valid values start at $minimumColdRetention d.[/]"
            return
        }

        $changeArgs['TotalRetentionInDays'] = $coldDays
    }
    elseif ($changeCold -eq 'Remove long-term retention') {
        $changeArgs['TotalRetentionInDays'] = $null
    }

    if ($changeArgs.Count -eq 0) {
        Write-SpectreHost '[yellow]Nothing to change.[/]'
        return
    }

    Invoke-LogHorizonManagedTableUpdate -Analysis $Analysis -Context $Context -Tables $selectedTables @changeArgs
}

function Invoke-ManageTableTypeFlow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Analysis,
        [Parameter(Mandatory)][PSCustomObject]$Context,
        [Parameter(Mandatory)][PSCustomObject[]]$AllTables,
        [PSCustomObject[]]$PreselectedTables
    )

    Clear-LogHorizonScreen

    $eligibleTables = @(Get-LogHorizonTypeSwitchableTableSet -Tables $(if ($PreselectedTables -and $PreselectedTables.Count -gt 0) { $PreselectedTables } else { $AllTables }))
    if ($eligibleTables.Count -eq 0) {
        Write-SpectreHost '[yellow]No selected tables support Analytics <-> Basic switching.[/]'
        return
    }

    $selectedTables = if ($PreselectedTables -and $PreselectedTables.Count -gt 0) {
        $eligibleTables
    }
    else {
        @(Select-LogHorizonTablesFromList -Tables $eligibleTables -Title '[deepskyblue1]Select table(s) to change type:[/]')
    }

    if ($selectedTables.Count -eq 0) {
        Write-SpectreHost '[yellow]No tables selected.[/]'
        return
    }

    Clear-LogHorizonScreen
    Show-LogHorizonManagedTableList -Tables $selectedTables -Title "$($selectedTables.Count) switchable table(s) selected"

    $targetPlan = Read-SpectreSelection -Title 'Change table type to:' -Choices @('Analytics', 'Basic', 'Back') -Color DodgerBlue2
    if ($targetPlan -eq 'Back') {
        return
    }

    Invoke-LogHorizonManagedTableUpdate -Analysis $Analysis -Context $Context -Tables $selectedTables -TargetPlan $targetPlan
}

# Interactive wizard for updating table retention and type.
function Invoke-ManageRetentionWizard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Analysis,
        [Parameter(Mandatory)][PSCustomObject]$Context,
        # Optional: pre-select tables (e.g. when launched from a single-table view).
        [string[]]$TableNames
    )

    $allTables = @($Analysis.TableAnalysis | Where-Object { $_.TablePlan } | Sort-Object TableName)
    if ($allTables.Count -eq 0) {
        Write-SpectreHost "[yellow]No tables with known plan/retention metadata are available to update.[/]"
        return
    }

        $preselectedTables = @()
    if ($TableNames -and $TableNames.Count -gt 0) {
            $preselectedTables = @($allTables | Where-Object { $_.TableName -in $TableNames })
            if ($preselectedTables.Count -eq 0) {
            Write-SpectreHost "[red]None of the supplied table names matched the analysis set.[/]"
            return
        }
    }
        $menu = [ordered]@{
            'Change retention for table(s)' = 'retention'
            'Change table type' = 'type'
            'Back' = 'back'
        }

        $showMenu = $true
        while ($showMenu) {
            Clear-LogHorizonScreen
            $choice = Read-SpectreSelection -Title '[deepskyblue1]Manage table retention and type:[/]' -Choices @($menu.Keys) -Color DodgerBlue2
            switch ($menu[$choice]) {
                'retention' {
                    Invoke-ManageTableRetentionFlow -Analysis $Analysis -Context $Context -AllTables $allTables -PreselectedTables $preselectedTables
                    if ($script:LogHorizonSkipNextHomeRedraw) {
                        return
                    }
                }
                'type' {
                    Invoke-ManageTableTypeFlow -Analysis $Analysis -Context $Context -AllTables $allTables -PreselectedTables $preselectedTables
                    if ($script:LogHorizonSkipNextHomeRedraw) {
                        return
                    }
                }
                'back' {
                    $showMenu = $false
                }
            }
        }
}


