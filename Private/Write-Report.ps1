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

function Get-ConsoleWidth {
    try { $Host.UI.RawUI.WindowSize.Width } catch { 120 }
}

function Get-SafeEscapedText ([string]$Value) {
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
        [string]$WorkspaceName
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
        'View SOC Optimization'         = 'soc'
        'View Retention Assessment'     = 'retention'
        'View Data Transforms'          = 'transforms'
        'View Split KQL Suggestions'    = 'splitkql'
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
            'retention'       { Write-RetentionAssessment -Analysis $Analysis }
            'transforms'      { Write-DataTransforms -Analysis $Analysis }
            'splitkql'        { Write-SplitKqlSuggestions -Analysis $Analysis }
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
        Where-Object { $_.Classification -eq 'primary' -and $_.TotalCoverage -ge 3 } |
        Group-Object Category

    if ($wellCovered) {
        $lines += "[green][bold]Well Covered[/][/]"
        foreach ($grp in $wellCovered) {
            $tableList = ($grp.Group | ForEach-Object { $_.TableName }) -join ', '
            $totalRules = ($grp.Group | Measure-Object TotalCoverage -Sum).Sum
            $lines += "  [green]●[/] $(Get-SafeEscapedText $grp.Name): $(Get-SafeEscapedText $tableList) [dim]($totalRules rules)[/]"
        }
        $lines += ""
    }

    # Gaps (1-2 rules)
    $gaps = $Analysis.TableAnalysis |
        Where-Object { $_.Classification -eq 'primary' -and -not $_.IsFree -and $_.TotalCoverage -lt 3 -and $_.TotalCoverage -ge 1 }

    if ($gaps) {
        $lines += "[yellow][bold]Gaps Detected[/][/]"
        foreach ($g in $gaps) {
            $lines += "  [yellow]●[/] $(Get-SafeEscapedText $g.TableName) - $($g.MonthlyGB) GB/mo, only $($g.TotalCoverage) rule(s)"
        }
        $lines += ""
    }

    # Zero detections
    $noCoverage = $Analysis.TableAnalysis |
        Where-Object { $_.Classification -eq 'primary' -and -not $_.IsFree -and $_.TotalCoverage -eq 0 }

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
    if ($extendedRecTables.Count -gt 0) {
        $lines += "[bold]Extended (>90d):[/]  [deepskyblue1]$($extendedRecTables.Count)[/] table(s) recommended for 180d+ retention"
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
    if ($extendedRecTables.Count -gt 0) {
        $choices = @("Show extended retention recommendations ($($extendedRecTables.Count) tables)", 'Back')
    }

    $pick = Read-SpectreSelection -Title "[deepskyblue1]Select an option:[/]" -Choices $choices -Color DodgerBlue2

    if ($pick -ne 'Back') {
        Write-SpectreHost ""

        $sorted = $extendedRecTables | Sort-Object RecommendedRetentionDays -Descending

        $impTable = @()
        foreach ($t in $sorted) {
            $currentStr = if ($null -ne $t.ActualRetentionDays) { "$($t.ActualRetentionDays)d" } else { '-' }
            $statusMarkup = if ($null -ne $t.ActualRetentionDays -and $t.ActualRetentionDays -ge $t.RecommendedRetentionDays) {
                '[green]Met[/]'
            } elseif ($t.RetentionCompliant) {
                '[yellow]Baseline only[/]'
            } else {
                '[red]Below baseline[/]'
            }

            $impTable += [PSCustomObject]@{
                'Table'       = Get-SafeEscapedText $t.TableName
                'Category'    = Get-SafeEscapedText $t.Category
                'Current'     = $currentStr
                'Recommended' = "[deepskyblue1]$($t.RecommendedRetentionDays)d[/]"
                'Status'      = $statusMarkup
            }
        }

        $impTable | Format-SpectreTable -Border Rounded -Color DodgerBlue2 -HeaderColor DodgerBlue2 -AllowMarkup

        Write-SpectreHost ""
        Write-SpectreHost "[deepskyblue1][bold]Tip:[/] Use the Data Lake (Auxiliary) tier for retention beyond 90 days.[/]"
        Write-SpectreHost "[dim]  Keep 90 days in the Analytics tier for active hunting and detections,[/]"
        Write-SpectreHost "[dim]  then archive to the Data Lake tier for long-term compliance retention.[/]"
        Write-SpectreHost "[dim]  Data Lake storage costs ~95% less than Analytics tier ingestion.[/]"
    }
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
        $streamingNames = ($xdrStreaming | ForEach-Object { Get-SafeEscapedText $_.TableName }) -join ', '
        $lines += "[bold]Streaming to Sentinel:[/] $streamingNames"
    }

    $xdrRecs = $Analysis.Recommendations | Where-Object Type -eq 'XDROptimize'
    if ($xdrRecs) {
        $lines += ""
        $lines += "[yellow][bold]Optimization Opportunities:[/][/]"
        foreach ($xr in $xdrRecs) {
            $lines += "  [yellow]>[/] $(Get-SafeEscapedText $xr.Title)"
            $lines += "    [dim]$(Get-SafeEscapedText $xr.Detail)[/]"
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

    Write-SpectreHost "[green]Report exported to [bold]$(Get-SafeEscapedText $ExportPath)[/][/]"
}
