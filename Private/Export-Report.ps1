function Export-Report {
    <#
    .SYNOPSIS
        Exports the Log Horizon analysis report to JSON, Markdown, or static HTML.
        MD and HTML render identical sections via a shared section renderer.
        JSON is the complete data dump containing all analysis properties.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Analysis,
        [Parameter(Mandatory)][ValidateSet('json', 'markdown', 'md', 'html')][string]$Format,
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$WorkspaceName,
        [PSCustomObject]$DefenderXDR
    )

    $moduleVersion = (Import-PowerShellDataFile "$PSScriptRoot\..\LogHorizon.psd1").ModuleVersion
    $timestamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
    $generatedStr = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC' -AsUTC

    # Validate output path — if directory, auto-generate timestamped filename
    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    if (Test-Path -Path $resolvedPath -PathType Container) {
        $ext = if ($Format -in 'markdown', 'md') { 'md' } else { $Format }
        $resolvedPath = Join-Path $resolvedPath "LogHorizon_Report_${timestamp}.$ext"
        $OutputPath = $resolvedPath
    }

    if (-not (Test-Path -Path (Split-Path -Path $resolvedPath -Parent) -IsValid)) {
        throw "Invalid output path: $OutputPath"
    }

    # --- Sanitisation helpers ---
    function ConvertTo-SafeMarkdown([string]$Text) {
        if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
        return $Text -replace '([\\`*_{}[\]()#+\-.!])', '\$1' -replace '<', '&lt;' -replace '>', '&gt;'
    }

    function ConvertTo-HtmlSafe([string]$Text) {
        if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
        return [System.Net.WebUtility]::HtmlEncode($Text)
    }

    $safeWorkspaceMD   = ConvertTo-SafeMarkdown $WorkspaceName
    $safeWorkspaceHTML = ConvertTo-HtmlSafe $WorkspaceName

    switch ($Format) {
        'json' {
            $export = [ordered]@{
                metadata = [ordered]@{
                    tool      = 'Log Horizon'
                    version   = $moduleVersion
                    workspace = $WorkspaceName
                    generated = (Get-Date -Format 'o')
                }
                summary              = $Analysis.Summary
                tableAnalysis        = $Analysis.TableAnalysis
                recommendations      = $Analysis.Recommendations
                keywordGaps          = $Analysis.KeywordGaps
                correlationExcluded  = $Analysis.CorrelationExcluded
                correlationIncluded  = $Analysis.CorrelationIncluded
                socRecommendations   = $Analysis.SocRecommendations
                dataTransforms       = $Analysis.DataTransforms
                detectionAnalyzer    = $Analysis.DetectionAnalyzer
                xdrChecker           = $Analysis.XdrChecker
            }
            if ($DefenderXDR) {
                $xdrStreamed = @($Analysis.TableAnalysis | Where-Object IsXDRStreaming)
                $export.defenderXDR = [ordered]@{
                    totalXDRRules    = $DefenderXDR.TotalXDRRules
                    xdrTableCoverage = $DefenderXDR.XDRTableCoverage
                    knownXDRTables   = $DefenderXDR.KnownXDRTables
                    streamingTables  = @($xdrStreamed | ForEach-Object {
                        [ordered]@{ tableName = $_.TableName; plan = $_.XDRState }
                    })
                }
            }

            $export | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding utf8
            Write-Output "JSON report written to $OutputPath"
        }

        { $_ -in 'markdown', 'md' } {
            $sections = ConvertTo-ReportSections -Analysis $Analysis -DefenderXDR $DefenderXDR

            $sb = [System.Text.StringBuilder]::new()
            [void]$sb.AppendLine('# Log Horizon - Sentinel Log Analysis Report')
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("**Workspace:** $safeWorkspaceMD  ")
            [void]$sb.AppendLine("**Generated:** $generatedStr  ")
            [void]$sb.AppendLine("**Version:** $moduleVersion  ")
            [void]$sb.AppendLine('')

            foreach ($section in $sections) {
                [void]$sb.Append($section.Markdown)
            }

            $sb.ToString() | Set-Content -Path $OutputPath -Encoding utf8
            Write-Output "Markdown report written to $OutputPath"
        }

        'html' {
            $sections = ConvertTo-ReportSections -Analysis $Analysis -DefenderXDR $DefenderXDR
            $templatePath = Join-Path -Path $PSScriptRoot -ChildPath '..\Data\ReportTemplate.html'
            $template = Get-Content -Path $templatePath -Raw

            # Build tab navigation (radios + labels) and tab panes
            $tabRadios = [System.Text.StringBuilder]::new()
            $tabLabels = [System.Text.StringBuilder]::new()
            $tabBody = [System.Text.StringBuilder]::new()
            $tabIndex = 0
            foreach ($section in $sections) {
                $tabId = $section.TabId
                $checked = if ($tabIndex -eq 0) { ' checked' } else { '' }
                [void]$tabRadios.AppendLine("            <input type=`"radio`" name=`"tabs`" id=`"tab-$tabId`" class=`"tab-radio`"$checked>")
                [void]$tabLabels.AppendLine("                <label for=`"tab-$tabId`" class=`"tab-label`">$($section.Title)</label>")
                [void]$tabBody.AppendLine("            <section class=`"tab-pane`" id=`"pane-$tabId`">")
                [void]$tabBody.Append($section.Html)
                [void]$tabBody.AppendLine('            </section>')
                $tabIndex++
            }

            $html = $template.Replace('__WORKSPACE__', $safeWorkspaceHTML)
            $html = $html.Replace('__GENERATED__', (ConvertTo-HtmlSafe $generatedStr))
            $html = $html.Replace('__VERSION__', (ConvertTo-HtmlSafe $moduleVersion))
            $html = $html.Replace('__TAB_NAVIGATION__', $tabRadios.ToString())
            $html = $html.Replace('__TAB_LABELS__', $tabLabels.ToString())
            $html = $html.Replace('__TAB_PANES__', $tabBody.ToString())

            $html | Set-Content -Path $OutputPath -Encoding utf8
            Write-Output "HTML report written to $OutputPath"
        }
    }
}

# ---------------------------------------------------------------------------
# Shared section renderer — produces identical content for MD and HTML
# ---------------------------------------------------------------------------
function ConvertTo-ReportSections {
    param(
        [Parameter(Mandatory)][PSCustomObject]$Analysis,
        [PSCustomObject]$DefenderXDR
    )

    function hEnc([string]$Text) { [System.Net.WebUtility]::HtmlEncode($Text) }
    function mdEsc([string]$Text) {
        if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
        $Text -replace '([\\`*_{}[\]()#+\-.!])', '\$1' -replace '<', '&lt;' -replace '>', '&gt;'
    }

    $sections = [System.Collections.Generic.List[PSCustomObject]]::new()
    $s = $Analysis.Summary

    # ── 1. Summary ──
    $mdSb = [System.Text.StringBuilder]::new()
    [void]$mdSb.AppendLine('## Summary')
    [void]$mdSb.AppendLine('')
    [void]$mdSb.AppendLine('| Metric | Value |')
    [void]$mdSb.AppendLine('| --- | --- |')
    [void]$mdSb.AppendLine("| Total Tables | $($s.TotalTables) |")
    [void]$mdSb.AppendLine("| Primary Sources | $($s.PrimaryCount) |")
    [void]$mdSb.AppendLine("| Secondary Sources | $($s.SecondaryCount) |")
    [void]$mdSb.AppendLine("| Total Ingestion | $($s.TotalMonthlyGB) GB/mo |")
    [void]$mdSb.AppendLine("| Est. Monthly Cost | `$$($s.TotalMonthlyCost) |")
    [void]$mdSb.AppendLine("| Active Rules | $($s.EnabledRules) |")
    [void]$mdSb.AppendLine("| Hunting Queries | $($s.HuntingQueries) |")
    [void]$mdSb.AppendLine("| Coverage | $($s.CoveragePercent)% |")
    [void]$mdSb.AppendLine("| Potential Savings | `$$($s.EstTotalSavings) |")
    if ($s.RetentionChecked -gt 0) {
        [void]$mdSb.AppendLine("| Retention Compliant | $($s.RetentionCompliant) of $($s.RetentionChecked) |")
    }
    if ($s.TablesWithTransforms -gt 0) {
        [void]$mdSb.AppendLine("| Tables with Transforms | $($s.TablesWithTransforms) |")
    }
    if ($s.SplitTables -gt 0) {
        [void]$mdSb.AppendLine("| Split Tables | $($s.SplitTables) |")
    }
    [void]$mdSb.AppendLine('')

    $htmlSb = [System.Text.StringBuilder]::new()
    [void]$htmlSb.AppendLine('            <div class="summary-grid">')
    $metrics = @(
        @{ Value = $s.TotalTables; Label = 'Total Tables' }
        @{ Value = "$($s.TotalMonthlyGB) GB/mo"; Label = 'Ingestion' }
        @{ Value = "`$$($s.TotalMonthlyCost)/mo"; Label = 'Est. Cost' }
        @{ Value = $s.EnabledRules; Label = 'Active Rules' }
        @{ Value = "$($s.CoveragePercent)%"; Label = 'Rule Coverage' }
        @{ Value = "`$$($s.EstTotalSavings)/mo"; Label = 'Potential Savings'; Class = 'savings' }
    )
    foreach ($m in $metrics) {
        $cls = if ($m.Class) { " class=`"metric-value $($m.Class)`"" } else { ' class="metric-value"' }
        [void]$htmlSb.AppendLine("                <div class=`"metric-card`"><div$cls>$(hEnc "$($m.Value)")</div><div class=`"metric-label`">$(hEnc $m.Label)</div></div>")
    }
    [void]$htmlSb.AppendLine('            </div>')

    $sections.Add([PSCustomObject]@{ Title = 'Summary'; TabId = 'summary'; Markdown = $mdSb.ToString(); Html = $htmlSb.ToString() })

    # ── 2. Recommendations ──
    if ($Analysis.Recommendations.Count -gt 0) {
        $sortedRecs = $Analysis.Recommendations | Sort-Object @{Expression={
            switch ($_.Priority) { 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } default { 4 } }
        }}

        $mdSb = [System.Text.StringBuilder]::new()
        [void]$mdSb.AppendLine('## Recommendations')
        [void]$mdSb.AppendLine('')
        $num = 1
        foreach ($rec in $sortedRecs) {
            $icon = switch ($rec.Priority) { 'High' { '🔴' } 'Medium' { '🟡' } 'Low' { '🔵' } }
            [void]$mdSb.AppendLine("### $num. $icon $($rec.Title)")
            [void]$mdSb.AppendLine('')
            [void]$mdSb.AppendLine("**Priority:** $($rec.Priority)  ")
            [void]$mdSb.AppendLine("**Type:** $($rec.Type)  ")
            [void]$mdSb.AppendLine("**Current Cost:** `$$($rec.CurrentCost)/mo  ")
            if ($rec.EstSavingsUSD -gt 0) {
                [void]$mdSb.AppendLine("**Est. Savings:** `$$($rec.EstSavingsUSD)/mo  ")
            }
            [void]$mdSb.AppendLine('')
            [void]$mdSb.AppendLine($rec.Detail)
            [void]$mdSb.AppendLine('')
            $num++
        }

        $htmlSb = [System.Text.StringBuilder]::new()
        $num = 1
        foreach ($rec in $sortedRecs) {
            $prioClass = switch ($rec.Priority) { 'High' { 'badge-high' } 'Medium' { 'badge-medium' } 'Low' { 'badge-low' } }
            $saveBadge = if ($rec.EstSavingsUSD -gt 0) { " <span class=`"badge badge-savings`">Saves `$$($rec.EstSavingsUSD)/mo</span>" } else { '' }
            [void]$htmlSb.AppendLine("            <article class=`"rec-card`">")
            [void]$htmlSb.AppendLine("                <div class=`"rec-header`"><span class=`"badge $prioClass`">$($rec.Priority)</span> <span class=`"badge`">$($rec.Type)</span>$saveBadge <strong>$(hEnc $rec.Title)</strong></div>")
            [void]$htmlSb.AppendLine("                <p>$(hEnc $rec.Detail)</p>")
            [void]$htmlSb.AppendLine('            </article>')
            $num++
        }

        $sections.Add([PSCustomObject]@{ Title = 'Recommendations'; TabId = 'recs'; Markdown = $mdSb.ToString(); Html = $htmlSb.ToString() })
    }

    # ── 3. Table Analysis ──
    $sorted = $Analysis.TableAnalysis | Sort-Object EstMonthlyCostUSD -Descending

    $mdSb = [System.Text.StringBuilder]::new()
    [void]$mdSb.AppendLine('## Table Analysis')
    [void]$mdSb.AppendLine('')
    [void]$mdSb.AppendLine('| Table | Class | GB/mo | Cost/mo | Rules | Hunting | Assessment |')
    [void]$mdSb.AppendLine('| --- | --- | ---: | ---: | ---: | ---: | --- |')
    foreach ($t in $sorted) {
        $costStr = if ($t.IsFree) { 'FREE' } else { "`$$($t.EstMonthlyCostUSD)" }
        [void]$mdSb.AppendLine("| $($t.TableName) | $($t.Classification) | $($t.MonthlyGB) | $costStr | $($t.AnalyticsRules) | $($t.HuntingQueries) | $($t.Assessment) |")
    }
    [void]$mdSb.AppendLine('')

    $htmlSb = [System.Text.StringBuilder]::new()
    [void]$htmlSb.AppendLine('            <div class="table-wrap"><table>')
    [void]$htmlSb.AppendLine('                <thead><tr><th>Table</th><th>Class</th><th>GB/mo</th><th>Cost/mo</th><th>Rules</th><th>Hunting</th><th>Assessment</th></tr></thead>')
    [void]$htmlSb.AppendLine('                <tbody>')
    foreach ($t in $sorted) {
        $clsClass = switch ($t.Classification) { 'primary' { 'cls-primary' } 'secondary' { 'cls-secondary' } default { 'cls-unknown' } }
        $costStr = if ($t.IsFree) { '<span class="badge badge-savings">FREE</span>' } else { "`$$($t.EstMonthlyCostUSD)" }
        [void]$htmlSb.AppendLine("                <tr><td>$(hEnc $t.TableName)</td><td class=`"$clsClass`">$($t.Classification.ToUpper())</td><td class=`"num`">$($t.MonthlyGB)</td><td class=`"num`">$costStr</td><td class=`"num`">$($t.TotalCoverage)</td><td class=`"num`">$($t.HuntingQueries)</td><td>$(hEnc $t.Assessment)</td></tr>")
    }
    [void]$htmlSb.AppendLine('                </tbody>')
    [void]$htmlSb.AppendLine('            </table></div>')

    $sections.Add([PSCustomObject]@{ Title = 'Tables &amp; Costs'; TabId = 'tables'; Markdown = $mdSb.ToString(); Html = $htmlSb.ToString() })

    # ── 4. Keyword Gaps ──
    if ($Analysis.KeywordGaps -and $Analysis.KeywordGaps.Count -gt 0) {
        $mdSb = [System.Text.StringBuilder]::new()
        [void]$mdSb.AppendLine('## Missing Log Sources (Keyword Matches)')
        [void]$mdSb.AppendLine('')
        [void]$mdSb.AppendLine('| Table | Connector | Classification | Keyword |')
        [void]$mdSb.AppendLine('| --- | --- | --- | --- |')
        foreach ($kg in $Analysis.KeywordGaps) {
            [void]$mdSb.AppendLine("| $($kg.TableName) | $($kg.Connector) | $($kg.Classification) | $($kg.MatchedKeyword) |")
        }
        [void]$mdSb.AppendLine('')

        $htmlSb = [System.Text.StringBuilder]::new()
        [void]$htmlSb.AppendLine('            <p>Tables matching your keywords that are not currently ingested.</p>')
        [void]$htmlSb.AppendLine('            <div class="table-wrap"><table>')
        [void]$htmlSb.AppendLine('                <thead><tr><th>Table</th><th>Connector</th><th>Classification</th><th>Keyword</th></tr></thead>')
        [void]$htmlSb.AppendLine('                <tbody>')
        foreach ($kg in $Analysis.KeywordGaps) {
            [void]$htmlSb.AppendLine("                <tr><td>$(hEnc $kg.TableName)</td><td>$(hEnc $kg.Connector)</td><td>$(hEnc $kg.Classification)</td><td>$(hEnc $kg.MatchedKeyword)</td></tr>")
        }
        [void]$htmlSb.AppendLine('                </tbody>')
        [void]$htmlSb.AppendLine('            </table></div>')

        $sections.Add([PSCustomObject]@{ Title = 'Keyword Gaps'; TabId = 'keywords'; Markdown = $mdSb.ToString(); Html = $htmlSb.ToString() })
    }

    # ── 5. Retention Assessment ──
    $nonCompliant = @($Analysis.TableAnalysis | Where-Object { $_.RetentionCompliant -eq $false } | Sort-Object ActualRetentionDays)
    $improvable = @($Analysis.TableAnalysis | Where-Object { $_.RetentionCanImprove -eq $true } | Sort-Object RecommendedRetentionDays -Descending)

    if ($nonCompliant.Count -gt 0 -or $improvable.Count -gt 0) {
        $mdSb = [System.Text.StringBuilder]::new()
        [void]$mdSb.AppendLine('## Retention Assessment')
        [void]$mdSb.AppendLine('')

        if ($s.WorkspaceRetentionDays -gt 0 -and $s.WorkspaceRetentionDays -lt 90) {
            [void]$mdSb.AppendLine("> **Warning:** Workspace default retention is $($s.WorkspaceRetentionDays)d — increase to at least 90d.  ")
            [void]$mdSb.AppendLine('')
        }

        if ($nonCompliant.Count -gt 0) {
            [void]$mdSb.AppendLine('### Below 90-Day Baseline')
            [void]$mdSb.AppendLine('')
            [void]$mdSb.AppendLine('| Table | Plan | Current | Baseline | Shortfall |')
            [void]$mdSb.AppendLine('| --- | --- | ---: | ---: | ---: |')
            foreach ($t in $nonCompliant) {
                $shortfall = 90 - $t.ActualRetentionDays
                $plan = if ($t.TablePlan) { $t.TablePlan } else { '-' }
                [void]$mdSb.AppendLine("| $($t.TableName) | $plan | $($t.ActualRetentionDays)d | 90d | +${shortfall}d |")
            }
            [void]$mdSb.AppendLine('')
        }

        if ($improvable.Count -gt 0) {
            [void]$mdSb.AppendLine('### Extended Retention Recommendations')
            [void]$mdSb.AppendLine('')
            [void]$mdSb.AppendLine('| Table | Category | Current | Recommended |')
            [void]$mdSb.AppendLine('| --- | --- | ---: | ---: |')
            foreach ($t in $improvable) {
                $currentStr = if ($null -ne $t.ActualRetentionDays) { "$($t.ActualRetentionDays)d" } else { '-' }
                [void]$mdSb.AppendLine("| $($t.TableName) | $($t.Category) | $currentStr | $($t.RecommendedRetentionDays)d |")
            }
            [void]$mdSb.AppendLine('')
        }

        $htmlSb = [System.Text.StringBuilder]::new()
        if ($s.WorkspaceRetentionDays -gt 0 -and $s.WorkspaceRetentionDays -lt 90) {
            [void]$htmlSb.AppendLine("            <p class=`"warning`">⚠ Workspace default retention is $($s.WorkspaceRetentionDays)d — increase to at least 90d.</p>")
        }

        if ($nonCompliant.Count -gt 0) {
            [void]$htmlSb.AppendLine('            <h3>Below 90-Day Baseline</h3>')
            [void]$htmlSb.AppendLine('            <div class="table-wrap"><table>')
            [void]$htmlSb.AppendLine('                <thead><tr><th>Table</th><th>Plan</th><th>Current</th><th>Baseline</th><th>Shortfall</th></tr></thead>')
            [void]$htmlSb.AppendLine('                <tbody>')
            foreach ($t in $nonCompliant) {
                $shortfall = 90 - $t.ActualRetentionDays
                $plan = if ($t.TablePlan) { hEnc $t.TablePlan } else { '-' }
                [void]$htmlSb.AppendLine("                <tr><td>$(hEnc $t.TableName)</td><td>$plan</td><td class=`"num bad`">$($t.ActualRetentionDays)d</td><td class=`"num`">90d</td><td class=`"num bad`">+${shortfall}d</td></tr>")
            }
            [void]$htmlSb.AppendLine('                </tbody></table></div>')
        }

        if ($improvable.Count -gt 0) {
            [void]$htmlSb.AppendLine('            <h3>Extended Retention Recommendations</h3>')
            [void]$htmlSb.AppendLine('            <div class="table-wrap"><table>')
            [void]$htmlSb.AppendLine('                <thead><tr><th>Table</th><th>Category</th><th>Current</th><th>Recommended</th></tr></thead>')
            [void]$htmlSb.AppendLine('                <tbody>')
            foreach ($t in $improvable) {
                $currentStr = if ($null -ne $t.ActualRetentionDays) { "$($t.ActualRetentionDays)d" } else { '-' }
                [void]$htmlSb.AppendLine("                <tr><td>$(hEnc $t.TableName)</td><td>$(hEnc $t.Category)</td><td class=`"num`">$currentStr</td><td class=`"num`">$($t.RecommendedRetentionDays)d</td></tr>")
            }
            [void]$htmlSb.AppendLine('                </tbody></table></div>')
        }

        $sections.Add([PSCustomObject]@{ Title = 'Retention'; TabId = 'retention'; Markdown = $mdSb.ToString(); Html = $htmlSb.ToString() })
    }

    # ── 6. Data Transforms ──
    $transforms = $Analysis.DataTransforms
    $tablesWithTransforms = @($Analysis.TableAnalysis | Where-Object { $_.HasTransform })
    $splitTables = @($Analysis.TableAnalysis | Where-Object { $_.IsSplitTable })

    if ($tablesWithTransforms.Count -gt 0 -or $splitTables.Count -gt 0) {
        $mdSb = [System.Text.StringBuilder]::new()
        [void]$mdSb.AppendLine('## Data Transforms')
        [void]$mdSb.AppendLine('')

        if ($splitTables.Count -gt 0) {
            [void]$mdSb.AppendLine('### Split Tables')
            [void]$mdSb.AppendLine('')
            [void]$mdSb.AppendLine('| Split Table | Parent | Split GB/mo | Plan |')
            [void]$mdSb.AppendLine('| --- | --- | ---: | --- |')
            foreach ($t in $splitTables) {
                $plan = if ($t.TablePlan) { $t.TablePlan } else { 'Data Lake' }
                [void]$mdSb.AppendLine("| $($t.TableName) | $($t.ParentTable) | $($t.MonthlyGB) | $plan |")
            }
            [void]$mdSb.AppendLine('')
        }

        if ($tablesWithTransforms.Count -gt 0 -and $transforms -and $transforms.Transforms.Count -gt 0) {
            [void]$mdSb.AppendLine('### DCR Transforms')
            [void]$mdSb.AppendLine('')
            [void]$mdSb.AppendLine('| Table | Type | KQL |')
            [void]$mdSb.AppendLine('| --- | --- | --- |')
            foreach ($tr in $transforms.Transforms) {
                $kqlPreview = $tr.TransformKql -replace '\r?\n', ' ' -replace '\s+', ' '
                $kqlPreview = $kqlPreview -replace '\|', '&#124;'
                [void]$mdSb.AppendLine("| $($tr.OutputTable) | $($tr.TransformType) | <code>$kqlPreview</code> |")
            }
            [void]$mdSb.AppendLine('')
        }

        $htmlSb = [System.Text.StringBuilder]::new()

        if ($splitTables.Count -gt 0) {
            [void]$htmlSb.AppendLine('            <h3>Split Tables</h3>')
            [void]$htmlSb.AppendLine('            <div class="table-wrap"><table>')
            [void]$htmlSb.AppendLine('                <thead><tr><th>Split Table</th><th>Parent</th><th>Split GB/mo</th><th>Plan</th></tr></thead>')
            [void]$htmlSb.AppendLine('                <tbody>')
            foreach ($t in $splitTables) {
                $plan = if ($t.TablePlan) { hEnc $t.TablePlan } else { 'Data Lake' }
                [void]$htmlSb.AppendLine("                <tr><td>$(hEnc $t.TableName)</td><td>$(hEnc $t.ParentTable)</td><td class=`"num`">$($t.MonthlyGB)</td><td>$plan</td></tr>")
            }
            [void]$htmlSb.AppendLine('                </tbody></table></div>')
        }

        if ($tablesWithTransforms.Count -gt 0 -and $transforms -and $transforms.Transforms.Count -gt 0) {
            [void]$htmlSb.AppendLine('            <h3>DCR Transforms</h3>')
            [void]$htmlSb.AppendLine('            <div class="table-wrap"><table>')
            [void]$htmlSb.AppendLine('                <thead><tr><th>Table</th><th>Type</th><th>KQL</th></tr></thead>')
            [void]$htmlSb.AppendLine('                <tbody>')
            foreach ($tr in $transforms.Transforms) {
                [void]$htmlSb.AppendLine("                <tr><td>$(hEnc $tr.OutputTable)</td><td>$(hEnc $tr.TransformType)</td><td><code class=`"kql`">$(hEnc $tr.TransformKql)</code></td></tr>")
            }
            [void]$htmlSb.AppendLine('                </tbody></table></div>')
        }

        $sections.Add([PSCustomObject]@{ Title = 'Transforms'; TabId = 'transforms'; Markdown = $mdSb.ToString(); Html = $htmlSb.ToString() })
    }

    # ── 7. Split KQL Suggestions ──
    $splitRecs = @($Analysis.Recommendations | Where-Object { $_.Type -eq 'SplitCandidate' -and $_.SplitSuggestion -and $_.SplitSuggestion.Source -ne 'none' })

    if ($splitRecs.Count -gt 0) {
        $mdSb = [System.Text.StringBuilder]::new()
        [void]$mdSb.AppendLine('## Split KQL Suggestions')
        [void]$mdSb.AppendLine('')

        foreach ($rec in $splitRecs) {
            $ss = $rec.SplitSuggestion
            [void]$mdSb.AppendLine("### $($rec.TableName)")
            [void]$mdSb.AppendLine('')
            [void]$mdSb.AppendLine("**Source:** $($ss.Source) | **Rules:** $($ss.RuleCount) | **Est. Savings:** `$$($rec.EstSavingsUSD)/mo  ")
            [void]$mdSb.AppendLine('')
            if ($ss.SplitKql) {
                [void]$mdSb.AppendLine('**Split KQL:**')
                [void]$mdSb.AppendLine('```kql')
                [void]$mdSb.AppendLine($ss.SplitKql)
                [void]$mdSb.AppendLine('```')
                [void]$mdSb.AppendLine('')
            }
            if ($ss.ProjectKql) {
                [void]$mdSb.AppendLine('**Projection KQL:**')
                [void]$mdSb.AppendLine('```kql')
                [void]$mdSb.AppendLine($ss.ProjectKql)
                [void]$mdSb.AppendLine('```')
                [void]$mdSb.AppendLine('')
            }
        }

        $htmlSb = [System.Text.StringBuilder]::new()
        [void]$htmlSb.AppendLine('            <p>Ready-to-use split KQL statements for high-volume primary tables.</p>')
        foreach ($rec in $splitRecs) {
            $ss = $rec.SplitSuggestion
            [void]$htmlSb.AppendLine("            <article class=`"rec-card`">")
            [void]$htmlSb.AppendLine("                <div class=`"rec-header`"><strong>$(hEnc $rec.TableName)</strong> <span class=`"badge`">$($ss.Source)</span> <span class=`"badge badge-savings`">Saves `$$($rec.EstSavingsUSD)/mo</span></div>")
            if ($ss.SplitKql) {
                [void]$htmlSb.AppendLine("                <p><strong>Split KQL:</strong></p>")
                [void]$htmlSb.AppendLine("                <pre class=`"kql-block`">$(hEnc $ss.SplitKql)</pre>")
            }
            if ($ss.ProjectKql) {
                [void]$htmlSb.AppendLine("                <p><strong>Projection KQL:</strong></p>")
                [void]$htmlSb.AppendLine("                <pre class=`"kql-block`">$(hEnc $ss.ProjectKql)</pre>")
            }
            [void]$htmlSb.AppendLine('            </article>')
        }

        $sections.Add([PSCustomObject]@{ Title = 'Split KQLs'; TabId = 'splitkql'; Markdown = $mdSb.ToString(); Html = $htmlSb.ToString() })
    }

    # ── 8. Correlation Rules ──
    $corrExcluded = $Analysis.CorrelationExcluded
    $corrIncluded = $Analysis.CorrelationIncluded
    if (($corrExcluded -and $corrExcluded.Count -gt 0) -or ($corrIncluded -and $corrIncluded.Count -gt 0)) {
        $mdSb = [System.Text.StringBuilder]::new()
        [void]$mdSb.AppendLine('## Correlation Rules')
        [void]$mdSb.AppendLine('')

        if ($corrExcluded -and $corrExcluded.Count -gt 0) {
            [void]$mdSb.AppendLine('### Excluded from Correlation')
            [void]$mdSb.AppendLine('')
            [void]$mdSb.AppendLine('| Rule | Kind | Tables |')
            [void]$mdSb.AppendLine('| --- | --- | --- |')
            foreach ($cr in $corrExcluded) {
                $tables = if ($cr.Tables) { ($cr.Tables -join ', ') } else { '-' }
                [void]$mdSb.AppendLine("| $(mdEsc $cr.RuleName) | $($cr.Kind) | $tables |")
            }
            [void]$mdSb.AppendLine('')
        }

        if ($corrIncluded -and $corrIncluded.Count -gt 0) {
            [void]$mdSb.AppendLine('### Included in Correlation')
            [void]$mdSb.AppendLine('')
            [void]$mdSb.AppendLine('| Rule | Kind | Tables |')
            [void]$mdSb.AppendLine('| --- | --- | --- |')
            foreach ($cr in $corrIncluded) {
                $tables = if ($cr.Tables) { ($cr.Tables -join ', ') } else { '-' }
                [void]$mdSb.AppendLine("| $(mdEsc $cr.RuleName) | $($cr.Kind) | $tables |")
            }
            [void]$mdSb.AppendLine('')
        }

        $htmlSb = [System.Text.StringBuilder]::new()

        if ($corrExcluded -and $corrExcluded.Count -gt 0) {
            [void]$htmlSb.AppendLine('            <h3>Excluded from Correlation</h3>')
            [void]$htmlSb.AppendLine('            <div class="table-wrap"><table>')
            [void]$htmlSb.AppendLine('                <thead><tr><th>Rule</th><th>Kind</th><th>Tables</th></tr></thead>')
            [void]$htmlSb.AppendLine('                <tbody>')
            foreach ($cr in $corrExcluded) {
                $tables = if ($cr.Tables) { hEnc ($cr.Tables -join ', ') } else { '-' }
                [void]$htmlSb.AppendLine("                <tr><td>$(hEnc $cr.RuleName)</td><td>$(hEnc $cr.Kind)</td><td>$tables</td></tr>")
            }
            [void]$htmlSb.AppendLine('                </tbody></table></div>')
        }

        if ($corrIncluded -and $corrIncluded.Count -gt 0) {
            [void]$htmlSb.AppendLine('            <h3>Included in Correlation</h3>')
            [void]$htmlSb.AppendLine('            <div class="table-wrap"><table>')
            [void]$htmlSb.AppendLine('                <thead><tr><th>Rule</th><th>Kind</th><th>Tables</th></tr></thead>')
            [void]$htmlSb.AppendLine('                <tbody>')
            foreach ($cr in $corrIncluded) {
                $tables = if ($cr.Tables) { hEnc ($cr.Tables -join ', ') } else { '-' }
                [void]$htmlSb.AppendLine("                <tr><td>$(hEnc $cr.RuleName)</td><td>$(hEnc $cr.Kind)</td><td>$tables</td></tr>")
            }
            [void]$htmlSb.AppendLine('                </tbody></table></div>')
        }

        $sections.Add([PSCustomObject]@{ Title = 'Correlation'; TabId = 'correlation'; Markdown = $mdSb.ToString(); Html = $htmlSb.ToString() })
    }

    # ── 9. Defender XDR (conditional) ──
    if ($DefenderXDR) {
        $mdSb = [System.Text.StringBuilder]::new()
        [void]$mdSb.AppendLine('## Defender XDR')
        [void]$mdSb.AppendLine('')
        [void]$mdSb.AppendLine("**Custom Detections:** $($DefenderXDR.TotalXDRRules) rules  ")

        $xdrStreaming = @($Analysis.TableAnalysis | Where-Object IsXDRStreaming)
        if ($xdrStreaming.Count -gt 0) {
            $streamingNames = ($xdrStreaming | ForEach-Object {
                $tierLabel = if ($_.XDRState -eq 'Auxiliary') { 'data lake' } else { $_.XDRState }
                "$($_.TableName) ($tierLabel)"
            }) -join ', '
            [void]$mdSb.AppendLine("**Streaming to Sentinel:** $streamingNames  ")
        }

        if ($Analysis.XdrChecker -and $Analysis.XdrChecker.Summary.NotStreamedCount -gt 0) {
            $notStreamedFindings = @($Analysis.XdrChecker.Findings | Where-Object Type -eq 'NotStreaming')
            $notStreamedNames = ($notStreamedFindings | ForEach-Object { $_.TableName }) -join ', '
            [void]$mdSb.AppendLine("**Not streaming (XDR default 30d):** $notStreamedNames  ")
        }
        [void]$mdSb.AppendLine('')

        $xdrRecs = @($Analysis.Recommendations | Where-Object Type -eq 'XDROptimize')
        if ($xdrRecs.Count -gt 0) {
            [void]$mdSb.AppendLine('### XDR Optimization Opportunities')
            [void]$mdSb.AppendLine('')
            foreach ($xr in $xdrRecs) {
                [void]$mdSb.AppendLine("- **$($xr.Title):** $($xr.Detail)")
            }
            [void]$mdSb.AppendLine('')
        }

        $htmlSb = [System.Text.StringBuilder]::new()
        [void]$htmlSb.AppendLine("            <p><strong>Custom Detections:</strong> $($DefenderXDR.TotalXDRRules) rules</p>")
        if ($xdrStreaming.Count -gt 0) {
            [void]$htmlSb.AppendLine("            <p><strong>Streaming to Sentinel:</strong> $(hEnc $streamingNames)</p>")
        }
        if ($Analysis.XdrChecker -and $Analysis.XdrChecker.Summary.NotStreamedCount -gt 0) {
            [void]$htmlSb.AppendLine("            <p><strong>Not streaming (XDR default 30d):</strong> $(hEnc $notStreamedNames)</p>")
        }
        if ($xdrRecs.Count -gt 0) {
            [void]$htmlSb.AppendLine('            <h3>XDR Optimization Opportunities</h3>')
            [void]$htmlSb.AppendLine('            <ul>')
            foreach ($xr in $xdrRecs) {
                [void]$htmlSb.AppendLine("            <li><strong>$(hEnc $xr.Title):</strong> $(hEnc $xr.Detail)</li>")
            }
            [void]$htmlSb.AppendLine('            </ul>')
        }

        $sections.Add([PSCustomObject]@{ Title = 'Defender XDR'; TabId = 'xdr'; Markdown = $mdSb.ToString(); Html = $htmlSb.ToString() })
    }

    # ── 10. Detection Analyzer (conditional) ──
    if ($Analysis.DetectionAnalyzer -and $Analysis.DetectionAnalyzer.RuleMetrics.Count -gt 0) {
        $scored = @($Analysis.DetectionAnalyzer.RuleMetrics | Where-Object { $null -ne $_.NoisinessScore } | Sort-Object NoisinessScore -Descending)
        $unscored = @($Analysis.DetectionAnalyzer.RuleMetrics | Where-Object { $null -eq $_.NoisinessScore })
        $sortedMetrics = @($scored) + @($unscored)

        $mdSb = [System.Text.StringBuilder]::new()
        [void]$mdSb.AppendLine('## Detection Analyzer')
        [void]$mdSb.AppendLine('')
        [void]$mdSb.AppendLine("**Rules analyzed:** $($Analysis.DetectionAnalyzer.Summary.RulesAnalyzed)  ")
        [void]$mdSb.AppendLine("**Noisy rules (score >= 70):** $($Analysis.DetectionAnalyzer.Summary.NoisyRules)  ")
        [void]$mdSb.AppendLine("**Incidents analyzed:** $($Analysis.DetectionAnalyzer.Summary.IncidentsAnalyzed)  ")
        if ($Analysis.DetectionAnalyzer.Summary.CustomDetectionRules -gt 0) {
            [void]$mdSb.AppendLine("**Custom Detection Rules:** $($Analysis.DetectionAnalyzer.Summary.CustomDetectionRules) ($($Analysis.DetectionAnalyzer.Summary.CDRCorrelatedIncidents) with incidents)  ")
        }
        [void]$mdSb.AppendLine('')
        [void]$mdSb.AppendLine('| Rule | Kind | Incidents | AutoClose % | FalsePositive % | Noisiness Score |')
        [void]$mdSb.AppendLine('| --- | --- | ---: | ---: | ---: | ---: |')
        foreach ($r in ($sortedMetrics | Select-Object -First 25)) {
            $scoreStr = if ($null -eq $r.NoisinessScore) { 'N/A' } else { $r.NoisinessScore }
            [void]$mdSb.AppendLine("| $($r.RuleName) | $($r.RuleKind) | $($r.IncidentsTotal) | $([math]::Round($r.AutoCloseRatio * 100, 1)) | $([math]::Round($r.FalsePositiveRatio * 100, 1)) | $scoreStr |")
        }
        [void]$mdSb.AppendLine('')

        $htmlSb = [System.Text.StringBuilder]::new()
        [void]$htmlSb.AppendLine("            <p><strong>Rules analyzed:</strong> $($Analysis.DetectionAnalyzer.Summary.RulesAnalyzed)</p>")
        [void]$htmlSb.AppendLine("            <p><strong>Noisy rules:</strong> $($Analysis.DetectionAnalyzer.Summary.NoisyRules)</p>")
        if ($Analysis.DetectionAnalyzer.Summary.CustomDetectionRules -gt 0) {
            [void]$htmlSb.AppendLine("            <p><strong>Custom Detection Rules:</strong> $($Analysis.DetectionAnalyzer.Summary.CustomDetectionRules) ($($Analysis.DetectionAnalyzer.Summary.CDRCorrelatedIncidents) with incidents)</p>")
        }
        [void]$htmlSb.AppendLine('            <div class="table-wrap"><table>')
        [void]$htmlSb.AppendLine('                <thead><tr><th>Rule</th><th>Kind</th><th>Incidents</th><th>AutoClose %</th><th>FalsePositive %</th><th>Noisiness Score</th></tr></thead>')
        [void]$htmlSb.AppendLine('                <tbody>')
        foreach ($r in ($sortedMetrics | Select-Object -First 25)) {
            $scoreStr = if ($null -eq $r.NoisinessScore) { 'N/A' } else { $r.NoisinessScore }
            [void]$htmlSb.AppendLine("                <tr><td>$(hEnc $r.RuleName)</td><td>$(hEnc $r.RuleKind)</td><td class=`"num`">$($r.IncidentsTotal)</td><td class=`"num`">$([math]::Round($r.AutoCloseRatio * 100, 1))</td><td class=`"num`">$([math]::Round($r.FalsePositiveRatio * 100, 1))</td><td class=`"num`">$scoreStr</td></tr>")
        }
        [void]$htmlSb.AppendLine('                </tbody>')
        [void]$htmlSb.AppendLine('            </table></div>')

        $sections.Add([PSCustomObject]@{ Title = 'Detection Analyzer'; TabId = 'detanalyzer'; Markdown = $mdSb.ToString(); Html = $htmlSb.ToString() })
    }

    # ── 11. XDR Checker (conditional) ──
    if ($Analysis.XdrChecker -and $Analysis.XdrChecker.Findings.Count -gt 0) {
        $mdSb = [System.Text.StringBuilder]::new()
        [void]$mdSb.AppendLine('## XDR Checker')
        [void]$mdSb.AppendLine('')
        [void]$mdSb.AppendLine("**Advisory retention target:** $($Analysis.XdrChecker.Summary.AdvisoryRetentionDays) days (Data Lake)  ")
        [void]$mdSb.AppendLine('')
        [void]$mdSb.AppendLine('| Table | Type | Severity | Detail |')
        [void]$mdSb.AppendLine('| --- | --- | --- | --- |')
        foreach ($f in $Analysis.XdrChecker.Findings) {
            [void]$mdSb.AppendLine("| $($f.TableName) | $($f.Type) | $($f.Severity) | $($f.Detail) |")
        }
        [void]$mdSb.AppendLine('')

        $htmlSb = [System.Text.StringBuilder]::new()
        [void]$htmlSb.AppendLine("            <p><strong>Advisory retention target:</strong> $($Analysis.XdrChecker.Summary.AdvisoryRetentionDays) days in Data Lake for XDR-related logs.</p>")
        [void]$htmlSb.AppendLine('            <div class="table-wrap"><table>')
        [void]$htmlSb.AppendLine('                <thead><tr><th>Table</th><th>Type</th><th>Severity</th><th>Detail</th></tr></thead>')
        [void]$htmlSb.AppendLine('                <tbody>')
        foreach ($f in $Analysis.XdrChecker.Findings) {
            [void]$htmlSb.AppendLine("                <tr><td>$(hEnc $f.TableName)</td><td>$(hEnc $f.Type)</td><td>$(hEnc $f.Severity)</td><td>$(hEnc $f.Detail)</td></tr>")
        }
        [void]$htmlSb.AppendLine('                </tbody>')
        [void]$htmlSb.AppendLine('            </table></div>')

        $sections.Add([PSCustomObject]@{ Title = 'XDR Checker'; TabId = 'xdrchecker'; Markdown = $mdSb.ToString(); Html = $htmlSb.ToString() })
    }

    return $sections
}
