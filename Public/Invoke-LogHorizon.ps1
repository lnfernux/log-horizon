function Invoke-LogHorizon {
    <#
    .SYNOPSIS
        Log Horizon - Sentinel SIEM log source analyser.

        Connects to a Microsoft Sentinel workspace, classifies every ingesting
        log source as primary or secondary security data, evaluates cost vs.
        detection value, and produces actionable optimisation recommendations.

        Optionally connects to Defender XDR via Graph.

    .EXAMPLE
        Invoke-LogHorizon -SubscriptionId '00000000-...' -ResourceGroup 'rg-sentinel' -WorkspaceName 'my-sentinel-ws'

    .EXAMPLE
        Invoke-LogHorizon -SubscriptionId '...' -ResourceGroup 'rg' -WorkspaceName 'ws' -Keywords 'CrowdStrike','AWS' -IncludeDefenderXDR

    .EXAMPLE
        Invoke-LogHorizon -SubscriptionId '...' -ResourceGroup 'rg' -WorkspaceName 'ws' -Output json -OutputPath ./report.json -PricePerGB 4.61
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Parameters are captured and used inside nested status scriptblocks.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, HelpMessage = 'Azure subscription ID')]
        [string]$SubscriptionId,

        [Parameter(Mandatory, HelpMessage = 'Resource group containing the Sentinel workspace')]
        [string]$ResourceGroup,

        [Parameter(Mandatory, HelpMessage = 'Log Analytics workspace name')]
        [string]$WorkspaceName,

        [string]$WorkspaceId,

        [ValidateSet('json', 'markdown', 'md', 'html')]
        [Alias('o')]
        [string]$Output,

        [string]$OutputPath,

        [switch]$NonInteractive,

        [Alias('kw')]
        [string[]]$Keywords,

        [switch]$IncludeDefenderXDR,

        [switch]$IncludeDetectionAnalyzer,

        [ValidateRange(1, 365)]
        [int]$DetectionLookbackDays = 90,

        [ValidateRange(1, 365)]
        [int]$DaysBack = 90,

        [Alias('ppgb')]
        [ValidateRange(0.01, 100)]
        [decimal]$PricePerGB = 5.59,

        [ValidateRange(0.01, 100)]
        [decimal]$BasicPricePerGB = 1.15,

        [ValidateRange(0.01, 100)]
        [decimal]$LakePricePerGB = 0.20,

        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [Alias('clf')]
        [string]$CustomClassificationPath,

        [switch]$NoCache,

        [switch]$RefreshCache,

        [ValidateRange(1, 10080)]
        [int]$CacheMaxAgeMinutes = 60,

        [string]$CachePath
    )

    $ErrorActionPreference = 'Stop'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $moduleVersion = (Import-PowerShellDataFile "$PSScriptRoot\..\LogHorizon.psd1").ModuleVersion

    # Resolve the export target up front so a bad path fails before the collection runs
    $resolvedOutputPath = $null
    if ($Output) {
        if (-not $OutputPath) { $OutputPath = $PWD.Path }
        $resolvedOutputPath = Resolve-ReportOutputPath -OutputPath $OutputPath -Format $Output
    }

    # Phase 0 - Authentication and workspace resolution (outside the spinner so prompts stay visible)
    $ctx = Connect-Sentinel -SubscriptionId $SubscriptionId `
                            -ResourceGroup $ResourceGroup `
                            -WorkspaceName $WorkspaceName `
                            -WorkspaceId $WorkspaceId

    try {
        $cacheKey = Get-CollectionCacheKey -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -WorkspaceName $WorkspaceName `
                                           -DaysBack $DaysBack -DetectionLookbackDays $DetectionLookbackDays `
                                           -IncludeDefenderXDR ([bool]$IncludeDefenderXDR) -IncludeDetectionAnalyzer ([bool]$IncludeDetectionAnalyzer) `
                                           -PricePerGB $PricePerGB -BasicPricePerGB $BasicPricePerGB -LakePricePerGB $LakePricePerGB `
                                           -ModuleVersion $moduleVersion
        $collectResult = $null
        $collectWarnings = [System.Collections.Generic.List[string]]::new()

        if (-not $NoCache -and -not $RefreshCache) {
            $cached = Get-CollectionCache -Key $cacheKey -CachePath $CachePath -MaxAgeMinutes $CacheMaxAgeMinutes
            if ($cached) {
                $collectResult = $cached.Data
                Write-SpectreHost "[deepskyblue1]Using cached collection from $($cached.AgeMinutes) minute(s) ago ($(Get-SafeEscapedText $cached.Path)). Use -RefreshCache to collect again or -NoCache to bypass.[/]"
            }
        }

        if (-not $collectResult) {
            # Defender XDR first: it may need an interactive Graph sign-in
            $defenderXDRResult = $null
            if ($IncludeDefenderXDR) {
                try { $defenderXDRResult = Get-DefenderXDR -Context $ctx 3>&1 | ForEach-Object { if ($_ -is [System.Management.Automation.WarningRecord]) { $collectWarnings.Add($_.Message) } else { $_ } } }
                catch { $collectWarnings.Add("Defender XDR analysis skipped: $($_.Exception.Message)") }
            }

            # Phase 1 - Data collection
            $spinnerOutput = try {
                Invoke-SpectreCommandWithStatus -Title "[deepskyblue1]Collecting data...[/]" -Spinner Dots -ScriptBlock {
                    $result = [ordered]@{}
                    $result.DefenderXDR = $defenderXDRResult

                    # Table usage
                    $result.TableUsage = Get-TableUsage -Context $ctx -DaysBack $DaysBack -PricePerGB $PricePerGB `
                                                        -BasicPricePerGB $BasicPricePerGB -LakePricePerGB $LakePricePerGB

                    # Analytics rules
                    $result.RulesData = Get-AnalyticsRules -Context $ctx

                    # Hunting queries
                    $result.HuntingData = Get-HuntingQueries -Context $ctx

                    # Data connectors
                    $result.Connectors = Get-DataConnectors -Context $ctx

                    # Detection analyzer inputs (optional)
                    $result.Incidents = @()
                    $result.AutomationRules = @()
                    $result.AutoCloseHealth = $null
                    if ($IncludeDetectionAnalyzer) {
                        try { $result.Incidents = Get-Incidents -Context $ctx -DaysBack $DetectionLookbackDays } catch { Write-Warning "Detection Analyzer: could not fetch incidents: $($_.Exception.Message)" }
                        try { $result.AutomationRules = Get-AutomationRules -Context $ctx } catch { Write-Warning "Detection Analyzer: could not fetch automation rules: $($_.Exception.Message)" }
                        try {
                            $closeRuleNames = @($result.AutomationRules | Where-Object { $_.Enabled -and ($_.IsCloseIncidentRule -or $_.HasPlaybookAction) } | ForEach-Object DisplayName)
                            $result.AutoCloseHealth = Get-AutoCloseFromHealth -Context $ctx -DaysBack $DetectionLookbackDays -CloseRuleNames $closeRuleNames
                        } catch { Write-Warning "Detection Analyzer: SentinelHealth auto-close lookup failed: $($_.Exception.Message)" }
                    }

                    # SOC Optimization
                    $result.SocRecs = Get-SocOptimization -Context $ctx

                    # Table retention configuration
                    $result.TableRetention = Get-TableRetention -Context $ctx

                    # Data transforms (DCR-based); the workspace transformation DCR id comes from the workspace resource
                    $result.DataTransforms = Get-DataTransforms -Context $ctx -WorkspaceDefaultDcrId $result.TableRetention.WorkspaceDefaultDcrId

                    [PSCustomObject]$result
                } 3>&1
            }
            catch {
                # The status host wraps scriptblock errors in MethodInvocationException; surface the real one
                $inner = $_.Exception
                while ($inner -is [System.Management.Automation.MethodInvocationException] -and $inner.InnerException) { $inner = $inner.InnerException }
                throw $inner
            }

            foreach ($item in @($spinnerOutput)) {
                if ($item -is [System.Management.Automation.WarningRecord]) { $collectWarnings.Add($item.Message) }
                elseif ($null -ne $item -and $item.PSObject.Properties.Name -contains 'TableUsage') { $collectResult = $item }
                elseif ($null -ne $item) { Write-Verbose "Ignoring stray collector output of type $($item.GetType().Name)." }
            }
            if (-not $collectResult) { throw 'Data collection produced no result object; see warnings above.' }

            if (-not $NoCache) {
                try {
                    $savedTo = Save-CollectionCache -Key $cacheKey -Data $collectResult -CachePath $CachePath -Version $moduleVersion -MaxAgeMinutes $CacheMaxAgeMinutes
                    Write-Verbose "Collection cached to $savedTo"
                }
                catch { $collectWarnings.Add("Could not write collection cache: $($_.Exception.Message)") }
            }
        }

        foreach ($w in $collectWarnings) {
            Write-SpectreHost "[yellow]Warning:[/] $(Get-SafeEscapedText $w)"
        }
        if ($collectWarnings.Count -gt 0) { Write-SpectreHost "" }

        $tableUsage  = $collectResult.TableUsage
        $rulesData   = $collectResult.RulesData
        $huntingData = $collectResult.HuntingData
        $defenderXDR = $collectResult.DefenderXDR
        $socRecs     = $collectResult.SocRecs
        $tableRetentionResult = $collectResult.TableRetention
        $tableRetention = $tableRetentionResult.Tables
        $workspaceRetentionDays = $tableRetentionResult.WorkspaceRetentionDays
        $dataTransforms = $collectResult.DataTransforms
        $incidents = @($collectResult.Incidents)
        $automationRules = @($collectResult.AutomationRules)
        $autoCloseHealth = $collectResult.AutoCloseHealth

        # Phase 2 - Classification
        $classifications = Invoke-SpectreCommandWithStatus -Title "[deepskyblue1]Classifying log sources...[/]" -Spinner Dots -ScriptBlock {
            Invoke-Classification -TableUsage $tableUsage `
                                  -RuleTableCoverage $rulesData.TableCoverage `
                                  -Keywords $Keywords `
                                  -CustomClassificationPath $CustomClassificationPath
        }

        # Load high-value-fields knowledge base
        $hvFieldsPath = Join-Path $PSScriptRoot '..\Data\high-value-fields.json'
        $highValueFields = @{}
        if (Test-Path $hvFieldsPath) {
            $hvRaw = Get-Content $hvFieldsPath -Raw | ConvertFrom-Json
            foreach ($prop in $hvRaw.PSObject.Properties) {
                $highValueFields[$prop.Name] = $prop.Value
            }
        }

        # Load field-frequency-stats knowledge base (generated by Build-FieldKnowledgeBase.ps1)
        $ffStatsPath = Join-Path $PSScriptRoot '..\Data\field-frequency-stats.json'
        $fieldFrequencyStats = @{}
        if (Test-Path $ffStatsPath) {
            $ffRaw = Get-Content $ffStatsPath -Raw | ConvertFrom-Json
            # Convert to hashtable for easy lookup
            $fieldFrequencyStats = @{
                universalFields  = @($ffRaw.universalFields)
                categoryDefaults = @{}
                perTable         = @{}
            }
            if ($ffRaw.categoryDefaults) {
                foreach ($prop in $ffRaw.categoryDefaults.PSObject.Properties) {
                    $fieldFrequencyStats.categoryDefaults[$prop.Name] = @($prop.Value)
                }
            }
            if ($ffRaw.perTable) {
                foreach ($prop in $ffRaw.perTable.PSObject.Properties) {
                    $fieldFrequencyStats.perTable[$prop.Name] = $prop.Value
                }
            }
        }

        # Phase 3 - Analysis
        $analysis = Invoke-SpectreCommandWithStatus -Title "[deepskyblue1]Computing cost-value analysis...[/]" -Spinner Dots -ScriptBlock {
            Invoke-Analysis -TableUsage $tableUsage `
                            -Classifications $classifications `
                            -RulesData $rulesData `
                            -HuntingData $huntingData `
                            -DefenderXDR $defenderXDR `
                            -SocRecommendations $socRecs `
                            -TableRetention $tableRetention `
                            -WorkspaceRetentionDays $workspaceRetentionDays `
                            -PricePerGB $PricePerGB `
                            -BasicPricePerGB $BasicPricePerGB `
                            -LakePricePerGB $LakePricePerGB `
                            -DataTransforms $dataTransforms `
                            -HighValueFields $highValueFields `
                            -FieldFrequencyStats $fieldFrequencyStats `
                            -Incidents $incidents `
                            -AutomationRules $automationRules `
                            -AutoCloseHealthData $autoCloseHealth `
                            -IncludeDetectionAnalyzer:$IncludeDetectionAnalyzer
        }

        $sw.Stop()
        Write-SpectreHost "[green]Analysis complete in $([math]::Round($sw.Elapsed.TotalSeconds, 1))s[/]"
        Write-SpectreHost ""

        # Phase 4 - Output
        if ($NonInteractive) {
            if ($Output) {
                Write-SpectreHost "[deepskyblue1]Non-interactive mode: exporting to $(Get-SafeEscapedText $resolvedOutputPath)[/]"
                $written = Export-Report -Analysis $analysis `
                              -Format $Output `
                              -OutputPath $resolvedOutputPath `
                              -WorkspaceName $ctx.WorkspaceName `
                              -DefenderXDR $defenderXDR
                Write-SpectreHost "[green]Report written to $(Get-SafeEscapedText "$written")[/]"
            } else {
                Write-Warning "NonInteractive switch was provided but -Output was omitted. Returning data to pipeline."
                $analysis
            }
        } else {
            Write-Report -Analysis $analysis `
                         -WorkspaceName $ctx.WorkspaceName `
                         -DefenderXDR $defenderXDR `
                         -ExportFormat $Output `
                         -ExportPath $(if ($resolvedOutputPath) { $resolvedOutputPath } else { $OutputPath }) `
                         -Context $ctx
        }
    }
    finally {
        # Phase 5 - Cleanup: tokens never outlive the run, even on error
        if ($null -ne $ctx) {
            $ctx.ArmToken = $null
            $ctx.LaToken = $null
        }
    }
}
