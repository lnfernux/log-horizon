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

        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [Alias('clf')]
        [string]$CustomClassificationPath
    )

    $ErrorActionPreference = 'Stop'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    # Phase 1 - Data collection
    $collectResult = Invoke-SpectreCommandWithStatus -Title "[deepskyblue1]Collecting data...[/]" -Spinner Dots -ScriptBlock {
        $result = [ordered]@{}

        # Connect
        $ctx = Connect-Sentinel -SubscriptionId $SubscriptionId `
                                -ResourceGroup $ResourceGroup `
                                -WorkspaceName $WorkspaceName `
                                -WorkspaceId $WorkspaceId
        $result.Context = $ctx

        # Table usage
        $result.TableUsage = Get-TableUsage -Context $ctx -DaysBack $DaysBack -PricePerGB $PricePerGB

        # Analytics rules
        $result.RulesData = Get-AnalyticsRules -Context $ctx

        # Hunting queries
        $result.HuntingData = Get-HuntingQueries -Context $ctx

        # Data connectors
        $result.Connectors = Get-DataConnectors -Context $ctx

        # Defender XDR (optional)
        $result.DefenderXDR = $null
        if ($IncludeDefenderXDR) {
            try { $result.DefenderXDR = Get-DefenderXDR -Context $ctx } catch { }
        }

        # Detection analyzer inputs (optional)
        $result.Incidents = @()
        $result.AutomationRules = @()
        $result.AutoCloseHealth = $null
        if ($IncludeDetectionAnalyzer) {
            try { $result.Incidents = Get-Incidents -Context $ctx -DaysBack $DetectionLookbackDays } catch { }
            try { $result.AutomationRules = Get-AutomationRules -Context $ctx } catch { }
            try {
                $result.AutoCloseHealth = Get-AutoCloseFromHealth -Context $ctx -DaysBack $DetectionLookbackDays
            } catch { }
        }

        # SOC Optimization
        $result.SocRecs = Get-SocOptimization -Context $ctx

        # Table retention configuration
        $result.TableRetention = Get-TableRetention -Context $ctx

        # Data transforms (DCR-based)
        $result.DataTransforms = Get-DataTransforms -Context $ctx

        [PSCustomObject]$result
    }

    $ctx         = $collectResult.Context
    $tableUsage  = $collectResult.TableUsage
    $rulesData   = $collectResult.RulesData
    $huntingData = $collectResult.HuntingData
    $defenderXDR = $collectResult.DefenderXDR
    $socRecs     = $collectResult.SocRecs
    $tableRetentionResult = $collectResult.TableRetention
    $tableRetention = $tableRetentionResult.Tables
    $workspaceRetentionDays = $tableRetentionResult.WorkspaceRetentionDays
    $dataTransforms = $collectResult.DataTransforms
    $incidents = $collectResult.Incidents
    $automationRules = $collectResult.AutomationRules
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
            if (-not $OutputPath) {
                $OutputPath = $PWD.Path
            }
            Write-SpectreHost "[deepskyblue1]Non-interactive mode: exporting directly to $OutputPath[/]"
            Export-Report -Analysis $analysis `
                          -Format $Output `
                          -OutputPath $OutputPath `
                          -WorkspaceName $ctx.WorkspaceName `
                          -DefenderXDR $defenderXDR
        } else {
            Write-Warning "NonInteractive switch was provided but -Output was omitted. Returning data to pipeline."
            $analysis
        }
    } else {
        Write-Report -Analysis $analysis `
                     -WorkspaceName $ctx.WorkspaceName `
                     -DefenderXDR $defenderXDR `
                     -ExportFormat $Output `
                     -ExportPath $OutputPath
    }

    # Phase 5 - Cleanup
    if ($null -ne $ctx) {
        $ctx.ArmToken = $null
        $ctx.LaToken = $null
    }
}
