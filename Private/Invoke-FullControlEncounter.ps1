function Invoke-FullControlEncounter {
    <#
    .SYNOPSIS
        Full Control Encounter wizard for building custom classification overrides.
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath = $PWD.Path,
        [switch]$IncludeDecisionSummary,
        [hashtable]$PresetAnswers,
        [array]$ClassificationDatabase
    )

    $db = if ($ClassificationDatabase) {
        $ClassificationDatabase
    } else {
        Get-FceClassificationDatabase
    }

    if ($db.Count -eq 0) {
        throw 'Unable to load classification database for Full Control Encounter.'
    }

    if (-not $PresetAnswers) {
        Write-FceBanner
    }

    $catalog = Get-FceCategoryCatalog
    $state = if ($PresetAnswers) {
        Get-FceStateFromPreset -Catalog $catalog -PresetAnswers $PresetAnswers
    } else {
        Start-FceInteractiveSelection -Catalog $catalog -Database $db
    }

    $rawOverrides = New-FceRawOverrides -Database $db -Catalog $catalog -State $state

    $applyPromotions = $true
    $promotionGroups = @($rawOverrides | Where-Object { $_.WouldPromote } | Group-Object WizardCategory)
    if ($promotionGroups.Count -gt 0 -and -not $PresetAnswers) {
        Show-FcePromotionReview -PromotionGroups $promotionGroups
        $applyPromotions = Read-FceYesNo -Prompt 'Apply these secondary-to-primary promotions?' -DefaultYes $true
    }

    $finalOverrides = ConvertTo-FceFinalOverrides -RawOverrides $rawOverrides -ApplyPromotions:$applyPromotions
    if ($finalOverrides.Count -eq 0) {
        throw 'No matching table classifications were generated. Rerun the wizard and broaden category or technology selection.'
    }

    $exportResult = Export-FceOverrides -Overrides $finalOverrides -OutputPath $OutputPath

    $summaryPath = $null
    if ($IncludeDecisionSummary) {
        $summaryPath = Export-FceDecisionSummary -OutputPath $OutputPath -State $state -RawOverrides $rawOverrides -FinalOverrides $finalOverrides -JsonPath $exportResult.Path -PromotionsApplied:$applyPromotions
    }

    $result = [PSCustomObject]@{
        JsonPath = $exportResult.Path
        JsonCount = $finalOverrides.Count
        SummaryPath = $summaryPath
        PromotionsProposed = @($rawOverrides | Where-Object { $_.WouldPromote }).Count
        PromotionsApplied = if ($applyPromotions) { @($rawOverrides | Where-Object { $_.WouldPromote }).Count } else { 0 }
    }

    if (-not $PresetAnswers) {
        $lines = @(
            "[bold]Full Control Encounter complete.[/]",
            "",
            "[bold]Custom classification JSON:[/] [deepskyblue1]$($result.JsonPath)[/]"
        )
        if ($summaryPath) {
            $lines += "[bold]Decision summary markdown:[/] [deepskyblue1]$summaryPath[/]"
        }
        $lines += ""
        $lines += "[bold]Next step:[/] Invoke-LogHorizon -SubscriptionId <id> -ResourceGroup <rg> -WorkspaceName <ws> -CustomClassificationPath `"$($result.JsonPath)`""

        ($lines -join "`n") | Format-SpectrePanel -Header "[dodgerblue2] FULL CONTROL ENCOUNTER [/]" -Border Rounded -Color DodgerBlue2
        Write-SpectreHost ""
    }

    $result
}

function Get-FceClassificationDatabase {
    $dbPath = Join-Path $PSScriptRoot '..\Data\log-classifications.json'
    if (-not (Test-Path $dbPath)) {
        return @()
    }

    @(Get-Content $dbPath -Raw | ConvertFrom-Json)
}

function Write-FceBanner {
    $art = @'
[deepskyblue1]
██╗      ██████╗  ██████╗                                                                                                                                                            
██║     ██╔═══██╗██╔════╝                                                                                                                                                            
██║     ██║   ██║██║  ███╗                                                                                                                                                           
██║     ██║   ██║██║   ██║                                                                                                                                                           
███████╗╚██████╔╝╚██████╔╝                                                                                                                                                           
╚══════╝ ╚═════╝  ╚═════╝                                                                                                                                                                                                                                                                                                                                            
██╗  ██╗ ██████╗ ██████╗ ██╗███████╗ ██████╗ ███╗   ██╗                                                                                                                              
██║  ██║██╔═══██╗██╔══██╗██║╚══███╔╝██╔═══██╗████╗  ██║                                                                                                                              
███████║██║   ██║██████╔╝██║  ███╔╝ ██║   ██║██╔██╗ ██║                                                                                                                              
██╔══██║██║   ██║██╔══██╗██║ ███╔╝  ██║   ██║██║╚██╗██║                                                                                                                              
██║  ██║╚██████╔╝██║  ██║██║███████╗╚██████╔╝██║ ╚████║                                                                                                                              
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝ 

  __|      |  |     __|              |             |    __|                               |              
  _| |  |  |  |    (      _ \    \    _|   _| _ \  |    _|     \    _|   _ \  |  |    \    _|   -_)   _| 
 _| \_,_| _| _|   \___| \___/ _| _| \__| _| \___/ _|   ___| _| _| \__| \___/ \_,_| _| _| \__| \___| _|   
[/]
[dim]created by infernux.no[/]
'@

    Write-SpectreHost $art
    Write-SpectreHost ""
}

function Get-FceCategoryCatalog {
    $base = @(
        [PSCustomObject]@{ Key = 'identity'; Name = 'Identity and authentication'; Prompt = 'Do you have an identity provider tool, like Entra ID, Active Directory, or similar?'; DbCategories = @('Identity & Access') }
        [PSCustomObject]@{ Key = 'privilege'; Name = 'Privilege and role changes'; Prompt = 'Do you need visibility into role assignments, privilege changes, and administrative entitlements?'; DbCategories = @('Identity & Access', 'Cloud Control Plane', 'Configuration Management') }
        [PSCustomObject]@{ Key = 'admin'; Name = 'Administrative and control plane operations'; Prompt = 'Do you want control-plane and admin operation logs prioritized for detection and triage?'; DbCategories = @('Cloud Control Plane', 'Platform Health', 'Configuration Management') }
        [PSCustomObject]@{ Key = 'remote'; Name = 'Remote access and lateral movement signals'; Prompt = 'Do you rely on remote-access and lateral-movement signals for early compromise detection?'; DbCategories = @('Endpoint Detection', 'Endpoint Telemetry', 'Network Security') }
        [PSCustomObject]@{ Key = 'endpoint'; Name = 'Endpoint process execution'; Prompt = 'Do you use endpoint process telemetry for malware and script abuse detection?'; DbCategories = @('Endpoint Detection', 'Endpoint Telemetry', 'Vulnerability Management') }
        [PSCustomObject]@{ Key = 'network'; Name = 'Network security events'; Prompt = 'Do you ingest network security events (allow, deny, block, alert) for threat detection?'; DbCategories = @('Network Security', 'Network Flow') }
        [PSCustomObject]@{ Key = 'alerts'; Name = 'Security alerts and findings'; Prompt = 'Do you want security product alerts and findings treated as first-class primary signals?'; DbCategories = @('Security Alerts', 'Threat Intelligence', 'Cloud Security', 'Posture Management') }
        [PSCustomObject]@{ Key = 'dataaccess'; Name = 'Data access and audit trail'; Prompt = 'Do you need data access and audit trail coverage for triage, forensics, or compliance?'; DbCategories = @('Data Security', 'Storage Access', 'Data Platform', 'Cloud Control Plane') }
        [PSCustomObject]@{ Key = 'email'; Name = 'Email and collaboration activity'; Prompt = 'Do you monitor email and collaboration activity for phishing and abuse detection?'; DbCategories = @('Email Security') }
    )

    $toolCatalog = Get-FceToolCatalog

    $base | ForEach-Object {
        $category = $_
        $entry = $toolCatalog | Where-Object { $_.categoryKey -eq $category.Key } | Select-Object -First 1

        $topTools = if ($entry) { Convert-FceToolEntries -Entries $entry.top5Tools } else { @() }
        $otherTools = if ($entry) { Convert-FceToolEntries -Entries $entry.otherTools } else { @() }

        [PSCustomObject]@{
            Key = $category.Key
            Name = $category.Name
            Prompt = $category.Prompt
            DbCategories = $category.DbCategories
            TopTools = $topTools
            OtherTools = $otherTools
            Technologies = @($topTools + $otherTools)
        }
    }
}

function Get-FceToolCatalog {
    $catalogPath = Join-Path $PSScriptRoot '..\Data\fce-tool-catalog.json'
    if (-not (Test-Path $catalogPath -PathType Leaf)) {
        throw "Missing required tool catalog file: $catalogPath"
    }

    @(Get-Content $catalogPath -Raw | ConvertFrom-Json)
}

function Convert-FceToolEntries {
    param([array]$Entries)

    if (-not $Entries) {
        return @()
    }

    @($Entries | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.displayName
            Key = $_.normalizedKey
            Keywords = @($_.matchingKeywords)
            EvidenceType = $_.evidenceType
            EvidenceSourceName = $_.evidenceSourceName
            EvidenceSourceUrl = $_.evidenceSourceUrl
            EvidenceDate = $_.evidenceDate
            Confidence = $_.confidence
        }
    })
}

function Start-FceInteractiveSelection {
    param(
        [array]$Catalog,
        [array]$Database
    )

    $state = @{}
    $index = 0
    $total = $Catalog.Count

    Write-SpectreHost "[dim]Flow: answer category coverage, select tools, then mark business-critical tools.[/]"
    Write-SpectreHost ""

    foreach ($category in $Catalog) {
        $index++
        Set-FceCategorySelection -State $state -Category $category -Index $index -Total $total
    }

    Set-FceBusinessCriticalSelections -State $state -Catalog $Catalog

    Show-FceSelectionReview -State $state -Catalog $Catalog -Database $Database | Out-Null

    $state
}

function Set-FceCategorySelection {
    param(
        [hashtable]$State,
        [PSCustomObject]$Category,
        [int]$Index,
        [int]$Total
    )

    Write-SpectreRule -Title "[dodgerblue2]CATEGORY $Index/$Total[/]" -Color DodgerBlue2
    Write-SpectreHost "[bold]$($Category.Name)[/]"
    Write-SpectreHost "[dim]$($Category.Prompt)[/]"
    Write-SpectreHost ""

    $hasTools = Read-SpectreConfirm -Message "Do you have any tools in '$($Category.Name)'?" -DefaultAnswer 'y' -Color DodgerBlue2

    if (-not $hasTools) {
        $State[$Category.Key] = [PSCustomObject]@{
            Enabled = $false
            Technologies = @()
            IsBusinessCritical = $false
        }
        Write-SpectreHost "[dim]Skipped category '$($Category.Name)'.[/]"
        Write-SpectreHost ""
        return
    }

    $selectedTech = Read-FceTechnologySelection -Category $Category

    if (-not $selectedTech -or $selectedTech.Count -eq 0) {
        $State[$Category.Key] = [PSCustomObject]@{
            Enabled = $false
            Technologies = @()
            IsBusinessCritical = $false
        }
        Write-SpectreHost "[dim]No tools selected. Category '$($Category.Name)' set to skipped.[/]"
        Write-SpectreHost ""
        return
    }

    $State[$Category.Key] = [PSCustomObject]@{
        Enabled = $true
        Technologies = $selectedTech
        CriticalTechnologies = @()
        IsBusinessCritical = $false
    }

    $summaryText = @(
        "[bold]Captured:[/] $($Category.Name)",
        "[bold]Technologies:[/] $((@($selectedTech) -join ', '))"
    ) -join "`n"
    $summaryText | Format-SpectrePanel -Header "[dodgerblue2] SELECTION SAVED [/]" -Border Rounded -Color DodgerBlue2
    Write-SpectreHost ""
}

function Set-FceBusinessCriticalSelections {
    param(
        [hashtable]$State,
        [array]$Catalog
    )

    $selectedTools = New-Object System.Collections.Generic.List[object]

    foreach ($category in $Catalog) {
        $entry = $State[$category.Key]
        if ($null -eq $entry -or -not $entry.Enabled) {
            continue
        }

        foreach ($toolName in @($entry.Technologies)) {
            $selectedTools.Add([PSCustomObject]@{
                CategoryKey = $category.Key
                CategoryName = $category.Name
                ToolName = $toolName
                Label = "$toolName ($($category.Name))"
            })
        }
    }

    if ($selectedTools.Count -eq 0) {
        return
    }

    Write-SpectreRule -Title '[dodgerblue2]BUSINESS CRITICALITY[/]' -Color DodgerBlue2
    $hasCriticalTools = Read-SpectreConfirm -Message 'Are any of the tools you selected business-critical?' -DefaultAnswer 'n' -Color DodgerBlue2
    if (-not $hasCriticalTools) {
        return
    }

    $criticalSelections = Read-SpectreMultiSelection -Message 'Select the business-critical tools' -Choices @($selectedTools) -ChoiceLabelProperty Label -Color DodgerBlue2 -PageSize 10 -AllowEmpty

    $criticalLookup = @{}
    foreach ($tool in @($criticalSelections)) {
        if (-not $criticalLookup.ContainsKey($tool.CategoryKey)) {
            $criticalLookup[$tool.CategoryKey] = New-Object System.Collections.Generic.List[string]
        }
        $criticalLookup[$tool.CategoryKey].Add($tool.ToolName)
    }

    foreach ($category in $Catalog) {
        $entry = $State[$category.Key]
        if ($null -eq $entry -or -not $entry.Enabled) {
            continue
        }

        $criticalTools = if ($criticalLookup.ContainsKey($category.Key)) {
            @($criticalLookup[$category.Key] | Select-Object -Unique)
        } else {
            @()
        }

        $entry.CriticalTechnologies = $criticalTools
        $entry.IsBusinessCritical = ($criticalTools.Count -gt 0)
    }
}

function Show-FceSelectionReview {
    param(
        [hashtable]$State,
        [array]$Catalog,
        [array]$Database
    )

    $rows = @()
    $estimatedMatches = 0
    $promotionCandidates = 0

    foreach ($category in $Catalog) {
        $entry = $State[$category.Key]
        $enabled = ($null -ne $entry -and $entry.Enabled)
        $techText = if ($enabled) { (@($entry.Technologies) -join ', ') } else { '-' }
        $criticalText = if ($enabled -and $entry.IsBusinessCritical) { (@($entry.CriticalTechnologies) -join ', ') } else { '-' }

        if ($enabled) {
            $source = @($Database | Where-Object { $_.category -in $category.DbCategories })
            $selectedTechObjects = @($category.Technologies | Where-Object { $_.Name -in $entry.Technologies })
            if ($selectedTechObjects.Count -gt 0) {
                $source = @($source | Where-Object { Test-FceEntryMatchesTechnology -Entry $_ -Technologies $selectedTechObjects })
            }

            $estimatedMatches += $source.Count
            if ($entry.IsBusinessCritical) {
                $promotionCandidates += @($source | Where-Object { $_.classification -eq 'secondary' }).Count
            }
        }

        $rows += [PSCustomObject]@{
            Category = $category.Name
            Enabled = if ($enabled) { 'yes' } else { 'no' }
            BusinessCritical = $criticalText
            Technologies = $techText
        }
    }

    Write-SpectreRule -Title '[dodgerblue2]REVIEW[/]' -Color DodgerBlue2
    $rows | Format-SpectreTable -Border Rounded -Color DeepSkyBlue1 -HeaderColor DodgerBlue2

    $summary = @(
        "[bold]Enabled categories:[/] $(@($rows | Where-Object { $_.Enabled -eq 'yes' }).Count)",
        "[bold]Estimated matching tables:[/] $estimatedMatches",
        "[bold]Estimated promotion candidates:[/] $promotionCandidates"
    ) -join "`n"
    $summary | Format-SpectrePanel -Header '[dodgerblue2] PREVIEW [/]' -Border Rounded -Color DodgerBlue2

    [PSCustomObject]@{ Action = 'continue' }
}

function Get-FceStateFromPreset {
    param(
        [array]$Catalog,
        [hashtable]$PresetAnswers
    )

    $state = @{}
    foreach ($category in $Catalog) {
        if (-not $PresetAnswers.ContainsKey($category.Key)) {
            $state[$category.Key] = [PSCustomObject]@{ Enabled = $false; Technologies = @(); IsBusinessCritical = $false }
            continue
        }

        $entry = $PresetAnswers[$category.Key]
        $state[$category.Key] = [PSCustomObject]@{
            Enabled = [bool]$entry.Enabled
            Technologies = @($entry.Technologies)
            CriticalTechnologies = @($entry.CriticalTechnologies)
            IsBusinessCritical = [bool]$entry.IsBusinessCritical
        }
    }

    $state
}

function Read-FceYesNo {
    param(
        [string]$Prompt,
        [bool]$DefaultYes = $true
    )

    $choices = if ($DefaultYes) { @('Yes', 'No') } else { @('No', 'Yes') }
    $choice = Read-SpectreSelection -Title "$Prompt" -Choices $choices -Color DodgerBlue2
    $choice -eq 'Yes'
}

function Read-FceTechnologySelection {
    param([PSCustomObject]$Category)

    Write-SpectreHost "[dim]Technology selection for $($Category.Name).[/]"
    $selected = New-Object System.Collections.Generic.List[string]

    $topTools = @(Get-FceTopToolSet -Category $Category)
    if ($topTools.Count -eq 0) {
        return @()
    }

    Write-SpectreHost "[bold]Top 10 technologies for '$($Category.Name)'[/]"
    $topSelected = @(Select-FceTools -Title "Select one or more Top 10 tools for '$($Category.Name)'" -Tools $topTools)
    foreach ($item in $topSelected) {
        $selected.Add($item)
    }

    $addFromFullList = Read-SpectreConfirm -Message "Do you want to add technologies from the full list for '$($Category.Name)'?" -DefaultAnswer 'n' -Color DodgerBlue2
    if ($addFromFullList) {
        $fullTools = @(Get-FceFullToolSet -Category $Category | Where-Object { $_.Name -notin $selected })
        if ($fullTools.Count -gt 0) {
            $fullSelected = @(Select-FceTools -Title "Select additional tools from full list for '$($Category.Name)'" -Tools $fullTools)
            foreach ($item in $fullSelected) {
                $selected.Add($item)
            }
        }
    }

    @($selected | Select-Object -Unique)
}

function Select-FceTools {
    param(
        [string]$Title,
        [array]$Tools
    )

    if (-not $Tools -or $Tools.Count -eq 0) {
        return @()
    }

    $selected = Read-SpectreMultiSelection -Message $Title -Choices @($Tools) -ChoiceLabelProperty {
        if ($_.Confidence) {
            "$($_.Name) (confidence: $($_.Confidence))"
        } else {
            $_.Name
        }
    } -Color DodgerBlue2 -PageSize 10 -AllowEmpty

    @($selected.Name | Select-Object -Unique)
}

function Get-FceTopToolSet {
    param([PSCustomObject]$Category)

    @((@($Category.TopTools) + @($Category.OtherTools)) | Select-Object -First 10)
}

function Get-FceFullToolSet {
    param([PSCustomObject]$Category)

    @((@($Category.TopTools) + @($Category.OtherTools)) | Sort-Object Name -Unique)
}

function New-FceRawOverrides {
    param(
        [array]$Database,
        [array]$Catalog,
        [hashtable]$State
    )

    $overrides = @()

    foreach ($category in $Catalog) {
        $choice = $State[$category.Key]
        if (-not $choice -or -not $choice.Enabled) {
            continue
        }

        $source = $Database | Where-Object { $_.category -in $category.DbCategories }
        if ($source.Count -eq 0) {
            continue
        }

        $selectedTechObjects = @($category.Technologies | Where-Object { $_.Name -in $choice.Technologies })
        if ($selectedTechObjects.Count -gt 0) {
            $source = @($source | Where-Object { Test-FceEntryMatchesTechnology -Entry $_ -Technologies $selectedTechObjects })
        }

        foreach ($entry in $source) {
            $wouldPromote = ($choice.IsBusinessCritical -and $entry.classification -eq 'secondary')
            $reasonParts = @(
                "FCE category: $($category.Name)",
                "technologies: $((@($choice.Technologies) -join ', '))"
            )
            if ($choice.IsBusinessCritical) {
                $reasonParts += 'business-critical: yes'
            } else {
                $reasonParts += 'business-critical: no'
            }

            $overrides += [PSCustomObject]@{
                tableName = $entry.tableName
                connector = $entry.connector
                category = $entry.category
                description = (($reasonParts -join ' | ') + ". Baseline: $($entry.classification).")
                keywords = @($entry.keywords)
                mitreSources = @($entry.mitreSources)
                isFree = [bool]$entry.isFree
                recommendedRetentionDays = if ($entry.recommendedRetentionDays) { [int]$entry.recommendedRetentionDays } else { 90 }
                baselineClassification = $entry.classification
                baselineTier = $entry.recommendedTier
                proposedClassification = if ($wouldPromote) { 'primary' } else { $entry.classification }
                proposedTier = if ($wouldPromote) { 'analytics' } else { $entry.recommendedTier }
                wouldPromote = $wouldPromote
                wizardCategory = $category.Name
            }
        }
    }

    @($overrides | Group-Object tableName | ForEach-Object {
        $_.Group | Sort-Object wouldPromote -Descending | Select-Object -First 1
    })
}

function Test-FceEntryMatchesTechnology {
    param(
        [PSCustomObject]$Entry,
        [array]$Technologies
    )

    if (-not $Technologies -or $Technologies.Count -eq 0) {
        return $true
    }

    $textParts = @($Entry.tableName, $Entry.connector, $Entry.description)
    if ($Entry.keywords) {
        $textParts += @($Entry.keywords)
    }
    $blob = ($textParts -join ' ').ToLowerInvariant()

    foreach ($tech in $Technologies) {
        foreach ($kw in @($tech.Keywords)) {
            if ([string]::IsNullOrWhiteSpace($kw)) { continue }
            if ($blob.Contains($kw.ToLowerInvariant())) {
                return $true
            }
        }
    }

    return $false
}

function Show-FcePromotionReview {
    param([array]$PromotionGroups)

    Write-SpectreHost ""
    Write-SpectreRule -Title "[dodgerblue2]PROMOTION REVIEW[/]" -Color DodgerBlue2
    $summaryLines = @(
        '[bold]Secondary to Primary Promotions (grouped by category)[/]',
        "[bold]Categories with promotions:[/] $($PromotionGroups.Count)",
        "[bold]Total promotions:[/] $((@($PromotionGroups | ForEach-Object { $_.Count }) | Measure-Object -Sum).Sum)"
    )
    ($summaryLines -join "`n") | Format-SpectrePanel -Header "[dodgerblue2] FCE [/]" -Border Rounded -Color DodgerBlue2

    foreach ($group in $PromotionGroups | Sort-Object Name) {
        $rows = @()
        foreach ($row in $group.Group | Sort-Object tableName | Select-Object -First 8) {
            $rows += [PSCustomObject]@{ Table = $row.tableName; Baseline = $row.baselineClassification; Proposed = $row.proposedClassification }
        }
        Write-SpectreHost ""
        Write-SpectreHost "[bold]$($group.Name)[/] [dim]($($group.Count) table(s))[/]"
        $rows | Format-SpectreTable -Border Rounded -Color DeepSkyBlue1 -HeaderColor DodgerBlue2
        if ($group.Count -gt 8) {
            Write-SpectreHost "[dim]... and $($group.Count - 8) more[/]"
        }
    }

    Write-SpectreHost ""
}

function ConvertTo-FceFinalOverrides {
    param(
        [array]$RawOverrides,
        [switch]$ApplyPromotions
    )

    $result = foreach ($row in $RawOverrides) {
        $isPromoted = ($ApplyPromotions -and $row.wouldPromote)
        [PSCustomObject]@{
            tableName = $row.tableName
            connector = $row.connector
            classification = if ($isPromoted) { 'primary' } else { $row.baselineClassification }
            category = $row.category
            description = if ($isPromoted) { $row.description + ' Promoted to primary due to business-critical selection.' } else { $row.description }
            keywords = @($row.keywords)
            mitreSources = @($row.mitreSources)
            recommendedTier = if ($isPromoted) { 'analytics' } else { $row.baselineTier }
            isFree = [bool]$row.isFree
            recommendedRetentionDays = [int]$row.recommendedRetentionDays
        }
    }

    @($result | Group-Object tableName | ForEach-Object { $_.Group | Select-Object -First 1 })
}

function Export-FceOverrides {
    param(
        [array]$Overrides,
        [string]$OutputPath
    )

    $targetDir = if ([string]::IsNullOrWhiteSpace($OutputPath)) { $PWD.Path } else { $OutputPath }
    if (-not (Test-Path $targetDir -PathType Container)) {
        New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
    }

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $path = Join-Path $targetDir "FullControlEncounter_CustomClassifications_$stamp.json"

    $Overrides | ConvertTo-Json -Depth 10 | Set-Content -Path $path -Encoding UTF8

    [PSCustomObject]@{
        Path = $path
        Count = $Overrides.Count
    }
}

function Export-FceDecisionSummary {
    param(
        [string]$OutputPath,
        [hashtable]$State,
        [array]$RawOverrides,
        [array]$FinalOverrides,
        [string]$JsonPath,
        [switch]$PromotionsApplied
    )

    $targetDir = if ([string]::IsNullOrWhiteSpace($OutputPath)) { $PWD.Path } else { $OutputPath }
    if (-not (Test-Path $targetDir -PathType Container)) {
        New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
    }

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $summaryPath = Join-Path $targetDir "FullControlEncounter_DecisionSummary_$stamp.md"

    $enabledKeys = @($State.GetEnumerator() | Where-Object { $_.Value.Enabled } | ForEach-Object { $_.Key })
    $proposedPromotions = @($RawOverrides | Where-Object { $_.WouldPromote }).Count
    $appliedPromotions = if ($PromotionsApplied) { $proposedPromotions } else { 0 }

    $lines = @(
        '# Full Control Encounter - Decision Summary',
        '',
        "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ssK')",
        "Custom classifications: $($FinalOverrides.Count)",
        "Promotion candidates: $proposedPromotions",
        "Promotions applied: $appliedPromotions",
        '',
        '## Selected categories',
        "- $($enabledKeys -join ', ')",
        '',
        '## Business-critical categories',
        "- $((@($State.GetEnumerator() | Where-Object { $_.Value.Enabled -and $_.Value.IsBusinessCritical } | ForEach-Object { $_.Key }) -join ', '))",
        '',
        '## Next step',
        ('- Invoke-LogHorizon -SubscriptionId <id> -ResourceGroup <rg> -WorkspaceName <ws> -CustomClassificationPath "' + $JsonPath + '"')
    )

    Set-Content -Path $summaryPath -Value ($lines -join "`n") -Encoding UTF8
    $summaryPath
}
