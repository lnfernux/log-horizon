function Get-LogHorizonDictionary {
    <#
    .SYNOPSIS
        Loads Data/dictionary.json: the terms Log Horizon uses for classification,
        tiers, assessments, recommendations, plans, lifecycle status and transforms.
    .OUTPUTS
        PSCustomObject with Description and Sections (Name, Description, Terms[Term, Definition]).
        Sections is empty when the file is missing or unreadable.
    #>
    [CmdletBinding()]
    param([string]$Path = (Join-Path $PSScriptRoot '..\Data\dictionary.json'))

    $empty = [PSCustomObject]@{ Description = ''; Sections = @() }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-Verbose "Dictionary not found at $Path."
        return $empty
    }

    try { $raw = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json }
    catch {
        Write-Warning "Dictionary could not be read: $($_.Exception.Message)"
        return $empty
    }

    $sections = foreach ($s in @($raw.sections)) {
        if ([string]::IsNullOrWhiteSpace("$($s.name)")) { continue }
        $terms = @(@($s.terms) | Where-Object { -not [string]::IsNullOrWhiteSpace("$($_.term)") } | ForEach-Object {
            [PSCustomObject]@{ Term = "$($_.term)"; Definition = "$($_.definition)" }
        })
        [PSCustomObject]@{
            Name        = "$($s.name)"
            Description = "$($s.description)"
            Terms       = $terms
        }
    }

    [PSCustomObject]@{
        Description = "$($raw.description)"
        Sections    = @($sections)
    }
}
