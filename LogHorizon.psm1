# LogHorizon module loader
# Ensure UTF-8 for Spectre.Console Unicode/emoji support and suppress the PwshSpectreConsole encoding warning.
# Console encodings cannot be set when there is no console (redirected stdin, some CI hosts), so never fail import over it.
$env:IgnoreSpectreEncoding = $true
try {
    $OutputEncoding = [System.Text.UTF8Encoding]::new()
    [console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
}
catch {
    Write-Verbose "Could not set UTF-8 console encoding: $($_.Exception.Message)"
}

# Dot-source all private and public functions

$Private = @(Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction Stop)
$Public  = @(Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1"  -ErrorAction Stop)

foreach ($file in @($Private + $Public)) {
    try {
        . $file.FullName
    }
    catch {
        throw "Failed to import $($file.FullName): $_"
    }
}

# Export public functions
Export-ModuleMember -Function $Public.BaseName
