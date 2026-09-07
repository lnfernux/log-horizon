@{
    RootModule        = 'LogHorizon.psm1'
    ModuleVersion     = '0.9.0'
    GUID              = 'a3f7c8d1-4e2b-4f9a-b6c3-8d5e1f2a7b4c'
    Author            = 'infernux.no'
    Description       = 'Sentinel SIEM log source analyzer - classifies, scores, and optimizes log ingestion.'
    PowerShellVersion = '7.0'
    RequiredModules   = @(
        @{ ModuleName = 'PwshSpectreConsole'; ModuleVersion = '2.6.3' },
        'Az.Accounts'
    )
    FunctionsToExport = @('Invoke-LogHorizon', 'Set-LogHorizonTableRetention')
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Sentinel', 'SIEM', 'Security', 'Azure', 'LogAnalytics')
            ProjectUri = 'https://github.com/lnfernux/log-horizon'
            LicenseUri = 'https://www.gnu.org/licenses/gpl-3.0.html'
            ReleaseNotes = 'v0.9.0: plan-aware pricing from Usage.Plan and Usage.IsBillable; default-on collection cache (-NoCache, -RefreshCache, -CacheMaxAgeMinutes, -CachePath); DCR discovery at subscription scope with workspace transformation DCR and associations; classification database 481 tables with lifecycle status, XDR streamability and platform flags; DeprecatedSource and plan-aware Data Lake recommendations; severity-aware auto-close attribution; sovereign cloud endpoints; current API versions; Dictionary menu; Az.Resources dependency removed; GPL-3.0. Full history: https://github.com/lnfernux/log-horizon#version-history'
        }
    }
}
