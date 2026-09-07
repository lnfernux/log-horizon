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
        }
    }
}
