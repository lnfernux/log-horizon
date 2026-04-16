@{
    RootModule        = 'LogHorizon.psm1'
    ModuleVersion     = '0.7.0'
    GUID              = 'a3f7c8d1-4e2b-4f9a-b6c3-8d5e1f2a7b4c'
    Author            = 'infernux.no'
    Description       = 'Sentinel SIEM log source analyzer - classifies, scores, and optimizes log ingestion.'
    PowerShellVersion = '7.0'
    RequiredModules   = @('PwshSpectreConsole', 'Az.Accounts', 'Az.Resources')
    FunctionsToExport = @('Invoke-LogHorizon')
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Sentinel', 'SIEM', 'Security', 'Azure', 'LogAnalytics')
            ProjectUri = 'https://github.com/log-horizon'
        }
    }
}
