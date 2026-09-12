# Log Horizon Copilot Instructions

## Repository Summary & Overview

Log Horizon is a PowerShell module (`LogHorizon`) and CLI tool for Microsoft Sentinel, Defender XDR and Azure Log Analytics. It analyzes log ingestion, classifies and scores table value against security detections (analytic rules, hunting queries, incidents, Defender XDR), evaluates pricing plans (Analytics, Basic, Auxiliary/Data Lake), detects transformations/DCRs, and generates interactive Spectre.Console TUI reports as well as JSON, CSV, and HTML exports.

- **Type**: PowerShell 7+ Module / Security CLI Tool
- **Primary Language**: PowerShell (v7.0+)
- **Target Runtimes**: PowerShell 7.0+ on Linux (Ubuntu), macOS, and Windows
- **License**: GNU General Public License v3.0 (GPL-3.0)
- **Size**: ~35 source/data files, comprehensive classification database (480+ tables), ~350KB test suite (437+ unit tests)

---

## Build, Test & Validation Commands

All commands should be run using PowerShell 7 (`pwsh`).

### 1. Bootstrap & Prerequisites
Always install required dependencies from PowerShell Gallery before running tests or loading the module:
```powershell
Set-PSRepository PSGallery -InstallationPolicy Trusted
Install-Module -Name Pester -RequiredVersion 5.7.1 -Force -SkipPublisherCheck -Scope CurrentUser
Install-Module -Name PwshSpectreConsole -RequiredVersion 2.6.3 -Force -SkipPublisherCheck -Scope CurrentUser
Install-Module -Name Az.Accounts -Force -SkipPublisherCheck -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Authentication -Force -SkipPublisherCheck -Scope CurrentUser
```

### 2. Module Manifest Validation
Validate manifest syntax and exports before testing:
```powershell
Test-ModuleManifest -Path ./LogHorizon.psd1 -ErrorAction Stop
```

### 3. Running Unit Tests (Pester)
Use Pester **5.7.x** (do not use legacy Pester 3.x or incompatible 6.x defaults without proper configuration):
```powershell
Import-Module Pester -RequiredVersion 5.7.1 -Force
Import-Module PwshSpectreConsole -RequiredVersion 2.6.3 -Force
Import-Module Az.Accounts -Force
Import-Module Microsoft.Graph.Authentication -Force

$config = New-PesterConfiguration
$config.Run.Path = './Tests/LogHorizon.Tests.ps1'
$config.Run.PassThru = $true
$config.Output.Verbosity = 'Detailed'

$result = Invoke-Pester -Configuration $config
if ($result.FailedCount -gt 0) {
    throw "Pester failed with $($result.FailedCount) failed test(s)"
}
```
*Note*: The full test suite runs in ~25-30 seconds and runs completely offline with mocks (no Azure connection or credentials required).

### 4. Local Module Import & Interactive Execution
```powershell
Import-Module ./LogHorizon.psd1 -Force
# Run interactive analysis against a connected Sentinel workspace:
Invoke-LogHorizon -WorkspaceName '<workspace>' -SubscriptionId '<subId>' -ResourceGroupName '<rg>'
```

---

## Project Layout & Architecture

```
log-horizon/
├── LogHorizon.psd1           # Module manifest (Version, dependencies, exports)
├── LogHorizon.psm1           # Module loader (dot-sources Private & Public functions)
├── Data/                     # Static classification datasets and HTML templates
│   ├── log-classifications.json         # 480+ Sentinel tables with tiers, categories, streamability
│   ├── basic-plan-tables.json           # Tables supported on Basic log plan
│   ├── auxiliary-plan-tables.json       # Tables supported on Auxiliary/Data Lake plan
│   ├── high-value-fields.json           # Key security detection fields per category
│   ├── field-frequency-stats.json       # Aggregated community field usage stats
│   ├── dictionary.json                  # In-app term dictionary definitions
│   └── ReportTemplate.html              # Standalone HTML report template
├── Private/                  # Internal helper and engine functions
│   ├── Connect-Sentinel.ps1             # Azure authentication & workspace discovery
│   ├── Invoke-Analysis.ps1              # Core evaluation engine (cost vs. detection score)
│   ├── Invoke-Classification.ps1        # Table categorization and metadata mapping
│   ├── Get-AnalyticsRules.ps1           # Sentinel scheduled/NRT/ML/threat intel analytic rules
│   ├── Get-HuntingQueries.ps1           # Log Analytics hunting queries extraction
│   ├── Get-DataTransforms.ps1           # DCR and workspace ingestion transformation discovery
│   ├── Get-DefenderXDR.ps1              # Defender XDR streamed table correlation
│   ├── Get-CollectionCache.ps1          # Cross-platform cache manager for workspace data
│   ├── Invoke-AzRestWithRetry.ps1       # Resilient REST API caller with exponential backoff
│   ├── Export-Report.ps1                # JSON, CSV, and HTML report exporters
│   └── Write-Report.ps1                 # Spectre.Console interactive TUI menus and charts
├── Public/                   # Exported user-facing cmdlets
│   ├── Invoke-LogHorizon.ps1            # Main interactive entry point cmdlet
│   └── Set-LogHorizonTableRetention.ps1 # Interactive table retention configuration cmdlet
├── Tests/
│   └── LogHorizon.Tests.ps1             # Comprehensive unit test suite
└── .github/
    ├── workflows/ci.yml      # CI workflow running on ubuntu-latest & windows-latest
    └── dependabot.yml        # Weekly GitHub Actions updates
```

---

## Coding Standards & Critical Guidelines

1. **Cross-Platform Path Compatibility**:
   - Never hardcode Windows drive letters (`C:\`) or backslashes (`\`) in paths.
   - Always use `Join-Path` or `[System.IO.Path]::Combine()` / `[System.IO.Path]::GetTempPath()`.
2. **REST API Versioning & Endpoints**:
   - Azure REST calls use modern ARM / Log Analytics / SecurityInsights API versions. Always route requests through `Invoke-AzRestWithRetry` and resolve sovereign endpoints via `Get-LogHorizonEndpoint`.
3. **No Secrets or Tenant Identifiers**:
   - Never hardcode tenant IDs, subscription IDs, workspace keys, or tokens.
   - The collection cache (`Get-CollectionCache.ps1`) deliberately excludes tokens and auth contexts before persisting to disk.
4. **Spectre.Console TUI Discipline**:
   - Wrap dynamic text rendered in markup with `Get-SafeEscapedText` (or escape `[` and `]`) to prevent markup parsing errors.
   - Set `$env:IgnoreSpectreEncoding = $true` to allow headless and CI execution without terminal encoding warnings.
5. **Testing Expectations**:
   - Every bug fix, new recommendation rule, or table classification change must be accompanied by matching Pester unit tests in `Tests/LogHorizon.Tests.ps1`.
   - Ensure all 437+ unit tests pass cleanly before submitting changes.

---

## Copilot Code Review & PR Verification Focus

When reviewing Pull Requests for this repository, prioritize:
- **Pester CI Status**: Ensure both `ubuntu-latest` and `windows-latest` CI jobs pass.
- **Sentinel / Table Logic**: Verify changes to `Data/*.json` maintain valid JSON structure and match expected classification schemas.
- **Documentation Validation**: Changes to data or schema should be validated against official Microsoft Learn docs (e.g., using the `microsoft-learn` MCP server at `https://learn.microsoft.com/api/mcp`). Because live Sentinel/Defender features can move faster than published documentation, if there is a discrepancy between code/schema and docs, note it with a **warning** rather than treating it as a blocker.
- **Error Handling**: Verify Azure API interactions gracefully handle missing permissions, non-existent tables, throttling (HTTP 429), or empty datasets.
- **PowerShell Best Practices**: Avoid deprecated cmdlets, adhere to strict approved verbs (`Invoke-`, `Get-`, `Set-`), and preserve backward compatibility with PowerShell 7.0+.

---

## MCP Servers for Copilot Agents

When working in this repository, Copilot cloud agent and review agents can use the Microsoft Learn MCP server:
- **Server Name**: `microsoft-learn`
- **URL**: `https://learn.microsoft.com/api/mcp`
- **Type**: `http`
- **Purpose**: Ground table schema, REST API version, and feature changes in authoritative Microsoft Learn documentation.

*Trust these instructions as the primary source of truth for repository structure and validation steps.*
