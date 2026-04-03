<center>
  <img width="500"  src="https://github.com/user-attachments/assets/a1e00e5f-e566-47bd-ad08-2678ba07b7ee" />
</center>

**Microsoft Sentinel SIEM Log Source Analyzer**

![PowerShell 7+](https://img.shields.io/badge/PowerShell-7%2B-blue)
![Module Version](https://img.shields.io/badge/version-0.5.0-green)

---
I've had to answer *"what are we actually getting out of these logs?"* or *"what is the recommended logs for Microsoft Sentinel"* more times than I can count. The answer always depend on so many things, but we can be generic. So I built this thingy right here.

**Log Horizon** connects to your Microsoft Sentinel workspace (and optionally Defender XDR), goes through every log table you're ingesting, and tells you whether you're getting security value from it or just burning money. It classifies tables, scores them against your detection rules, and gives you concrete recommendations with savings estimates.

> **Important**: This is a generic approach. If you know a log source is important to your environment, that context always takes precedence over what this tool tells you. The classifications are a starting point, not gospel.

## Features

| Feature | Description |
|---|---|
| **Classification Engine** | 344-entry knowledge base covering 190+ connectors, 21 categories, with automatic heuristic fallback for unknown tables |
| **Cost-Value Scoring** | Per-table cost tier vs detection tier matrix with combined assessment (High Value → Low Value) |
| **Recommendations** | Prioritised actions: data lake candidates, zero-detection tables, XDR streaming waste, ingest-time filtering, retention shortfalls |
| **Detection Mapping** | Maps analytics rules, hunting queries, and XDR detections to each table to spot coverage gaps |
| **Correlation Tags** | Detects `#DONT_CORR#` / `#INC_CORR#` tags in rule descriptions and flags rules excluded from Defender correlation |
| **Retention Compliance** | Compares actual retention against recommended minimums based on industry standards and security best practices |
| **SOC Optimisation** | Pulls Microsoft's own SOC improvement recommendations from the Security Insights API |
| **Keyword Gap Analysis** | Flag tables you should be ingesting but aren't based on vendor/product keywords |
| **Transform Discovery** | Discovers Data Collection Rules (DCRs) and classifies ingest-time transforms (filter, projection, enrichment, aggregation) |
| **Split Table Detection** | Identifies `_SPLT_CL` split tables and links them back to parent tables in the classification engine |
| **Split KQL Generator** | Generates portal-ready split KQL from a 15-table knowledge base and/or your analytics rules — condition-only format that pastes straight into the Sentinel split rule editor |
| **Custom Classifications** | Provide your own JSON to add or override the built-in classification database |
| **Interactive TUI** | Spectre.Console dashboard with menus, colour-coded tables, drill-downs, and ASCII art |
| **Export** | JSON, Markdown, or static HTML report for sharing with the team |

## Prerequisites

| What you need | Version |
|---|---|
| PowerShell | 7.0+ |
| Az modules | `Az.Accounts`, `Az.OperationalInsights`, `Az.SecurityInsights` |
| PwshSpectreConsole | 2.6.3+ |

If you're not already logged into Azure, the module will fire up `Connect-AzAccount` for you. If you are, it'll just carry on.

## Getting started

Pretty straight forward:

```powershell
# Grab the dependencies
Install-Module -Name Az.Accounts, Az.OperationalInsights, Az.SecurityInsights -Scope CurrentUser
Install-Module -Name PwshSpectreConsole -Scope CurrentUser

# Clone and import
git clone <repo-url> log-horizon
Import-Module ./log-horizon/LogHorizon.psd1
```

## Usage

### The basics

```powershell
Invoke-LogHorizon -SubscriptionId '00000000-0000-0000-0000-000000000000' -ResourceGroup 'rg-sentinel' -WorkspaceName 'my-sentinel-ws'
```

Output should look something like this:

<img width="860" height="842" alt="{F4FFA929-B24F-490C-BD3D-F75E214BCD93}" src="https://github.com/user-attachments/assets/29e7a399-713d-4a2b-9d7d-43dbf368be3f" />

Also has a menu to dig deeper into other outputs:

<img width="395" height="223" alt="{83CE9E6E-F373-49CD-BE05-182DB69F36BE}" src="https://github.com/user-attachments/assets/c1e0804e-5267-4d8e-bb10-01770b25b831" />


### Keyword gaps + Defender XDR

Want to know if you're missing tables related to specific vendors? Throw in some keywords. Add `-IncludeDefenderXDR` if you want the XDR analysis too.

```powershell
Invoke-LogHorizon -SubscriptionId '...' -ResourceGroup 'rg' -WorkspaceName 'ws' -Keywords 'CrowdStrike','AWS','Okta' -IncludeDefenderXDR
```

### Export a report

```powershell
# JSON
Invoke-LogHorizon -SubscriptionId '...' -ResourceGroup 'rg' -WorkspaceName 'ws' -Output json -OutputPath ./report.json

# Markdown
Invoke-LogHorizon -SubscriptionId '...' -ResourceGroup 'rg' -WorkspaceName 'ws' -Output markdown -OutputPath ./report.md

# Static HTML (self-contained, no JS, works offline)
Invoke-LogHorizon -SubscriptionId '...' -ResourceGroup 'rg' -WorkspaceName 'ws' -Output html -OutputPath ./report.html

# Auto-generate timestamped filename by pointing at a directory
Invoke-LogHorizon -SubscriptionId '...' -ResourceGroup 'rg' -WorkspaceName 'ws' -Output html -OutputPath ./reports/
```

### Non-interactive / CI mode

Skip the interactive TUI and export straight to a file — useful for pipelines or scheduled runs:

```powershell
Invoke-LogHorizon -SubscriptionId '...' -ResourceGroup 'rg' -WorkspaceName 'ws' -NonInteractive -Output json -OutputPath ./reports/
```

If you omit `-Output`, the analysis object is returned to the pipeline so you can pipe it into your own logic.

### Split KQL Suggestions

The interactive TUI includes a **Split KQL Suggestions** menu that generates portal-ready split KQL for tables that are good candidates for splitting. It shows per-table KQL you can paste straight into the Sentinel split rule editor, with source attribution (knowledge base, rule analysis, or combined).

### Custom pricing

Default price is 5.59 $/GB (West Europe Simplified PAYG). If your commitment tier is different:

```powershell
Invoke-LogHorizon -SubscriptionId '...' -ResourceGroup 'rg' -WorkspaceName 'ws' -PricePerGB 4.61
```

### All parameters

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `-SubscriptionId` | string | Yes | - | Azure subscription ID |
| `-ResourceGroup` | string | Yes | - | Resource group containing the Sentinel workspace |
| `-WorkspaceName` | string | Yes | - | Log Analytics workspace name |
| `-WorkspaceId` | string | No | - | Workspace ID (auto-resolved if omitted) |
| `-Output` | string | No | - | Export format: `json`, `markdown` / `md`, or `html` |
| `-OutputPath` | string | No | - | File or directory path for export (auto-generates timestamped filename when a directory) |
| `-Keywords` | string[] | No | - | Keywords for gap analysis (e.g. `'AWS','CrowdStrike'`) |
| `-IncludeDefenderXDR` | switch | No | - | Include Defender XDR custom detection analysis |
| `-DaysBack` | int | No | 90 | Query window for usage data (1-365 days) |
| `-PricePerGB` | decimal | No | 5.59 | Sentinel ingestion price per GB |
| `-NonInteractive` | switch | No | - | Skip the TUI dashboard and export directly (or return data to pipeline if `-Output` is omitted) |
| `-CustomClassificationPath` | string | No | - | Path to a custom JSON file to add or override classifications |

---

## Under the hood

So there's four phases.

### 1. Data collection

The module connects to Azure and pulls data from the Log Analytics and Security Insights APIs:

| Data Source | API | What we grab |
|---|---|---|
| Table usage | `Usage` table (KQL) | Ingestion volume per table over your query window |
| Analytics rules | Security Insights REST | Active detection rules + which tables they hit + correlation tags |
| Hunting queries | Security Insights REST | Saved hunting queries + referenced tables |
| Data connectors | Security Insights REST | Installed connector inventory |
| SOC optimisation | Security Insights REST | Microsoft's built-in SOC recommendations |
| Table retention | Azure Tables REST | Per-table retention, archive, and plan (Analytics/Basic) |
| Defender XDR | Security Insights REST | XDR custom detections and streaming config (optional) |

### 2. Classification

Every table gets classified through two passes:

**First**, a direct lookup against the 344-entry knowledge base in `Data/log-classifications.json`. Each entry carries the connector name, primary/secondary classification, security category, MITRE data source mappings, and a recommended pricing tier.

**If there's no match**, heuristic rules kick in:
- Name contains security patterns like `Alert`, `Incident`, `Threat`, `Signin`, `Audit`, `Risk` -> **primary**
- Name looks like infra telemetry: `Flow`, `Metric`, `Diagnostic`, `Perf`, `Heartbeat` -> **secondary**
- Has active analytics rules pointing at it -> **primary**
- High volume (>10 GB/mo) with nothing detecting on it -> **secondary**
- None of the above -> **unknown**

### 3. Cost-value scoring

Each table gets scored on a few dimensions:

- **Cost tier**: Free / Low (<1 GB) / Medium (1-10 GB) / High (10-50 GB) / Very High (>50 GB)
- **Detection tier**: None / Low (1-2 rules) / Medium (3-9 rules) / High (10+ rules)
- **Assessment**: High Value / Good Value / Missing Coverage / Review Needed / Data Lake Candidate / Free Tier
- **Coverage %**: Percentage of tables with at least one analytics rule or hunting query referencing them, calculated as `tablesWithRules / totalTables * 100`. Per-table coverage sums analytics rules + hunting queries found by parsing KQL for table names.

Then the module generates recommendations:

| Type | When it fires | What to do |
|---|---|---|
| **Data Lake** | Secondary + high cost + few detections | Move to Auxiliary/Data Lake tier (~95% savings) |
| **Low Value** | High cost + zero detections | Add rules, filter, or move to data lake |
| **XDR Optimise** | XDR-streamed + 0 Sentinel rules + XDR rules exist | Stop streaming, use the unified XDR portal instead |
| **Missing Coverage** | Primary + zero detections | Write analytics rules to get value from the data |
| **Ingest-time Filter** | Primary + >20 GB + <=3 detections | Apply ingest-time transformation to cut volume |
| **Split Candidate** | Primary + high volume + detections + no existing transform | Split the table — high-value rows stay on Analytics, the rest goes to Data Lake |
| **Retention Shortfall** | Table retention below recommended minimum | Increase total/archive retention to meet regulatory guidance |

### 4. Interactive dashboard

You land in a Spectre.Console TUI with a menu:

- **Dashboard**: overview stats, top 10 costliest tables, coverage bar, retention compliance summary, correlation exclusion callout
- **Recommendations**: prioritised actions with estimated monthly savings — expandable to show the full list when there are more than 10
- **Detection Assessment**: per-table rule and hunting query coverage breakdown, correlation-excluded rule listing
- **SOC Optimisation**: Microsoft's own improvement suggestions
- **Retention Assessment**: tables below recommended minimums with current vs recommended retention, plan type, and shortfall
- **Transforms**: DCR transform inventory with transform type classification
- **Split KQL Suggestions**: per-table split KQL ready to paste into the portal, with source attribution (knowledge base, rule analysis, or combined)
- **All Tables**: the full list with classification, cost, rules, retention (colour-coded), and assessment
- **XDR Analysis**: Defender XDR integration (when you used `-IncludeDefenderXDR`)
- **Export**: dump the report to JSON or Markdown right from the menu

---

## The classification database

Sitting at `Data/log-classifications.json`. **344 entries**, **190 connectors**, **21 categories**.

### What's in each entry

| Field | What it holds |
|---|---|
| `tableName` | Log Analytics table name (`SecurityEvent`, `SigninLogs`, etc.) |
| `connector` | Which data connector produces this table |
| `classification` | `primary` (security value) or `secondary` (supporting telemetry) |
| `category` | Security category: Identity & Access, Network Security, etc. |
| `description` | Plain-English summary of what's in the table |
| `keywords` | Terms for keyword gap analysis matching |
| `mitreSources` | MITRE ATT&CK data source mappings |
| `recommendedTier` | `analytics` (hot tier) or `datalake` (auxiliary candidate) |
| `recommendedRetentionDays` | Minimum recommended total retention in days (regulatory guidance) |
| `isFree` | Whether Microsoft ingests this one for free |

### Primary vs secondary security data

**Primary** (211 entries): the tables you're actually building detections on. Sign-in logs, security alerts, threat intel, audit trails, vulnerability findings, firewall hits, EDR telemetry.

**Secondary** (133 entries): supporting stuff. Perf metrics, infrastructure diagnostics, network flow volumes, inventory snapshots, config baselines, health checks. Still useful, just not where your detections live.

### Categories at a glance

| Category | Count | Examples |
|---|---|---|
| Identity & Access | 33 | `SigninLogs`, `OktaSSO`, `CyberArk_AuditEvents_CL` |
| Network Security | 29 | `AZFWNetworkRule`, `Cloudflare_CL`, `darktrace_model_alerts_CL` |
| Security Alerts | 26 | `SecurityAlert`, `SecurityIncident`, `SentinelOneAlerts_CL` |
| Endpoint Detection | 22 | `DeviceProcessEvents`, `DeviceFileEvents`, `SentinelOne_CL` |
| Cloud Control Plane | 22 | `AzureActivity`, `OfficeActivity`, `GoogleWorkspaceReports` |
| Network Flow | 23 | `AzureNetworkAnalytics_CL`, `CommonSecurityLog`, `AZFWFatFlow` |
| Cloud Security | 13 | `McasShadowItReporting`, `PaloAltoPrismaCloudAlertV2_CL` |
| Email Security | 20 | `EmailEvents`, `ProofPointTAPMessagesBlockedV2_CL`, `MimecastSIEM_CL` |
| Endpoint Telemetry | 14 | `DeviceInfo`, `SentinelOneAgents_CL`, `jamfprotecttelemetryv2_CL` |
| Vulnerability Mgmt | 11 | `DeviceTvmSoftwareVulnerabilities`, `QualysHostDetectionV3_CL` |
| Data Security | 12 | `PurviewDataSensitivityLogs`, `VaronisAlerts_CL`, `MimecastDLP_CL` |
| Application Logs | 22 | `AppServiceHTTPLogs`, `FunctionAppLogs`, `DynatraceAttacks_CL` |
| Threat Intelligence | 8 | `ThreatIntelligenceIndicator`, `CybleVisionAlerts_CL` |
| SAP Security | 7 | `ABAPAuditLog`, `SAPBTPAuditLog_CL`, `Onapsis_Defend_CL` |
| IoT/OT Security | 4 | `RadiflowEvent`, `DragosAlerts_CL`, `Phosphorus_CL` |
| Data Platform | 13 | `AzureDiagnostics`, `SnowflakeLogin_CL`, `MongoDBAudit_CL` |
| Container & K8s | 7 | `ContainerLog`, `KubeEvents`, `GKEAudit`, `AWSEKSLogs_CL` |
| Platform Health | 6 | `SentinelHealth`, `Watchlist`, `SOCPrimeAuditLogs_CL` |
| Infrastructure Diag | 7 | `AzureMetrics`, `GCPComputeEngine`, `GCPMonitoring` |
| Posture Management | 7 | `DeviceTvmSecureConfigurationAssessment`, `CortexXpanseAlerts_CL` |
| Configuration Mgmt | 6 | `ConfigurationData`, `ESIExchangeOnlineConfig_CL` |
| Storage Access | 5 | `StorageBlobLogs`, `StorageFileLogs`, `AWSS3ServerAccess` |

### Custom classifications

You can provide your own classification file to **add** entries for tables not in the built-in database, or **override** existing entries when the defaults don't match your environment. Custom entries take precedence over built-in ones when the same `tableName` appears in both.

```powershell
Invoke-LogHorizon -SubscriptionId '...' -ResourceGroup 'rg' -WorkspaceName 'ws' `
    -CustomClassificationPath './my-classifications.json'
```

The custom file uses the same schema as `Data/log-classifications.json` — an array of objects:

```json
[
  {
    "tableName": "MyCustomApp_CL",
    "connector": "Custom Logs (DCR)",
    "classification": "primary",
    "category": "Application Logs",
    "description": "Security-relevant audit events from an internal application",
    "keywords": ["custom", "internal", "audit"],
    "mitreSources": [],
    "recommendedTier": "analytics",
    "isFree": false
  },
  {
    "tableName": "AzureMetrics",
    "connector": "Azure Monitor",
    "classification": "primary",
    "category": "Infrastructure Diag",
    "description": "Override: promoted to primary because we detect on Azure resource metrics in this environment",
    "keywords": ["metrics", "azure", "infrastructure", "monitoring"],
    "mitreSources": [],
    "recommendedTier": "analytics",
    "isFree": false
  }
]
```

See `Data/custom-classifications-example.json` for a ready-to-use template.

### How the classifications were built

The primary/secondary grading was done by feeding Microsoft's data connector and table definitions into AI, using Microsoft best practices and industry standards as the classification criteria. On manual review it's a solid baseline and starting point, but AI can still make mistakes. If something looks off for your environment, trust your own context over the tool.

The classification criteria were drawn from the following sources:

**Microsoft**
- [Microsoft Sentinel data connectors reference](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference)
- [Microsoft Sentinel tables & connectors reference](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-tables-connectors-reference)
- [Azure-Sentinel GitHub repo](https://github.com/Azure/Azure-Sentinel) (community analytics rules, connector definitions, solution templates)
- Microsoft Sentinel pricing docs for free tier identification

**MITRE**
- [MITRE ATT&CK Data Sources](https://attack.mitre.org/datasources/)

**NIST**
- NIST SP 800-92 Rev. 1, Cybersecurity Log Management Planning Guide
- NIST Guide to Operational Technology (OT) Security

**CISA**
- CISA Guidance for Implementing M-21-31: Improving the Federal Government's Investigative and Remediation Capabilities
- CISA SCuBA TRA and eVRF Guidance Documents

**NSA**
- NSA Cyber Event Forwarding Guidance

**NCSC-UK**
- NCSC-UK's "What exactly should we be logging?"

**ASD ACSC / Joint advisories**
- Joint-sealed advisory: Identifying and Mitigating Living Off the Land Techniques
- ASD ACSC's Windows Event Logging and Forwarding

---

## Project layout

```
LogHorizon.psd1              Module manifest (v0.5.0)
LogHorizon.psm1              Module loader
Public/
  Invoke-LogHorizon.ps1      Entry point, the main orchestrator
Private/
  Connect-Sentinel.ps1       Azure auth + workspace resolution
  Get-TableUsage.ps1         KQL query for ingestion volumes
  Get-AnalyticsRules.ps1     Analytics rules + table/field extraction + correlation tags
  Get-HuntingQueries.ps1     Hunting queries + table extraction
  Get-DataConnectors.ps1     Data connector inventory
  Get-DataTransforms.ps1     DCR transform discovery, split KQL generation
  Get-DefenderXDR.ps1        Defender XDR analysis (optional)
  Get-SocOptimization.ps1    SOC improvement recommendations
  Get-TableRetention.ps1     Per-table retention, archive, and plan type
  Invoke-Classification.ps1  Static DB + heuristic classification + _SPLT_CL detection
  Invoke-Analysis.ps1        Cost-value matrix + recommendations + split suggestions
  Write-Report.ps1           Spectre.Console TUI rendering
  Export-Report.ps1          JSON / Markdown / static HTML export with shared section renderer
Data/
  log-classifications.json              344-entry classification knowledge base
  high-value-fields.json                15-table split KQL knowledge base with curated fields and split hints
  custom-classifications-example.json   Example custom classification override file
  ReportTemplate.html                   Static HTML report template (pure-CSS tabs, zero JS)
Tests/
  LogHorizon.Tests.ps1       Pester v5 unit tests (106 tests)
```

## Tests

```powershell
Invoke-Pester ./Tests/LogHorizon.Tests.ps1 -Output Detailed
```

## License

MIT

## Version history

| Version | Date | Changes |
|---|---|---|
| 0.5.0 | 2026-04-03 | Static HTML export with pure-CSS tabs (zero JS, no CDN, fully self-contained), unified MD/HTML section renderer, complete JSON data capture (dataTransforms, correlationExcluded/Included, streamingTables), `-NonInteractive` switch for CI/pipeline usage, `md` format alias, datetime-stamped auto-filenames, full KQL display in DCR transforms (no truncation), multiline KQL handling in markdown tables, fixed regex `$`-backreference corruption in HTML token replacement, renamed internal helpers to avoid PowerShell alias conflicts (`h`→`hEnc`, `md`→`mdEsc`), 33 new Pester tests (106 total) |
| 0.4.1 | 2026-04-03 | Security & stability fixes - added token memory sanitization, output path validation & XSS protection, REST API pagination limits, fixed module loader error masking, and resolved PSScriptAnalyzer warnings |
| 0.4.0 | 2026-04-02 | Transform discovery (DCR listing + transform type classification), split table detection (`_SPLT_CL`), split KQL helper with 15-table knowledge base (`high-value-fields.json`) + rule-analysis fallback, portal-ready condition-only KQL output, expandable recommendations list, split KQL suggestions TUI menu |
| 0.3.0 | 2026-04-02 | Log retention compliance analysis (CISA M-21-31, NIST SP 800-92, NCSC-UK, ASD ACSC, NSA), correlation tag detection (`#DONT_CORR#`/`#INC_CORR#`), retention assessment menu view, retention column in All Tables, `recommendedRetentionDays` in classification schema |
| 0.2.2 | 2026-04-02 | SOC optimization table hides Detail column on narrow consoles |
| 0.2.1 | 2026-04-02 | Custom classification support (`-CustomClassificationPath`), enriched SOC optimization recommendations with API suggestions/drill-down, active-only default view, UTF-8 encoding warning suppression |
| 0.2.0 | - | Initial public release with classification engine, cost-value scoring, Spectre.Console TUI, export to JSON/Markdown |
| 0.1.0 | - | Internal version for development |

## Known issues

### PwshSpectreConsole UTF-8 encoding warning

To enable UTF-8 output in your terminal, add the following line at the top of your PowerShell `$PROFILE` file and restart the terminal:

```powershell
$OutputEncoding = [console]::InputEncoding = [console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
```

The module sets this automatically on import, but depending on your session the warning may still appear. It's cosmetic and doesn't affect functionality.

## Disclaimer

> [!CAUTION]
> **Disclaimer**
>
> **This tool is created with the help of AI.** Please exercise caution when using this solution and always understand what are you running before you run it in production. The developer assumes no liability for any vulnerabilities or issues.
> 
> By downloading, installing, or using this tool, you acknowledge that you have read, understood, and agree to these terms.
>

