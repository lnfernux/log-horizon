# Changelog

## 0.10.0 - 2026-10-07

- Data now comes from the bundled [log-baseline](https://github.com/lnfernux/log-baseline) release 0.5.0 (946 classifications, 57 shared-table sources). It is vendored by `scripts/Update-LogBaseline.ps1` and the baseline update workflow, and `Data/baseline-version.json` records the release, source commit and file checksums.
- Keyword gaps skip deprecated, legacy and XDR-only tables (`logAnalyticsTable: false`) and label Defender native tables as already queryable in advanced hunting.
- Rules that call a parser count toward the parser's source tables. String literals and comments are ignored when matching parser names.
- New `SharedTableSplit` recommendation for `CommonSecurityLog` and `Syslog`:
  - Per-source volume from a 7-day `_BilledSize` sample, summarized by the filter columns first so the source `case()` runs on distinct values.
  - Only tables whose configured plan is Analytics are queried. Basic and Auxiliary queries are billed per GB scanned.
  - One composed split condition with table and `_SPLT` retention. It keeps the rows matched by where-conditions of enabled rules on the table. If the query fails with those conditions, it is retried once without them.
  - Fires at 1 GB/mo or more of data lake sources, replaces the generic `SplitCandidate` estimate for that table, and warns when the condition exceeds the 15,360-character transformation limit.
  - Shown under Log Tuning / Transforms > Shared table sources and in the reports. Skip the measurement with `-SkipSharedSources`.
- `Get-SplitKql` joins all split hints.
- Long `DeprecatedSource` replacement lists are truncated.
- TUI: views that end without Back (Detection Analyzer without data, recommendations, export) stay on screen until you return. Resizing the window at a prompt redraws the current view at the new width.
- Detection Analyzer flags a rule as noisy when it has at least 5 closed incidents of which 80% or more were auto-closed by automation or closed as false positive, even when too few rules have incidents to compute a score. The 5-minute timing fallback does not count toward this rule.
- HTML report:
  - Tabs are keyboard operable (Tab to the group, arrow keys to switch) with a visible focus ring. They wrap instead of scrolling sideways, and the tab rules are generated per section, so there is no tab limit.
  - Every text colour now measures at least 4.5:1 against its background. Before, the orange and green badges, the active tab, the metric labels and secondary-class text did not.
  - Summary values use thousands separators and the units moved into the labels, so long amounts no longer overflow the cards.
  - Recommendation cards lead with the title, then priority, a readable type name, savings and current cost.
  - Each section has a heading for screen readers and for print.
- 475 tests.

## 0.9.0 - 2026-09-06

Remediation release from a full code and data review. Correctness: plan-aware pricing from `Usage.Plan` and `Usage.IsBillable` with Basic and Data Lake rates and billing GB (1000 MB), Detection Analyzer auto-close attribution restricted to enabled close/playbook rules (`triggeringLogic.isEnabled`), incidents via `2025-09-01` with `$top=1000`, implicit coverage for non-KQL rule kinds and platform tables (`implicit-consumers.json`), interactive-retention baseline check, single recommendation sort. Transforms: DCR discovery at subscription scope filtered on destination workspace plus the workspace transformation DCR and associations, with a visible status and warning when a permission is missing; workspace and multi-stage transform parsing; split KQL intersected with the live table schema. Robustness: collection cache on by default (`-NoCache`, `-RefreshCache`, `-CacheMaxAgeMinutes`, `-CachePath`), authentication before the spinner with warnings printed afterwards, escaped TUI and Markdown output, export path resolution that creates directories and returns the written path, CSP meta in HTML, REST retries on transport errors and Location-style async completion, workspace resolution over REST (`Az.Resources` dropped), custom classification validation, PascalCase-aware heuristics with a Microsoft first-party fallback, regex timeouts. Endpoints follow the signed-in Azure environment (Government, China) and API versions moved to SecurityInsights `2025-09-01`, OperationalInsights `2025-07-01`, recommendations `2025-10-01-preview`. Data: classification database 345 -> 481 entries with `status`/`replacedBy`/`xdrStreamable`/`platform` keys, 80+ first-party and 35 successor tables, connector label fixes, `isFree` corrections; regenerated `basic-plan-tables.json` and new `auxiliary-plan-tables.json` from the Azure Monitor table feature matrix; `DeprecatedSource` recommendation, plan-aware Data Lake recommendation with Basic fallback, XDR Checker honours streamability, lifecycle badges in TUI and exports. Review pass: cache key covers pricing and module version, custom classification booleans and tiers parsed rather than cast, severity-aware auto-close attribution, split KQL predicates checked against the live schema, XDR fetch status surfaced instead of a silent `$null`, output paths without an extension are files, incident owner identities no longer collected. Dictionary menu in the TUI with every term the tool uses, backed by `Data/dictionary.json` and pinned to the code by tests. Automation rule and Defender custom detection objects are projected to the consumed fields, so author identities (createdBy, lastModifiedBy, assigned owners) never reach the cache or exports. GPL-3.0 licence. 437 tests.

## 0.8.0 - 2026-05-26

Added interactive table retention management with a new bulk TUI flow and single-table update entry point, plus the public `Set-LogHorizonTableRetention` command. Added Tables API PATCH apply engine with validation, Azure async-operation polling, and two-step fallback (combined PATCH, then plan-only plus retention-only) for resilient retention updates. Added focused Pester coverage for validation, payload shape, fallback, and public command mapping. Also fixes an edge-case/bug where users would get recommendations to change data lake tables to data lake tier if they had analytics data still in Sentinel.

## 0.7.1 - 2026-05-15

Added plan-awareness from `Usage.Plan` without replacing the configured table plan: analysis now tracks observed plan history, flags multi-plan usage and configured-vs-observed mismatches, and surfaces plan data in the dashboard, table drill-down, View All Tables, retention assessment, and exports. Fixed Detection Analyzer auto-close attribution so the timing heuristic only applies when no enabled automation rules exist. 203 tests passing.

## 0.7.0 - 2026-04-16

Detection Assessment updated with cost-value matrix summary table (Primary/Secondary x7 assessment categories with color coding), drill-down submenu for primary/secondary tables with cost/detection tier columns. Detection Analyzer updated with GB-weighted volume coverage bars (detection/hunting/combined GB as percentage of total ingestion alongside existing table-count bars). Adaptive display improvements for Detection Analyzer (dynamic bar width, rule name truncation, conditional column hiding based on console width). 193 tests passing.

## 0.6.3 - 2026-04-11

Minor update for PSGallery.

## 0.6.2 - 2026-04-11

Log Tuning / Transforms menu: live data tuning analysis (per-table field usage from deployed rules/hunting queries, filter/project/combined KQL generation, savings estimates), schema column extraction from Tables API, `Get-SplitKql` fallback hierarchy (community stats → category defaults → universal fields), comprehensive table evaluator with field usage matrix, unified KB + live tuning export sections, `Build-FieldKnowledgeBase.ps1` mining script for Azure-Sentinel GitHub rule corpus. Detection Analyzer: SentinelHealth-based auto-close attribution (primary) with operator-aware rule-matching fallback, Boolean condition wrapper parsing, Resolved status detection, GUID-tail matching for ARM resource IDs. Coverage now table-count-based across all tables (including free tier). Scoring disclaimer added to TUI and exports. 174 tests.

## 0.6.1 - 2026-04-10

Bug fixes: `$kqlKeywords` filtering now shared at file scope (was undefined in `Get-TablesFromKql`), `[CmdletBinding()]` added to all helper functions, Defender unified check simplified, removed ghost `-RuleCount` test param. Robustness: `Get-HuntingQueries` pagination, `Invoke-AzRestWithRetry` retry wrapper with exponential backoff for 429/5xx, `PricePerGB` validation, `Write-Verbose` in key functions. Docs: version badge, DB count, prerequisites aligned with manifest.

## 0.6.0 - 2026-04-10

Dynamic XDR streaming detection with 21 `KnownXDRTables` (was hardcoded 18), per-table `XDRState` (`NotStreaming`/`Analytics`/`Basic`/`Auxiliary`), Auxiliary recognized as data lake tier, not-streamed XDR tables surfaced as Information/Low recommendations with `NotStreamedCount`, retention analyzer shows not-streamed XDR tables as "XDR only (30d)", overview tier breakdown (analytics/basic/data lake + not streamed), Export-Report Auxiliary→"data lake" labels, classification DB updated to 345 entries (+`DeviceNetworkInfo`, `DeviceInfo`→secondary/datalake, `DeviceImageLoadEvents` and `IdentityQueryEvents`→datalake tier), 15 new Pester tests (121 total).

## 0.5.0 - 2026-04-03

Static HTML export with pure-CSS tabs (zero JS, no CDN, fully self-contained), unified MD/HTML section renderer, complete JSON data capture (dataTransforms, correlationExcluded/Included, streamingTables), `-NonInteractive` switch for CI/pipeline usage, `md` format alias, datetime-stamped auto-filenames, full KQL display in DCR transforms (no truncation), multiline KQL handling in markdown tables, fixed regex `$`-backreference corruption in HTML token replacement, renamed internal helpers to avoid PowerShell alias conflicts (`h`→`hEnc`, `md`→`mdEsc`), 33 new Pester tests (106 total).

## 0.4.1 - 2026-04-03

Security & stability fixes - added token memory sanitization, output path validation & XSS protection, REST API pagination limits, fixed module loader error masking, and resolved PSScriptAnalyzer warnings.

## 0.4.0 - 2026-04-02

Transform discovery (DCR listing + transform type classification), split table detection (`_SPLT_CL`), split KQL helper with 15-table knowledge base (`high-value-fields.json`) + rule-analysis fallback, portal-ready condition-only KQL output, expandable recommendations list, split KQL suggestions TUI menu.

## 0.3.0 - 2026-04-02

Log retention compliance analysis (CISA M-21-31, NIST SP 800-92, NCSC-UK, ASD ACSC, NSA), correlation tag detection (`#DONT_CORR#`/`#INC_CORR#`), retention assessment menu view, retention column in All Tables, `recommendedRetentionDays` in classification schema.

## 0.2.2 - 2026-04-02

SOC optimization table hides Detail column on narrow consoles.

## 0.2.1 - 2026-04-02

Custom classification support (`-CustomClassificationPath`), enriched SOC optimization recommendations with API suggestions/drill-down, active-only default view, UTF-8 encoding warning suppression.

## 0.2.0

Initial public release with classification engine, cost-value scoring, Spectre.Console TUI, export to JSON/Markdown.

## 0.1.0

Internal version for development.
