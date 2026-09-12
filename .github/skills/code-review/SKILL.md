---
name: log-horizon-code-review
description: Code review guidelines and validation checks tailored for Log Horizon (PowerShell 7 Sentinel Log Source Analyzer & CLI). Use when reviewing PRs, auditing PowerShell code quality, checking Spectre.Console TUI safety, validating Sentinel table schema changes, or inspecting cross-platform test coverage.
---

# Log Horizon Code Review Skill

This skill guides GitHub Copilot code reviews for the `log-horizon` project. It ensures reviews focus on high-impact architectural, cross-platform, security, and Sentinel domain concerns rather than generic boilerplate.

---

## Review Priorities & Checklist

### 1. Cross-Platform Path & Runtime Compatibility (CRITICAL)
- [ ] **No Hardcoded Drive Letters or Backslashes**: Paths must never use `C:\` or single `\`. Use nested `Join-Path` or `[System.IO.Path]::Combine()` / `[System.IO.Path]::GetTempPath()`.
- [ ] **PowerShell 7+ Compatibility**: Ensure syntax works seamlessly across Linux (Ubuntu), macOS, and Windows. Avoid Windows-specific COM objects or WMI cmdlets.

### 2. Spectre.Console Markup Safety
- [ ] **Markup Escaping**: Any dynamic user or table input passed into Spectre.Console markup strings must be wrapped with `Get-SafeEscapedText` to escape `[` and `]` characters.
- [ ] **Terminal Encoding Safety**: Do not remove `$env:IgnoreSpectreEncoding = $true` in module loader or test setups.

### 3. Security, Auth & Zero-Secrets Rule
- [ ] **No Hardcoded Secrets**: Ensure tenant IDs, subscription IDs, workspace IDs, customer IDs, and tokens are never hardcoded in scripts or test files.
- [ ] **Cache Hygiene**: Verify `Get-CollectionCache.ps1` and `Save-CollectionCache` never serialize auth tokens or contexts (`Context`, `GraphToken`, `ArmToken`, `LaToken`).
- [ ] **Resilient API Calls**: All Azure Log Analytics, SecurityInsights, and ARM calls must route through `Invoke-AzRestWithRetry` with proper exponential backoff.
- [ ] **Sovereign Cloud Support**: Azure REST URIs and endpoints must be dynamically resolved via `Get-LogHorizonEndpoint` rather than hardcoded `management.azure.com`.

### 4. Sentinel Classification & Data Integrity
- [ ] **JSON Schema Validation**: Any modification to `Data/log-classifications.json`, `Data/basic-plan-tables.json`, `Data/auxiliary-plan-tables.json`, or `Data/high-value-fields.json` must preserve valid JSON syntax and correct classification properties (`Tier`, `Category`, `Plan`, `IsBillable`, `IsStreaming`).
- [ ] **Documentation Validation**: Changes to data or schema should be validated against official Microsoft Learn documentation (e.g., via the `microsoft-learn` MCP server at `https://learn.microsoft.com/api/mcp`). However, because cloud services evolve rapidly, official documentation might not always reflect the latest live service releases. If there is a discrepancy between code/schema and published docs, note it with a **warning** rather than treating it as a blocker.
- [ ] **Scoring Formula Integrity**: Ensure cost vs. detection value scoring in `Private/Invoke-Analysis.ps1` correctly handles free tables, auxiliary tables, and zero-coverage scenarios without division-by-zero errors.

### 5. Pester 5.x Test Coverage
- [ ] **No Broken Tests**: Every bug fix, new recommendation rule, or feature must include matching unit tests in `Tests/LogHorizon.Tests.ps1`.
- [ ] **Full Offline Testing**: Unit tests must run 100% offline using mocks and synthetic data (no live Azure credentials required).
- [ ] **Pester 5 Idioms**: Use `BeforeAll`, `Describe`, `Context`, `It`, and `Should -Be` operators. Avoid legacy Pester 3/4 syntax.
