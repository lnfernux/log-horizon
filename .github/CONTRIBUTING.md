# Contributing to Log Horizon

Thank you for your interest in contributing to Log Horizon! We/I welcome community contributions, bug reports, feature suggestions, and documentation improvements.

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to ensure the problem has not already been reported. When filing an issue, please include:

- A clear and descriptive title
- Steps to reproduce the problem
- Expected behavior vs. actual behavior
- PowerShell version (`$PSVersionTable.PSVersion`)
- Operating system platform
- Any relevant logs or sanitized screenshots (never include subscription IDs, workspace IDs, or credentials)

### Suggesting Enhancements

Feature requests are welcome! When opening a feature suggestion:

- Use a clear and descriptive title
- Explain why this enhancement would be useful to users of Log Horizon
- Describe the proposed solution or syntax example if applicable

### Pull Requests

1. **Fork the repository** and create your branch from `main`.
2. **Make your changes** in a focused branch (e.g., `fix/cache-expiration` or `feat/new-table-classifications`).
3. **Ensure tests pass**:
   ```powershell
   Import-Module Pester -RequiredVersion 5.7.1
   Import-Module PwshSpectreConsole
   Import-Module Az.Accounts

   $config = New-PesterConfiguration
   $config.Run.Path = './Tests/LogHorizon.Tests.ps1'
   $config.Run.PassThru = $true
   Invoke-Pester -Configuration $config
   ```
4. **Add or update tests** in `Tests/LogHorizon.Tests.ps1` for any new functionality or bug fixes.
5. **Open a Pull Request** against `main` using the provided Pull Request template.

## Coding Guidelines

- Target **PowerShell 7.0+** compatibility across Windows, macOS (not tested as of writing), and Linux (also not tested as of writing).
- Follow existing naming conventions (`Verb-Noun` for functions).
- Keep functions in `Private/` (internal helpers) or `Public/` (exported user-facing commands).
- Avoid unnecessary external dependencies.
- Never hardcode credentials, secrets, or tenant identifiers.
