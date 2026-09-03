# Scarafiotti Network - PowerShell

PowerShell scripts and automation tools developed by **Scarafiotti Network** for IT administration, managed services and infrastructure operations.

Scarafiotti Network is a Managed Service Provider (MSP) based in Piossasco, Turin, Italy, focused on IT management, cybersecurity, business continuity and networking for small and medium-sized businesses.

## Public scripts

### SN-Windows-HealthAudit

[`SN-Windows-HealthAudit.ps1`](./SN-Windows-HealthAudit.ps1) performs a non-invasive Windows health and security assessment.

The script is intentionally **read-only by design** and does not modify Windows configuration, install software, create scheduled tasks, write registry values or send telemetry.

It checks a selected set of operational and security indicators, including:

- Windows version and execution context
- uptime and pending reboot indicators
- fixed-disk free space and physical-disk health
- memory availability
- TPM and Secure Boot
- BitLocker status on the system drive
- Windows Firewall profiles
- endpoint-protection state when it can be validated reliably
- Windows Update / hotfix indicators
- Windows Time service
- basic network configuration
- core Windows services
- recent Critical/Error counts in the System event log
- Fast Startup and active power plan as informational settings

#### Examples

```powershell
.\SN-Windows-HealthAudit.ps1
```

```powershell
.\SN-Windows-HealthAudit.ps1 -OutputFormat Json
```

```powershell
.\SN-Windows-HealthAudit.ps1 -OutputPath C:\Temp\WindowsHealthAudit.json
```

```powershell
.\SN-Windows-HealthAudit.ps1 -SkipUpdateScan -IncludeNetworkDetails
```

#### Output states

The assessment uses five explicit states:

- `OK`
- `Warning`
- `Critical`
- `Info`
- `NotAvailable`

Exit codes are intentionally simple:

- `0` - no Warning or Critical results
- `1` - one or more Warning results and no Critical results
- `2` - one or more Critical results

#### Privacy by default

The script is designed to minimize the amount of identifying information returned by a public diagnostic tool.

It does not intentionally collect usernames, e-mail addresses, serial numbers, product keys, BitLocker recovery keys, MAC addresses or Event Log messages. Gateway and DNS addresses are suppressed unless `-IncludeNetworkDetails` is explicitly specified.

No report file is created unless `-OutputPath` is supplied.

## Repository scope

This repository is intended to contain selected PowerShell scripts used or developed for activities such as:

- Windows workstation and server administration
- system configuration and standardization
- Microsoft 365 administration
- endpoint management
- security assessment and hardening
- network diagnostics
- software deployment and maintenance
- monitoring and remediation
- backup and operational checks
- IT support automation

## Design principles

Public scripts are developed with particular attention to:

- clear and predictable execution
- validation before evaluation or changes
- readable console and structured output
- error handling close to the failing operation
- repeatability
- minimal dependencies
- compatibility with remote-management scenarios
- safe behaviour in production environments
- explicit handling of unsupported or unavailable checks
- documentation of assumptions and limitations

## Security and customer data

Only scripts considered suitable for public distribution are published in this repository.

Customer-specific information, credentials, API keys, internal addresses, private infrastructure details and other confidential data are not intentionally included.

Scripts derived from production activities are reviewed and sanitized before publication.

The public repository does **not** represent the complete internal Scarafiotti Network scripting framework, logging standards, RMM integrations, customer-specific checks or proprietary operational procedures.

## Repository status

This repository is being progressively populated with selected and documented automation tools.

Not all scripts developed or used by Scarafiotti Network are published, as many are customer-specific or contain operational logic intended for managed environments.

## Usage and disclaimer

Review every script before deploying it in a production environment.

Infrastructure, operating-system versions, vendor behaviour and security requirements may differ between environments. Testing in a controlled environment is strongly recommended.

Software in this repository is provided under the [MIT License](./LICENSE) unless explicitly stated otherwise and is provided without warranty.

## About Scarafiotti Network

**Scarafiotti Network**  
Managed IT Services · Cybersecurity · Business Continuity · Networking

Piossasco (TO) - Italy  
https://www.scarafiotti.it
