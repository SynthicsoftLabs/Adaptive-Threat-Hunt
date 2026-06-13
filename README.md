 # Adaptive Threat Hunt & Auto-Hardening (CLM-Safe)

**Developed by Synthicsoft Labs & Adam Rivers**

A comprehensive PowerShell security tool designed for high-security environments where **Constrained Language Mode (CLM)** is enforced. This script performs an automated threat hunt by cross-referencing local system data with global threat intelligence feeds and applies proactive hardening measures using only native Windows binaries and approved cmdlets.

## Features

### 1. Machine Fingerprinting
*   Detailed hardware and software profiling (CPU, GPU, RAM, BIOS, TPM).
*   Retrieval of OS build information and unique identifiers for tracking.

### 2. Automated Threat Intelligence Ingestion
*   **CISA KEV:** Downloads and parses the Known Exploited Vulnerabilities catalog.
*   **NVD CVE API v2:** Real-time querying of the NIST National Vulnerability Database for hardware and software specific vulnerabilities.
*   **MalwareBazaar:** Checks running process hashes against known malware samples.
*   **ThreatFox:** Cross-references established network connections with known malicious IOCs.
*   **URLhaus:** Scans DNS cache for domains associated with malware distribution.

### 3. Proactive System Hardening
*   **Microsoft Defender:** Enables real-time protection, ASR rules, and cloud-based scanning.
*   **Kernel Mitigations:** Configures Memory Integrity (HVCI) and Virtualization Based Security (VBS).
*   **Credential Protection:** Enables LSASS RunAsPPL and disables WDigest cleartext credentials.
*   **Network Hardening:** Disables LLMNR, SMBv1, and RDP; blocks common malicious ports.
*   **Audit & Logging:** Enforces advanced audit policies and PowerShell Script Block/Module logging.

### 4. Automated Scheduling
*   Automatically creates a scheduled task via `schtasks.exe` to run the hunt and hardening process weekly.

## CLM Compatibility

This script is specifically engineered to run in **PowerShell Constrained Language Mode**. It avoids all restricted operations, such as:
*   `Add-Type` and direct .NET reflection.
*   Direct instantiation of non-core .NET classes.
*   Static method calls on non-core types (e.g., `[math]` or `[uri]`).
*   COM object creation (unless via approved cmdlets).

Instead, it leverages:
*   Native Windows binaries (`reg.exe`, `sc.exe`, `certutil.exe`, `netsh.exe`, `auditpol.exe`).
*   Approved CIM/WMI cmdlets for system discovery.
*   `Invoke-RestMethod` and `Invoke-WebRequest` for API interactions.

## Requirements

*   **OS:** Windows 10/11 (Compatible with Canary/Insider builds).
*   **Privileges:** Must be run as **Administrator**.
*   **Internet Access:** Required for threat feed ingestion (NVD, CISA, abuse.ch).

## Usage

1.  Open an elevated PowerShell prompt (Run as Administrator).
2.  (Optional) If testing in CLM, set the session mode:
    ```powershell
    $ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"
    ```
3.  Execute the script:
    ```powershell
    .\AdaptiveThreatHunt_Final.ps1
    ```

## Output

*   **Console:** Real-time, color-coded logging of hunt phases and hardening actions.
*   **Report:** A detailed text report is saved to `C:\AdaptiveHunt_YYYYMMDD_HHMMSS.txt`.
*   **Cache:** Threat feeds are temporarily cached in `%TEMP%\Feeds_YYYYMMDD_HHMMSS`.

## Disclaimer

This tool applies significant system hardening measures. While designed for security, some settings (like disabling Print Spooler or RDP) may impact specific workflows. Review the `PHASE 4` hardening block before deployment in production environments.

---
Developed by **Adam Rivers** for **Synthicsoft Labs**. 
*Built for security researchers and system administrators.*
