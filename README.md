# Windows Security Sentinel

A lightweight, enterprise-grade Windows security scanner, forensic analysis tool, and threat remediation utility built with C#, .NET 8.0, and WPF.

---

## 🛡️ Core Highlights & Architecture

- **Platform:** Windows 10 & Windows 11 (64-bit).
- **Target Framework:** `.NET 8.0-windows` (WPF desktop UI).
- **Architecture:** Clean MVVM (`CommunityToolkit.Mvvm`), modular services, decoupled asynchronous tasks.
- **Privilege Model:** Standard-User Startup (`asInvoker`). Launches instantly without UAC prompt. Privileged operations (Security Event Log querying, elevated service stopping) execute on-demand via `--elevated-task` headless worker.
- **Zero Heavy Dependencies:** Native Win32 P/Invoke (`iphlpapi.dll`, `wintrust.dll`, `crypt32.dll`), WMI (`System.Management`), and `Microsoft.Data.Sqlite` for 100% local persistent history.

---

## 🚀 Key Modules & Capabilities

### 1. Main Dashboard
- Real-time overall security health assessment.
- Microsoft Defender status (signatures, real-time protection, signature age).
- Windows Firewall configuration check (Domain, Private, Public profiles).
- Quick metrics for active threats, suspicious startup entries, remote access tools, and failed logins.
- 10 distinct security scanning & inspection actions wired to live logic.

### 2. High-Performance Malware & Heuristic Scanner
- Inspects executables, scripts (`.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.hta`), and loaded modules.
- **Dual Authenticode & Windows Catalog Verification:** Uses `WinVerifyTrust` and `CryptCATAdminCalcHashFromFileHandle` to verify both embedded certificates and native Windows `.cat` catalog signatures (zero false positives on native system files).
- Checks known malicious SHA-256 hashes (including standard EICAR test definitions).
- Non-blocking asynchronous scanning with `EnumerationOptions` ignoring inaccessible paths and NTFS reparse points/junctions.

### 3. Remote Access & Tech-Support Scam Deep Forensics
- **Hidden Uninstall Entries:** Detects RMM tools with `SystemComponent = 1` hidden from Windows Settings.
- **ScreenConnect / ConnectWise Control:** Extracts Relay Host (`h=`), Relay Port (`p=`), Session GUID (`s=`), 16-hex instance thumbprint, and flags multiple concurrent instances.
- **AnyDesk Forensic Parser:** Checks `service.conf` and `system.conf` for active unattended access password hashes (`ad.security.pwd_hash`), and parses `ad.trace` for recent incoming sessions.
- **RustDesk, TeamViewer, UltraViewer, Supremo:** Inspects self-hosted relay servers and trace files.
- **One-Click Neutralization:** Terminates processes, stops and disables services, invalidates configuration files, and cleans leftover firewall rules.

### 4. Windows Login & Brute-Force Analysis
- XPath event log querying for Event ID 4625 (Failed logon), 4624 (Logon), 4740 (Account lockout), and RDP Event ID 1149.
- Translates logon types into human-readable descriptions (e.g., `Type 10 - RemoteInteractive / RDP`).
- Analyzes TerminalServices operational logs as a standard user, with an on-demand elevation button to query the Security log.

### 5. Startup & Persistence Inspection
- Inspects `Run`, `RunOnce`, `Policies\Explorer\Run` across 64-bit and 32-bit hives.
- Scans user and common Startup folders.
- Checks Winlogon `Userinit` and `Shell` tampering.
- Flags non-Microsoft auto-start services and WMI `CommandLineEventConsumer` persistence.

### 6. Native Network & Port Inspection
- Uses native P/Invoke (`GetExtendedTcpTable`, `GetExtendedUdpTable` from `iphlpapi.dll`) to map active sockets to PIDs without requiring administrative privileges.
- Flags Living-off-the-Land Binaries (LOLBins) with external socket connections.

### 7. Quarantine Vault
- Neutralizes malicious files using local XOR-obfuscation and renames them to `<GUID>.qtn`.
- Hardcoded safety guard protecting `C:\Windows\System32` and `WinSxS`.
- Bit-for-bit restoration with cryptographic SHA-256 validation.

### 8. SQLite Reports & History
- Persistent local SQLite database (`sentinel.db`).
- Standalone HTML reports with clean modern typography and badge styling.
- CSV export for integration with external SIEM or analysis pipelines.

---

## 🛠️ Build & Publication Instructions

### Prerequisites
- Windows 10/11 x64
- .NET 8.0 SDK (or Visual Studio 2022 with .NET desktop development workload)

### Compiling & Running
```cmd
# 1. Restore and build
dotnet build WindowsSecuritySentinel.sln -c Release

# 2. Run the application
dotnet run --project src\WindowsSecuritySentinel\WindowsSecuritySentinel.csproj
```

### Self-Contained Deployment
```cmd
# Publish a self-contained release executable
dotnet publish src\WindowsSecuritySentinel\WindowsSecuritySentinel.csproj -c Release -r win-x64 --self-contained false -o bin\Release\Publish
```

---

## 🔒 Privilege & Security Model
1. **asInvoker:** The app manifest ensures that standard users can launch the UI instantly without privilege elevation prompts.
2. **On-Demand Elevation:** When privileged system tasks are required (e.g. deep Security event log reading or terminating protected system services), the application launches an internal worker with verb `runas`:
   ```cmd
   WindowsSecuritySentinel.exe --elevated-task <TaskName> --input <Input.json> --output <Output.json>
   ```
   The GUI reads the structured JSON response and updates the UI seamlessly without requiring an entire application restart.
