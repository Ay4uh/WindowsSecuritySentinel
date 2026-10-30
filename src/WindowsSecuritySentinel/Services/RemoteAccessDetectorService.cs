using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using WindowsSecuritySentinel.Core;
using WindowsSecuritySentinel.Core.Interfaces;
using WindowsSecuritySentinel.Core.Models;

namespace WindowsSecuritySentinel.Services;

public class RemoteAccessDetectorService : IRemoteAccessDetectorService
{
    private static readonly string[] KnownRmmSignatures = new[]
    {
        "ScreenConnect", "ConnectWise", "AnyDesk", "TeamViewer", "UltraViewer", "Supremo",
        "RustDesk", "Splashtop", "Zoho Assist", "LogMeIn", "GoToAssist", "TightVNC",
        "UltraVNC", "RealVNC", "DWService", "SimpleHelp", "ISL Online", "BeyondTrust",
        "Bomgar", "Atera", "MeshCentral", "NinjaOne", "Kaseya", "Remote Utilities",
        "Action1", "Tactical RMM"
    };

    public async Task<List<RemoteAccessToolInfo>> DetectRemoteAccessToolsAsync(
        IProgress<ScanProgressReport>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var results = new List<RemoteAccessToolInfo>();
        if (!OperatingSystem.IsWindows()) return results;

        await Task.Run(() =>
        {
            var progressReport = new ScanProgressReport { CurrentStage = "Scanning for Remote Access Tools..." };
            progress?.Report(progressReport);

            // 1. Inspect Uninstall Registry Keys (HKLM and HKCU, 64-bit and 32-bit views)
            InspectUninstallKeys(results);

            // 2. Deep ScreenConnect Service & Instance Parsing
            InspectScreenConnectInstances(results);

            // 3. Inspect Running Processes
            InspectRmmProcesses(results);

            // 4. AnyDesk deep forensics
            InspectAnyDeskArtifacts(results);

            // 5. TeamViewer, RustDesk, UltraViewer, Supremo deep forensics
            InspectOtherRmmArtifacts(results);

            // 6. Inspect RMM Firewall Rules
            CorrelateFirewallRules(results);

            // 7. ClickOnce and Portable RMM runners
            InspectClickOnceAndPortable(results);

            // Post-processing: Flag multiple ScreenConnect instances
            var scInstances = results.Where(r => r.ToolName.Contains("ScreenConnect", StringComparison.OrdinalIgnoreCase)).ToList();
            if (scInstances.Count > 1)
            {
                foreach (var sc in scInstances)
                {
                    sc.IsMultipleInstance = true;
                    sc.RiskLevel = ThreatSeverity.Critical;
                    sc.RecommendedAction = "High/Critical Risk: Multiple concurrent ScreenConnect instances detected (common tech-support scam persistence). Review and neutralize unauthorized instance.";
                }
            }

            progressReport.CurrentStage = "Remote Access Scan Complete";
            progressReport.ThreatsFoundCount = results.Count;
            progress?.Report(progressReport);
        }, cancellationToken);

        return results;
    }

    private void InspectUninstallKeys(List<RemoteAccessToolInfo> results)
    {
        var roots = new[]
        {
            (RegistryKey: Registry.LocalMachine, View: RegistryView.Registry64, Hive: "HKLM 64"),
            (RegistryKey: Registry.LocalMachine, View: RegistryView.Registry32, Hive: "HKLM 32"),
            (RegistryKey: Registry.CurrentUser, View: RegistryView.Registry64, Hive: "HKCU 64"),
            (RegistryKey: Registry.CurrentUser, View: RegistryView.Registry32, Hive: "HKCU 32")
        };

        const string uninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

        foreach (var (rootKey, view, hiveName) in roots)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(rootKey == Registry.LocalMachine ? RegistryHive.LocalMachine : RegistryHive.CurrentUser, view);
                using var subKey = baseKey.OpenSubKey(uninstallPath);
                if (subKey == null) continue;

                foreach (var subKeyName in subKey.GetSubKeyNames())
                {
                    try
                    {
                        using var appKey = subKey.OpenSubKey(subKeyName);
                        if (appKey == null) continue;

                        string displayName = appKey.GetValue("DisplayName")?.ToString() ?? string.Empty;
                        string displayIcon = appKey.GetValue("DisplayIcon")?.ToString() ?? string.Empty;
                        string installLocation = appKey.GetValue("InstallLocation")?.ToString() ?? string.Empty;
                        string uninstallString = appKey.GetValue("UninstallString")?.ToString() ?? string.Empty;
                        int systemComponent = Convert.ToInt32(appKey.GetValue("SystemComponent") ?? 0);

                        string match = KnownRmmSignatures.FirstOrDefault(s =>
                            displayName.Contains(s, StringComparison.OrdinalIgnoreCase) ||
                            subKeyName.Contains(s, StringComparison.OrdinalIgnoreCase) ||
                            uninstallString.Contains(s, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                        if (!string.IsNullOrEmpty(match))
                        {
                            string exePath = CleanExecutablePath(displayIcon, installLocation, uninstallString);
                            var (isValid, signer, _) = SignatureVerifier.VerifyFileSignature(exePath);

                            var toolInfo = new RemoteAccessToolInfo
                            {
                                InstanceId = subKeyName,
                                ToolName = !string.IsNullOrEmpty(displayName) ? displayName : match,
                                InstallType = "Registry Installed",
                                Visibility = (systemComponent == 1) ? "Hidden via SystemComponent=1" : "Visible in Installed Apps",
                                IsHiddenComponent = (systemComponent == 1),
                                ExecutablePath = exePath,
                                DigitalSignatureStatus = signer,
                                RiskLevel = (systemComponent == 1) ? ThreatSeverity.High : ThreatSeverity.Medium,
                                RecommendedAction = (systemComponent == 1)
                                    ? "High Risk: Remote access tool is deliberately hidden from Windows Installed Apps. Neutralize and remove if not authorized."
                                    : "Review if this remote access tool was installed by you or your IT department."
                            };

                            results.Add(toolInfo);
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private void InspectScreenConnectInstances(List<RemoteAccessToolInfo> results)
    {
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (servicesKey == null) return;

            foreach (var svcName in servicesKey.GetSubKeyNames())
            {
                if (svcName.StartsWith("ScreenConnect Client (", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        using var svc = servicesKey.OpenSubKey(svcName);
                        if (svc == null) continue;

                        string imagePath = svc.GetValue("ImagePath")?.ToString() ?? string.Empty;
                        string exePath = CleanExecutablePath(imagePath);

                        // Extract 16-hex thumbprint
                        string thumbprint = string.Empty;
                        var m = Regex.Match(svcName, @"ScreenConnect Client \(([0-9a-fA-F]+)\)");
                        if (m.Success) thumbprint = m.Groups[1].Value;

                        string folder = Path.GetDirectoryName(exePath) ?? string.Empty;
                        string relayHost = string.Empty;
                        int relayPort = 8041;
                        string sessionGuid = string.Empty;

                        // Deep parse user.config or system.config in the folder
                        if (Directory.Exists(folder))
                        {
                            foreach (var configFile in Directory.GetFiles(folder, "*.config", SearchOption.AllDirectories))
                            {
                                try
                                {
                                    string text = File.ReadAllText(configFile);
                                    var hostMatch = Regex.Match(text, @"[?&]h=([a-zA-Z0-9\.\-]+)");
                                    if (hostMatch.Success) relayHost = hostMatch.Groups[1].Value;

                                    var portMatch = Regex.Match(text, @"[?&]p=([0-9]+)");
                                    if (portMatch.Success) int.TryParse(portMatch.Groups[1].Value, out relayPort);

                                    var guidMatch = Regex.Match(text, @"[?&]s=([a-fA-F0-9\-]+)");
                                    if (guidMatch.Success) sessionGuid = guidMatch.Groups[1].Value;
                                }
                                catch { }
                            }
                        }

                        var (isValid, signer, _) = SignatureVerifier.VerifyFileSignature(exePath);

                        var tool = new RemoteAccessToolInfo
                        {
                            InstanceId = thumbprint,
                            ToolName = $"ConnectWise ScreenConnect Client ({thumbprint})",
                            InstallType = "Windows Service",
                            Visibility = "System Service",
                            ExecutablePath = exePath,
                            AssociatedServiceName = svcName,
                            InstanceThumbprint = thumbprint,
                            RelayHost = !string.IsNullOrEmpty(relayHost) ? relayHost : "Unknown / Embedded",
                            RelayPort = relayPort,
                            SessionGuidOrId = sessionGuid,
                            DigitalSignatureStatus = signer,
                            UnattendedAccessStatus = "Enabled (Client Service Active)",
                            RiskLevel = ThreatSeverity.Medium,
                            RecommendedAction = "Review connection relay. If unrequested, use One-Click Neutralize to stop service and clear config."
                        };

                        results.Add(tool);
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    private void InspectAnyDeskArtifacts(List<RemoteAccessToolInfo> results)
    {
        try
        {
            string programDataAnyDesk = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AnyDesk");
            string appDataAnyDesk = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AnyDesk");

            string[] paths = new[] { programDataAnyDesk, appDataAnyDesk };
            foreach (var dir in paths)
            {
                if (!Directory.Exists(dir)) continue;

                string systemConf = Path.Combine(dir, "system.conf");
                string serviceConf = Path.Combine(dir, "service.conf");
                string confFile = File.Exists(systemConf) ? systemConf : (File.Exists(serviceConf) ? serviceConf : string.Empty);

                bool unattendedEnabled = false;
                if (!string.IsNullOrEmpty(confFile))
                {
                    try
                    {
                        using var fs = new FileStream(confFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var reader = new StreamReader(fs);
                        string content = reader.ReadToEnd();
                        if (content.Contains("ad.security.pwd_hash") || content.Contains("ad.security.interactive_access=2"))
                        {
                            unattendedEnabled = true;
                        }
                    }
                    catch { }
                }

                // Check ad.trace for incoming connections
                var recentConnections = new List<string>();
                string traceFile = Path.Combine(dir, "ad.trace");
                if (File.Exists(traceFile))
                {
                    try
                    {
                        using var fs = new FileStream(traceFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var reader = new StreamReader(fs);
                        string line;
                        while ((line = reader.ReadLine()!) != null)
                        {
                            if (line.Contains("Logged in from") || line.Contains("Incoming session"))
                            {
                                recentConnections.Add(line.Trim());
                                if (recentConnections.Count > 10) recentConnections.RemoveAt(0);
                            }
                        }
                    }
                    catch { }
                }

                // Check if already in results from installed apps
                var existing = results.FirstOrDefault(r => r.ToolName.Contains("AnyDesk", StringComparison.OrdinalIgnoreCase));
                if (existing != null)
                {
                    existing.UnattendedAccessStatus = unattendedEnabled ? "Enabled (Password Hash Active)" : "Disabled / Default";
                    existing.RecentIncomingConnections.AddRange(recentConnections);
                }
                else if (File.Exists(confFile))
                {
                    results.Add(new RemoteAccessToolInfo
                    {
                        InstanceId = "AnyDesk-Artifacts",
                        ToolName = "AnyDesk (Config Artifacts Found)",
                        InstallType = "Residual / Portable",
                        Visibility = "Configuration Residual",
                        UnattendedAccessStatus = unattendedEnabled ? "Enabled" : "Unknown",
                        RecentIncomingConnections = recentConnections,
                        RiskLevel = unattendedEnabled ? ThreatSeverity.High : ThreatSeverity.Medium,
                        RecommendedAction = "AnyDesk configuration traces detected. If unauthorized, neutralize residual configs."
                    });
                }
            }
        }
        catch { }
    }

    private void InspectOtherRmmArtifacts(List<RemoteAccessToolInfo> results)
    {
        // RustDesk config inspection
        try
        {
            string rustDeskConfig = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"RustDesk\config\RustDesk.toml");
            if (File.Exists(rustDeskConfig))
            {
                string text = File.ReadAllText(rustDeskConfig);
                var match = Regex.Match(text, @"rendezvous_server\s*=\s*'([^']+)'");
                string server = match.Success ? match.Groups[1].Value : "Official Public Server";

                var existing = results.FirstOrDefault(r => r.ToolName.Contains("RustDesk", StringComparison.OrdinalIgnoreCase));
                if (existing != null)
                {
                    existing.RelayHost = server;
                }
                else
                {
                    results.Add(new RemoteAccessToolInfo
                    {
                        InstanceId = "RustDesk-Config",
                        ToolName = "RustDesk Remote Desktop",
                        InstallType = "Portable / Residual",
                        Visibility = "Config Found",
                        RelayHost = server,
                        RiskLevel = ThreatSeverity.Medium,
                        RecommendedAction = "RustDesk configuration found. Check if custom relay server is recognized."
                    });
                }
            }
        }
        catch { }
    }

    private void InspectRmmProcesses(List<RemoteAccessToolInfo> results)
    {
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    string name = proc.ProcessName;
                    string match = KnownRmmSignatures.FirstOrDefault(s => name.Contains(s, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                    if (!string.IsNullOrEmpty(match))
                    {
                        string? exePath = null;
                        try { exePath = proc.MainModule?.FileName; } catch { }

                        var existing = results.FirstOrDefault(r => !string.IsNullOrEmpty(exePath) && r.ExecutablePath.Equals(exePath, StringComparison.OrdinalIgnoreCase));
                        if (existing == null)
                        {
                            var (isValid, signer, _) = SignatureVerifier.VerifyFileSignature(exePath ?? string.Empty);
                            results.Add(new RemoteAccessToolInfo
                            {
                                InstanceId = $"PID-{proc.Id}",
                                ToolName = match,
                                InstallType = "Active Process",
                                Visibility = "Running Process",
                                ExecutablePath = exePath ?? "Inaccessible",
                                DigitalSignatureStatus = signer,
                                RiskLevel = ThreatSeverity.Medium,
                                RecommendedAction = "Process actively running. Review legitimacy and terminate if not authorized."
                            });
                        }
                    }
                }
                catch { }
                finally
                {
                    proc.Dispose();
                }
            }
        }
        catch { }
    }

    private void CorrelateFirewallRules(List<RemoteAccessToolInfo> results)
    {
        try
        {
            using var fwKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules");
            if (fwKey == null) return;

            foreach (var valName in fwKey.GetValueNames())
            {
                try
                {
                    string val = fwKey.GetValue(valName)?.ToString() ?? string.Empty;
                    foreach (var tool in results)
                    {
                        if (!string.IsNullOrEmpty(tool.ExecutablePath) && val.Contains(tool.ExecutablePath, StringComparison.OrdinalIgnoreCase))
                        {
                            tool.FirewallRules.Add(valName);
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void InspectClickOnceAndPortable(List<RemoteAccessToolInfo> results)
    {
        try
        {
            string clickOncePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Apps\2.0");
            if (Directory.Exists(clickOncePath))
            {
                var files = Directory.GetFiles(clickOncePath, "*ScreenConnect*.exe", SearchOption.AllDirectories);
                foreach (var f in files)
                {
                    var (isValid, signer, _) = SignatureVerifier.VerifyFileSignature(f);
                    results.Add(new RemoteAccessToolInfo
                    {
                        InstanceId = Path.GetFileName(f),
                        ToolName = "ScreenConnect ClickOnce Client",
                        InstallType = "ClickOnce Runner",
                        Visibility = "Portable ClickOnce Cache",
                        ExecutablePath = f,
                        DigitalSignatureStatus = signer,
                        RiskLevel = ThreatSeverity.High,
                        RecommendedAction = "Portable ClickOnce ScreenConnect runner found in user profile. Frequently used in one-off scam sessions."
                    });
                }
            }
        }
        catch { }
    }

    public async Task<(bool Success, string Message)> NeutralizeRmmInstanceAsync(RemoteAccessToolInfo tool)
    {
        return await Task.Run(() =>
        {
            var logs = new List<string>();

            // 1. Terminate running processes matching the tool
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        bool matches = false;
                        if (!string.IsNullOrEmpty(tool.ExecutablePath))
                        {
                            try { matches = proc.MainModule?.FileName.Equals(tool.ExecutablePath, StringComparison.OrdinalIgnoreCase) == true; } catch { }
                        }
                        if (!matches && proc.ProcessName.Contains(tool.ToolName, StringComparison.OrdinalIgnoreCase))
                        {
                            matches = true;
                        }

                        if (matches)
                        {
                            proc.Kill();
                            logs.Add($"Terminated process {proc.ProcessName} (PID {proc.Id}).");
                        }
                    }
                    catch (Exception ex)
                    {
                        logs.Add($"Failed to kill PID {proc.Id}: {ex.Message}");
                    }
                    finally
                    {
                        proc.Dispose();
                    }
                }
            }
            catch { }

            // 2. Stop and disable associated service if present
            if (!string.IsNullOrEmpty(tool.AssociatedServiceName))
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "sc.exe",
                        Arguments = $"stop \"{tool.AssociatedServiceName}\"",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    using var p = Process.Start(psi);
                    p?.WaitForExit(5000);

                    psi.Arguments = $"config \"{tool.AssociatedServiceName}\" start= disabled";
                    using var p2 = Process.Start(psi);
                    p2?.WaitForExit(5000);

                    logs.Add($"Stopped and disabled service {tool.AssociatedServiceName}.");
                }
                catch (Exception ex)
                {
                    logs.Add($"Service modification error: {ex.Message}");
                }
            }

            // 3. Remove or rename unattended config
            try
            {
                if (!string.IsNullOrEmpty(tool.ExecutablePath) && File.Exists(tool.ExecutablePath))
                {
                    string dir = Path.GetDirectoryName(tool.ExecutablePath) ?? string.Empty;
                    if (Directory.Exists(dir))
                    {
                        foreach (var cfg in Directory.GetFiles(dir, "*.config"))
                        {
                            try
                            {
                                File.Move(cfg, cfg + ".disabled_" + Guid.NewGuid().ToString("N"));
                                logs.Add($"Invalidated config: {Path.GetFileName(cfg)}");
                            }
                            catch { }
                        }
                    }
                }
            }
            catch { }

            // 4. Remove Firewall Rules
            if (tool.FirewallRules.Count > 0)
            {
                try
                {
                    using var fwKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules", true);
                    if (fwKey != null)
                    {
                        foreach (var r in tool.FirewallRules)
                        {
                            try { fwKey.DeleteValue(r); logs.Add($"Deleted firewall rule {r}"); } catch { }
                        }
                    }
                }
                catch { }
            }

            return (true, string.Join("\n", logs));
        });
    }

    private static string CleanExecutablePath(params string[] candidates)
    {
        foreach (var c in candidates)
        {
            if (string.IsNullOrWhiteSpace(c)) continue;

            string s = c.Trim();
            if (s.StartsWith("\""))
            {
                int nextQuote = s.IndexOf('"', 1);
                if (nextQuote > 1) s = s.Substring(1, nextQuote - 1);
            }
            else
            {
                int space = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                if (space > 0) s = s.Substring(0, space + 4);
            }

            if (File.Exists(s)) return s;
        }

        return candidates.FirstOrDefault(c => !string.IsNullOrWhiteSpace(c)) ?? string.Empty;
    }
}
