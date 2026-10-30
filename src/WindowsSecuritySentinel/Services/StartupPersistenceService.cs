using System.Diagnostics;
using System.Management;
using Microsoft.Win32;
using WindowsSecuritySentinel.Core;
using WindowsSecuritySentinel.Core.Interfaces;
using WindowsSecuritySentinel.Core.Models;

namespace WindowsSecuritySentinel.Services;

public class StartupPersistenceService : IStartupPersistenceService
{
    private readonly IElevationService _elevationService;

    public StartupPersistenceService(IElevationService elevationService)
    {
        _elevationService = elevationService;
    }

    public async Task<List<StartupItemInfo>> InspectStartupAndPersistenceAsync(
        IProgress<ScanProgressReport>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var items = new List<StartupItemInfo>();
        if (!OperatingSystem.IsWindows()) return items;

        var progressReport = new ScanProgressReport { CurrentStage = "Inspecting Windows Startup & Persistence Locations..." };
        progress?.Report(progressReport);

        await Task.Run(() =>
        {
            // 1. Registry Run and RunOnce Keys
            InspectRegistryRunKeys(items);

            // 2. Startup Folders (User & All Users)
            InspectStartupFolders(items);

            // 3. Winlogon Persistence (Userinit, Shell)
            InspectWinlogon(items);

            // 4. Non-Microsoft Auto-start Services
            InspectAutoStartServices(items);

            // 5. WMI Persistence Subscriptions
            InspectWmiSubscriptions(items);

            progressReport.CurrentStage = "Startup Inspection Completed";
            progressReport.ThreatsFoundCount = items.Count(i => i.IsSuspicious);
            progress?.Report(progressReport);
        }, cancellationToken);

        return items;
    }

    private void InspectRegistryRunKeys(List<StartupItemInfo> items)
    {
        var runPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
        };

        var hives = new[]
        {
            (Root: Registry.CurrentUser, Name: "HKCU", View: RegistryView.Default, IsElevated: false),
            (Root: Registry.LocalMachine, Name: "HKLM 64", View: RegistryView.Registry64, IsElevated: true),
            (Root: Registry.LocalMachine, Name: "HKLM 32", View: RegistryView.Registry32, IsElevated: true)
        };

        foreach (var (root, hiveName, view, isElevated) in hives)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(root == Registry.CurrentUser ? RegistryHive.CurrentUser : RegistryHive.LocalMachine, view);
                foreach (var path in runPaths)
                {
                    try
                    {
                        using var key = baseKey.OpenSubKey(path);
                        if (key == null) continue;

                        foreach (var valName in key.GetValueNames())
                        {
                            string cmd = key.GetValue(valName)?.ToString() ?? string.Empty;
                            string exe = ExtractExeFromCommand(cmd);

                            var (isValid, signer, sigDetails) = SignatureVerifier.VerifyFileSignature(exe);

                            bool isSuspicious = false;
                            string reason = string.Empty;

                            // Flag suspicious locations and encoded commands
                            string lowerCmd = cmd.ToLowerInvariant();
                            if (lowerCmd.Contains("-enc ") || lowerCmd.Contains("-encodedcommand") || lowerCmd.Contains("frombase64string") || lowerCmd.Contains("downloadstring"))
                            {
                                isSuspicious = true;
                                reason = "Encoded PowerShell or script stager detected in startup registry key.";
                            }
                            else if (!string.IsNullOrEmpty(exe) && (exe.Contains(@"\AppData\", StringComparison.OrdinalIgnoreCase) || exe.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase)) && !isValid)
                            {
                                isSuspicious = true;
                                reason = "Unsigned binary in AppData/Temp folder configured to launch automatically on logon.";
                            }

                            items.Add(new StartupItemInfo
                            {
                                Name = valName,
                                LocationType = $"Registry ({hiveName})",
                                LocationPath = $@"{hiveName}\{path}",
                                CommandOrTarget = cmd,
                                DigitalSignatureStatus = signer,
                                IsElevatedRequiredToDisable = isElevated,
                                IsSuspicious = isSuspicious,
                                SuspicionReason = reason,
                                Severity = isSuspicious ? ThreatSeverity.High : ThreatSeverity.Clean
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private void InspectStartupFolders(List<StartupItemInfo> items)
    {
        string[] startupFolders = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        };

        foreach (var folder in startupFolders)
        {
            if (!Directory.Exists(folder)) continue;
            bool isCommon = folder.Equals(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), StringComparison.OrdinalIgnoreCase);

            try
            {
                foreach (var file in Directory.GetFiles(folder))
                {
                    var (isValid, signer, _) = SignatureVerifier.VerifyFileSignature(file);
                    bool isSuspicious = false;
                    string reason = string.Empty;

                    string ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext == ".bat" || ext == ".cmd" || ext == ".ps1" || ext == ".vbs" || ext == ".js")
                    {
                        isSuspicious = true;
                        reason = "Direct script execution placed in startup folder.";
                    }
                    else if (!isValid && ext == ".exe")
                    {
                        isSuspicious = true;
                        reason = "Unsigned binary in Windows Startup directory.";
                    }

                    items.Add(new StartupItemInfo
                    {
                        Name = Path.GetFileName(file),
                        LocationType = "Startup Folder",
                        LocationPath = folder,
                        CommandOrTarget = file,
                        DigitalSignatureStatus = signer,
                        IsElevatedRequiredToDisable = isCommon,
                        IsSuspicious = isSuspicious,
                        SuspicionReason = reason,
                        Severity = isSuspicious ? ThreatSeverity.Medium : ThreatSeverity.Clean
                    });
                }
            }
            catch { }
        }
    }

    private void InspectWinlogon(List<StartupItemInfo> items)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
            if (key == null) return;

            string shell = key.GetValue("Shell")?.ToString() ?? "explorer.exe";
            string userinit = key.GetValue("Userinit")?.ToString() ?? @"C:\Windows\System32\userinit.exe,";

            bool shellTampered = !shell.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase);
            bool userinitTampered = !userinit.Contains("userinit.exe", StringComparison.OrdinalIgnoreCase);

            if (shellTampered)
            {
                items.Add(new StartupItemInfo
                {
                    Name = "Winlogon Shell Override",
                    LocationType = "Registry Winlogon",
                    LocationPath = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                    CommandOrTarget = shell,
                    IsElevatedRequiredToDisable = true,
                    IsSuspicious = true,
                    SuspicionReason = "Non-standard Windows logon Shell detected (Default is explorer.exe). Known malware hijacking vector.",
                    Severity = ThreatSeverity.Critical
                });
            }

            if (userinitTampered)
            {
                items.Add(new StartupItemInfo
                {
                    Name = "Winlogon Userinit Tampering",
                    LocationType = "Registry Winlogon",
                    LocationPath = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                    CommandOrTarget = userinit,
                    IsElevatedRequiredToDisable = true,
                    IsSuspicious = true,
                    SuspicionReason = "Tampered Userinit entry detected. Known malware persistence technique.",
                    Severity = ThreatSeverity.Critical
                });
            }
        }
        catch { }
    }

    private void InspectAutoStartServices(List<StartupItemInfo> items)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"SELECT Name, DisplayName, PathName, StartMode FROM Win32_Service WHERE StartMode = 'Auto'");
            foreach (ManagementObject obj in searcher.Get())
            {
                string name = obj["Name"]?.ToString() ?? string.Empty;
                string displayName = obj["DisplayName"]?.ToString() ?? name;
                string pathName = obj["PathName"]?.ToString() ?? string.Empty;

                string exe = ExtractExeFromCommand(pathName);
                if (string.IsNullOrEmpty(exe)) continue;

                // Ignore standard windows system32 services
                string lower = exe.ToLowerInvariant();
                if (lower.StartsWith(@"c:\windows\system32\") || lower.StartsWith(@"c:\windows\syswow64\"))
                    continue;

                var (isValid, signer, _) = SignatureVerifier.VerifyFileSignature(exe);

                bool isSuspicious = !isValid && (lower.Contains(@"\temp\") || lower.Contains(@"\appdata\"));
                string reason = isSuspicious ? "Unsigned auto-start service binary running from user or temp folder." : string.Empty;

                items.Add(new StartupItemInfo
                {
                    Name = displayName,
                    LocationType = "Windows Service (Auto-Start)",
                    LocationPath = name,
                    CommandOrTarget = pathName,
                    DigitalSignatureStatus = signer,
                    IsElevatedRequiredToDisable = true,
                    IsSuspicious = isSuspicious,
                    SuspicionReason = reason,
                    Severity = isSuspicious ? ThreatSeverity.High : ThreatSeverity.Clean
                });
            }
        }
        catch { }
    }

    private void InspectWmiSubscriptions(List<StartupItemInfo> items)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\subscription", "SELECT * FROM CommandLineEventConsumer");
            foreach (ManagementObject obj in searcher.Get())
            {
                string name = obj["Name"]?.ToString() ?? "WMI Consumer";
                string cmd = obj["CommandLineTemplate"]?.ToString() ?? string.Empty;

                items.Add(new StartupItemInfo
                {
                    Name = $"WMI Event: {name}",
                    LocationType = "WMI Subscription",
                    LocationPath = @"root\subscription\CommandLineEventConsumer",
                    CommandOrTarget = cmd,
                    DigitalSignatureStatus = "WMI Script/Command",
                    IsElevatedRequiredToDisable = true,
                    IsSuspicious = true,
                    SuspicionReason = "WMI Persistence event consumer detected. Frequently abused for stealth persistence.",
                    Severity = ThreatSeverity.High
                });
            }
        }
        catch { }
    }

    public async Task<(bool Success, string Message)> DisableStartupItemAsync(StartupItemInfo item)
    {
        return await Task.Run(() =>
        {
            try
            {
                if (item.LocationType.StartsWith("Registry (HKCU)"))
                {
                    string subKey = item.LocationPath.Substring(item.LocationPath.IndexOf(@"\") + 1);
                    using var key = Registry.CurrentUser.OpenSubKey(subKey, true);
                    if (key != null)
                    {
                        key.DeleteValue(item.Name, false);
                        item.IsEnabled = false;
                        return (true, $"Successfully disabled startup item '{item.Name}' from HKCU.");
                    }
                }
                else if (item.LocationType == "Startup Folder")
                {
                    if (File.Exists(item.CommandOrTarget))
                    {
                        File.Move(item.CommandOrTarget, item.CommandOrTarget + ".disabled");
                        item.IsEnabled = false;
                        return (true, $"Disabled startup shortcut/file: {item.Name}");
                    }
                }

                return (false, "Disabling this item requires administrative elevation or is a managed service.");
            }
            catch (Exception ex)
            {
                return (false, $"Error disabling startup item: {ex.Message}");
            }
        });
    }

    private static string ExtractExeFromCommand(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return string.Empty;
        string s = command.Trim();
        if (s.StartsWith("\""))
        {
            int nextQuote = s.IndexOf('"', 1);
            if (nextQuote > 1) return s.Substring(1, nextQuote - 1);
        }
        int space = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (space > 0) return s.Substring(0, space + 4);

        int firstSpace = s.IndexOf(' ');
        return firstSpace > 0 ? s.Substring(0, firstSpace) : s;
    }
}
