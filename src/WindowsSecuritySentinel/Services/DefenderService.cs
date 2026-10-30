using System.Diagnostics;
using System.Management;
using WindowsSecuritySentinel.Core.Interfaces;
using WindowsSecuritySentinel.Core.Models;

namespace WindowsSecuritySentinel.Services;

public class DefenderService : IDefenderService
{
    public async Task<DefenderStatusInfo> GetDefenderStatusAsync()
    {
        var status = new DefenderStatusInfo();

        if (!OperatingSystem.IsWindows())
            return status;

        await Task.Run(() =>
        {
            // 1. Check SecurityCenter2 for third party antivirus
            try
            {
                using var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntivirusProduct");
                foreach (ManagementObject obj in searcher.Get())
                {
                    string displayName = obj["displayName"]?.ToString() ?? string.Empty;
                    uint productState = obj["productState"] != null ? Convert.ToUInt32(obj["productState"]) : 0;

                    // productState is a bitmask: bits indicate on/off/snoozed/updated
                    if (!string.IsNullOrEmpty(displayName) && !displayName.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase))
                    {
                        status.ThirdPartyAntivirusName = displayName;
                        status.IsThirdPartyAvActive = true;
                    }
                }
            }
            catch
            {
                // SecurityCenter2 may not be accessible or available on Windows Server
            }

            // 2. Query root\Microsoft\Windows\Defender: MSFT_MpComputerStatus
            try
            {
                using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpComputerStatus");
                foreach (ManagementObject obj in searcher.Get())
                {
                    status.IsDefenderInstalled = true;
                    status.AntivirusEnabled = Convert.ToBoolean(obj["AntivirusEnabled"] ?? false);
                    status.RealTimeProtectionEnabled = Convert.ToBoolean(obj["RealTimeProtectionEnabled"] ?? false);
                    status.AntispywareEnabled = Convert.ToBoolean(obj["AntispywareEnabled"] ?? false);
                    status.BehaviorMonitorEnabled = Convert.ToBoolean(obj["BehaviorMonitorEnabled"] ?? false);
                    status.IoavProtectionEnabled = Convert.ToBoolean(obj["IoavProtectionEnabled"] ?? false);
                    status.TamperProtectionEnabled = Convert.ToBoolean(obj["IsTamperProtected"] ?? false);
                    status.AntivirusSignatureVersion = obj["AntivirusSignatureVersion"]?.ToString() ?? "Unknown";
                    status.EngineVersion = obj["AMEngineVersion"]?.ToString() ?? "Unknown";

                    if (obj["AntivirusSignatureLastUpdated"] != null)
                    {
                        try
                        {
                            string dts = obj["AntivirusSignatureLastUpdated"].ToString()!;
                            status.AntivirusSignatureLastUpdated = ManagementDateTimeConverter.ToDateTime(dts);
                            status.SignatureAgeInDays = Math.Max(0, (int)(DateTime.UtcNow - status.AntivirusSignatureLastUpdated).TotalDays);
                        }
                        catch
                        {
                            status.AntivirusSignatureLastUpdated = DateTime.UtcNow;
                        }
                    }
                    break;
                }
            }
            catch
            {
                // Defender WMI namespace may fail if defender service is stopped or disabled
            }

            // 3. Query Controlled Folder Access via MSFT_MpPreference
            try
            {
                using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT EnableControlledFolderAccess FROM MSFT_MpPreference");
                foreach (ManagementObject obj in searcher.Get())
                {
                    int cfa = Convert.ToInt32(obj["EnableControlledFolderAccess"] ?? 0);
                    status.ControlledFolderAccessEnabled = (cfa == 1);
                    break;
                }
            }
            catch { }
        });

        // 4. Retrieve Active Threats
        try
        {
            status.ActiveThreats = await GetActiveThreatsAsync();
        }
        catch { }

        return status;
    }

    public async Task<List<DefenderThreatInfo>> GetActiveThreatsAsync()
    {
        var threats = new List<DefenderThreatInfo>();
        if (!OperatingSystem.IsWindows()) return threats;

        await Task.Run(() =>
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpThreatDetection");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var threat = new DefenderThreatInfo
                    {
                        ThreatId = obj["ThreatID"]?.ToString() ?? string.Empty,
                        ThreatName = obj["ThreatName"]?.ToString() ?? "Unknown Threat",
                        Severity = obj["ThreatSeverityID"]?.ToString() switch
                        {
                            "1" => "Low",
                            "2" => "Medium",
                            "3" => "High",
                            "4" => "Severe",
                            _ => "Unknown"
                        },
                        Category = obj["DetectionSourceTypeID"]?.ToString() ?? "RealTime",
                        ResourcePath = obj["Resources"] is string[] res && res.Length > 0 ? res[0] : (obj["Resources"]?.ToString() ?? string.Empty)
                    };

                    if (obj["InitialDetectionTime"] != null)
                    {
                        try
                        {
                            threat.DetectionTime = ManagementDateTimeConverter.ToDateTime(obj["InitialDetectionTime"].ToString()!);
                        }
                        catch { threat.DetectionTime = DateTime.UtcNow; }
                    }

                    threats.Add(threat);
                }
            }
            catch { }
        });

        return threats;
    }

    public async Task<bool> UpdateSignaturesAsync(IProgress<string>? progress = null)
    {
        if (!OperatingSystem.IsWindows()) return false;

        progress?.Report("Triggering Microsoft Defender signature update via MpCmdRun.exe...");

        string mpCmdRunPath = LocateMpCmdRun();
        if (string.IsNullOrEmpty(mpCmdRunPath) || !File.Exists(mpCmdRunPath))
        {
            progress?.Report("MpCmdRun.exe not found. Attempting PowerShell Update-MpSignature...");
            return await RunPowerShellAsync("Update-MpSignature");
        }

        return await Task.Run(() =>
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = mpCmdRunPath,
                    Arguments = "-SignatureUpdate",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var process = Process.Start(psi);
                if (process == null) return false;

                process.WaitForExit(90000); // 90 second timeout for signature downloads
                return process.ExitCode == 0;
            }
            catch (Exception ex)
            {
                progress?.Report($"Signature update failed: {ex.Message}");
                return false;
            }
        });
    }

    public async Task<bool> StartScanAsync(ScanType type, string? customPath = null, IProgress<string>? progress = null, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows()) return false;

        string mpCmdRunPath = LocateMpCmdRun();
        string scanArg = type switch
        {
            ScanType.Quick => "-Scan -ScanType 1",
            ScanType.Full => "-Scan -ScanType 2",
            ScanType.Custom when !string.IsNullOrEmpty(customPath) => $"-Scan -ScanType 3 -File \"{customPath}\"",
            _ => "-Scan -ScanType 1"
        };

        progress?.Report($"Initiating Defender scan ({type})...");

        if (string.IsNullOrEmpty(mpCmdRunPath) || !File.Exists(mpCmdRunPath))
        {
            string psScanType = type == ScanType.Full ? "FullScan" : (type == ScanType.Custom ? "CustomScan" : "QuickScan");
            string cmd = type == ScanType.Custom && !string.IsNullOrEmpty(customPath)
                ? $"Start-MpScan -ScanType CustomScan -ScanPath '{customPath.Replace("'", "''")}'"
                : $"Start-MpScan -ScanType {psScanType}";
            return await RunPowerShellAsync(cmd);
        }

        return await Task.Run(() =>
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = mpCmdRunPath,
                    Arguments = scanArg,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var process = Process.Start(psi);
                if (process == null) return false;

                while (!process.HasExited)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        try { process.Kill(true); } catch { }
                        return false;
                    }
                    Thread.Sleep(500);
                }

                return process.ExitCode == 0;
            }
            catch (Exception ex)
            {
                progress?.Report($"Defender scan error: {ex.Message}");
                return false;
            }
        }, cancellationToken);
    }

    public void OpenWindowsSecurityCenter()
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "windowsdefender:",
                UseShellExecute = true
            });
        }
        catch
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "ms-settings:windowsdefender",
                    UseShellExecute = true
                });
            }
            catch { }
        }
    }

    private static string LocateMpCmdRun()
    {
        string programDataPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows Defender\Platform");
        if (Directory.Exists(programDataPath))
        {
            // Pick the latest platform version directory
            var subDirs = Directory.GetDirectories(programDataPath)
                .OrderByDescending(d => d)
                .ToList();

            foreach (var dir in subDirs)
            {
                string exe = Path.Combine(dir, "MpCmdRun.exe");
                if (File.Exists(exe)) return exe;
            }
        }

        string defaultPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Windows Defender\MpCmdRun.exe");
        if (File.Exists(defaultPath)) return defaultPath;

        return string.Empty;
    }

    private static async Task<bool> RunPowerShellAsync(string script)
    {
        return await Task.Run(() =>
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{script}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var p = Process.Start(psi);
                if (p == null) return false;
                p.WaitForExit(120000);
                return p.ExitCode == 0;
            }
            catch { return false; }
        });
    }
}
