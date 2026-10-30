using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using WindowsSecuritySentinel.Core;
using WindowsSecuritySentinel.Core.Interfaces;
using WindowsSecuritySentinel.Core.Models;

namespace WindowsSecuritySentinel.Services;

public class NetworkAnalyzerService : INetworkAnalyzerService
{
    private static readonly HashSet<string> LolBins = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "cmd.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "cscript.exe", "wscript.exe", "certutil.exe", "bitsadmin.exe"
    };

    public async Task<List<NetworkConnectionInfo>> AnalyzeConnectionsAsync(
        IProgress<ScanProgressReport>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var connections = new List<NetworkConnectionInfo>();
        if (!OperatingSystem.IsWindows()) return connections;

        var progressReport = new ScanProgressReport { CurrentStage = "Inspecting Native P/Invoke TCP/UDP Socket Tables..." };
        progress?.Report(progressReport);

        await Task.Run(() =>
        {
            // 1. Get Extended TCP Table
            GetTcpConnections(connections);

            // 2. Get Extended UDP Table
            GetUdpEndpoints(connections);

            // 3. Correlate PIDs to Process Names, Executable Paths, Signatures, and Heuristics
            var procMap = new Dictionary<int, (string Name, string Path, string Signer, bool IsValid)>();

            foreach (var conn in connections)
            {
                if (cancellationToken.IsCancellationRequested) break;
                if (conn.ProcessId <= 4)
                {
                    conn.ProcessName = conn.ProcessId == 0 ? "System Idle" : "System";
                    conn.ExecutablePath = "ntoskrnl.exe";
                    conn.DigitalSignatureStatus = "Microsoft Windows";
                    continue;
                }

                if (!procMap.TryGetValue(conn.ProcessId, out var pInfo))
                {
                    try
                    {
                        using var proc = Process.GetProcessById(conn.ProcessId);
                        string pName = proc.ProcessName;
                        string? exePath = null;
                        try { exePath = proc.MainModule?.FileName; } catch { }

                        var (isValid, signer, _) = SignatureVerifier.VerifyFileSignature(exePath ?? string.Empty);
                        pInfo = (pName, exePath ?? string.Empty, signer, isValid);
                        procMap[conn.ProcessId] = pInfo;
                    }
                    catch
                    {
                        pInfo = ("Unknown / Terminated", string.Empty, "Inaccessible", false);
                        procMap[conn.ProcessId] = pInfo;
                    }
                }

                conn.ProcessName = pInfo.Name;
                conn.ExecutablePath = pInfo.Path;
                conn.DigitalSignatureStatus = pInfo.Signer;

                // Evaluate Heuristics
                string lowerExe = Path.GetFileName(pInfo.Path).ToLowerInvariant();
                string fullPathLower = pInfo.Path.ToLowerInvariant();

                bool isLolBin = LolBins.Contains(lowerExe);
                bool inTempOrApp = fullPathLower.Contains(@"\temp\") || fullPathLower.Contains(@"\appdata\");

                if (isLolBin && conn.State == "ESTABLISHED" && !conn.RemoteAddress.StartsWith("127.") && conn.RemoteAddress != "::1")
                {
                    conn.IsSuspicious = true;
                    conn.SuspicionReason = $"LOLBin ({lowerExe}) with active external socket connection.";
                    conn.Severity = ThreatSeverity.High;
                }
                else if (inTempOrApp && !pInfo.IsValid && conn.State == "ESTABLISHED")
                {
                    conn.IsSuspicious = true;
                    conn.SuspicionReason = "Unsigned process running from user/temp directory maintaining active external connection.";
                    conn.Severity = ThreatSeverity.High;
                }
                else if (conn.State == "LISTEN" && conn.LocalAddress == "0.0.0.0" && conn.LocalPort > 1024 && !pInfo.IsValid && inTempOrApp)
                {
                    conn.IsSuspicious = true;
                    conn.SuspicionReason = "Unsigned process in temporary directory listening on all network interfaces (0.0.0.0).";
                    conn.Severity = ThreatSeverity.Medium;
                }
            }

            progressReport.CurrentStage = "Network Analysis Completed";
            progressReport.ThreatsFoundCount = connections.Count(c => c.IsSuspicious);
            progress?.Report(progressReport);
        }, cancellationToken);

        return connections;
    }

    private void GetTcpConnections(List<NetworkConnectionInfo> list)
    {
        int bufferSize = 0;
        uint ret = NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, NativeMethods.AF_INET, NativeMethods.TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);

        IntPtr pTable = Marshal.AllocHGlobal(bufferSize);
        try
        {
            ret = NativeMethods.GetExtendedTcpTable(pTable, ref bufferSize, true, NativeMethods.AF_INET, NativeMethods.TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0) return;

            int numEntries = Marshal.ReadInt32(pTable);
            IntPtr pRow = IntPtr.Add(pTable, 4);

            int rowSize = Marshal.SizeOf(typeof(NativeMethods.MIB_TCPROW_OWNER_PID));

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<NativeMethods.MIB_TCPROW_OWNER_PID>(pRow);
                pRow = IntPtr.Add(pRow, rowSize);

                list.Add(new NetworkConnectionInfo
                {
                    Protocol = "TCP",
                    LocalAddress = new IPAddress(row.localAddr).ToString(),
                    LocalPort = row.LocalPort,
                    RemoteAddress = new IPAddress(row.remoteAddr).ToString(),
                    RemotePort = row.RemotePort,
                    State = ResolveTcpState(row.state),
                    ProcessId = (int)row.owningPid
                });
            }
        }
        catch { }
        finally
        {
            Marshal.FreeHGlobal(pTable);
        }
    }

    private void GetUdpEndpoints(List<NetworkConnectionInfo> list)
    {
        int bufferSize = 0;
        uint ret = NativeMethods.GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, NativeMethods.AF_INET, NativeMethods.UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);

        IntPtr pTable = Marshal.AllocHGlobal(bufferSize);
        try
        {
            ret = NativeMethods.GetExtendedUdpTable(pTable, ref bufferSize, true, NativeMethods.AF_INET, NativeMethods.UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            if (ret != 0) return;

            int numEntries = Marshal.ReadInt32(pTable);
            IntPtr pRow = IntPtr.Add(pTable, 4);
            int rowSize = Marshal.SizeOf(typeof(NativeMethods.MIB_UDPROW_OWNER_PID));

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<NativeMethods.MIB_UDPROW_OWNER_PID>(pRow);
                pRow = IntPtr.Add(pRow, rowSize);

                list.Add(new NetworkConnectionInfo
                {
                    Protocol = "UDP",
                    LocalAddress = new IPAddress(row.localAddr).ToString(),
                    LocalPort = row.LocalPort,
                    RemoteAddress = "*",
                    RemotePort = 0,
                    State = "UDP",
                    ProcessId = (int)row.owningPid
                });
            }
        }
        catch { }
        finally
        {
            Marshal.FreeHGlobal(pTable);
        }
    }

    private static string ResolveTcpState(uint state) => state switch
    {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => $"STATE_{state}"
    };

    public async Task<(bool Domain, bool Private, bool Public)> GetFirewallStatusAsync()
    {
        return await Task.Run(() =>
        {
            bool domain = true, priv = true, pub = true;
            if (!OperatingSystem.IsWindows()) return (domain, priv, pub);

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy");
                if (key != null)
                {
                    using var domKey = key.OpenSubKey("DomainProfile");
                    if (domKey != null) domain = Convert.ToInt32(domKey.GetValue("EnableFirewall", 1)) == 1;

                    using var privKey = key.OpenSubKey("StandardProfile");
                    if (privKey != null) priv = Convert.ToInt32(privKey.GetValue("EnableFirewall", 1)) == 1;

                    using var pubKey = key.OpenSubKey("PublicProfile");
                    if (pubKey != null) pub = Convert.ToInt32(pubKey.GetValue("EnableFirewall", 1)) == 1;
                }
            }
            catch { }

            return (domain, priv, pub);
        });
    }

    public async Task<List<string>> GetDnsServersAsync()
    {
        return await Task.Run(() =>
        {
            var servers = new List<string>();
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus == OperationalStatus.Up && nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        var ipProps = nic.GetIPProperties();
                        foreach (var dns in ipProps.DnsAddresses)
                        {
                            servers.Add($"{nic.Name}: {dns}");
                        }
                    }
                }
            }
            catch { }
            return servers;
        });
    }
}
