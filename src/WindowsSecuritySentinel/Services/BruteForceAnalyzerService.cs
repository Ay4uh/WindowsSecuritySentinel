using System.Diagnostics.Eventing.Reader;
using System.Text.Json;
using System.Xml.Linq;
using WindowsSecuritySentinel.Core.Interfaces;
using WindowsSecuritySentinel.Core.Models;

namespace WindowsSecuritySentinel.Services;

public class BruteForceAnalyzerService : IBruteForceAnalyzerService
{
    private readonly IElevationService _elevationService;

    public BruteForceAnalyzerService(IElevationService elevationService)
    {
        _elevationService = elevationService;
    }

    public async Task<List<BruteForceIncident>> AnalyzeLoginEventsAsync(
        TimeSpan timeWindow,
        bool requestElevationIfNeeded = false,
        IProgress<ScanProgressReport>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var incidents = new List<BruteForceIncident>();
        if (!OperatingSystem.IsWindows()) return incidents;

        var progressReport = new ScanProgressReport { CurrentStage = "Inspecting Windows Security & Authentication Logs..." };
        progress?.Report(progressReport);

        bool isElevated = _elevationService.IsCurrentProcessElevated();

        // If not elevated and elevation is requested, execute via on-demand elevated worker
        if (!isElevated && requestElevationIfNeeded)
        {
            try
            {
                progressReport.CurrentStage = "Requesting UAC elevation to query Security Event Log...";
                progress?.Report(progressReport);

                string payload = JsonSerializer.Serialize(new { Hours = (int)timeWindow.TotalHours });
                string jsonResult = await _elevationService.ExecuteElevatedTaskJsonAsync("AnalyzeLogins", payload);

                if (!string.IsNullOrEmpty(jsonResult))
                {
                    var elevatedIncidents = JsonSerializer.Deserialize<List<BruteForceIncident>>(jsonResult);
                    if (elevatedIncidents != null) return elevatedIncidents;
                }
            }
            catch (Exception ex)
            {
                // Fall back or report error
                progressReport.CurrentStage = $"Elevated query cancelled or failed: {ex.Message}";
                progress?.Report(progressReport);
            }
        }

        // Direct in-process query (Works if elevated, or queries TerminalServices operational log if standard user)
        await Task.Run(() =>
        {
            DateTime startTime = DateTime.UtcNow.Subtract(timeWindow);
            string timeString = startTime.ToString("o");

            // 1. Query Security Event Log (Requires Admin)
            if (isElevated)
            {
                try
                {
                    string xpath = $"*[System[(EventID=4625 or EventID=4624 or EventID=4740 or EventID=4776) and TimeCreated[@SystemTime >= '{timeString}']]]";
                    var query = new EventLogQuery("Security", PathType.LogName, xpath);
                    using var reader = new EventLogReader(query);

                    EventRecord? record;
                    var failureAggregator = new Dictionary<string, (int Count, DateTime LastSeen, string Ip, string Workstation, int LogonType)>();

                    while ((record = reader.ReadEvent()) != null)
                    {
                        if (cancellationToken.IsCancellationRequested) break;
                        using (record)
                        {
                            ParseSecurityRecord(record, failureAggregator, incidents);
                        }
                    }

                    // Summarize aggregated repeated failures into incidents
                    foreach (var (user, stats) in failureAggregator)
                    {
                        if (stats.Count >= 3)
                        {
                            incidents.Add(new BruteForceIncident
                            {
                                Timestamp = stats.LastSeen,
                                TargetAccount = user,
                                SourceIp = !string.IsNullOrEmpty(stats.Ip) ? stats.Ip : "Local / Loopback",
                                WorkstationName = stats.Workstation,
                                LogonTypeDescription = TranslateLogonType(stats.LogonType),
                                AttemptCount = stats.Count,
                                EventId = 4625,
                                FailureReason = "Repeated failed logon attempts (Bad password or unknown username)",
                                Severity = stats.Count > 10 ? ThreatSeverity.High : ThreatSeverity.Medium,
                                RecommendedAction = stats.LogonType == 10
                                    ? "Remote Desktop brute-force detected. Restrict RDP port or enable Network Level Authentication (NLA)."
                                    : "Investigate whether user forgot password or credentials are being brute-forced."
                            });
                        }
                    }
                }
                catch { }
            }

            // 2. Query TerminalServices-RemoteConnectionManager/Operational (Readable by Standard User!)
            try
            {
                string rdpXpath = $"*[System[EventID=1149 and TimeCreated[@SystemTime >= '{timeString}']]]";
                var rdpQuery = new EventLogQuery("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", PathType.LogName, rdpXpath);
                using var rdpReader = new EventLogReader(rdpQuery);

                EventRecord? rec;
                while ((rec = rdpReader.ReadEvent()) != null)
                {
                    if (cancellationToken.IsCancellationRequested) break;
                    using (rec)
                    {
                        ParseRdpRecord(rec, incidents);
                    }
                }
            }
            catch { }

            progressReport.CurrentStage = "Authentication Analysis Complete";
            progressReport.ThreatsFoundCount = incidents.Count;
            progress?.Report(progressReport);
        }, cancellationToken);

        return incidents;
    }

    private static void ParseSecurityRecord(
        EventRecord record,
        Dictionary<string, (int Count, DateTime LastSeen, string Ip, string Workstation, int LogonType)> failureAggregator,
        List<BruteForceIncident> incidents)
    {
        try
        {
            string xml = record.ToXml();
            var doc = XDocument.Parse(xml);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";

            var eventData = doc.Root?.Element(ns + "EventData") ?? doc.Root?.Element("EventData");
            if (eventData == null) return;

            var dataDict = eventData.Elements()
                .Where(e => e.Attribute("Name") != null)
                .ToDictionary(e => e.Attribute("Name")!.Value, e => e.Value);

            int eventId = record.Id;
            DateTime time = record.TimeCreated ?? DateTime.UtcNow;

            if (eventId == 4625) // Failed logon
            {
                string user = dataDict.GetValueOrDefault("TargetUserName", "Unknown");
                string ip = dataDict.GetValueOrDefault("IpAddress", "-");
                string workstation = dataDict.GetValueOrDefault("WorkstationName", "-");
                int.TryParse(dataDict.GetValueOrDefault("LogonType", "0"), out int logonType);

                string key = $"{user}_{ip}_{logonType}";
                if (failureAggregator.TryGetValue(key, out var cur))
                {
                    failureAggregator[key] = (cur.Count + 1, time, ip, workstation, logonType);
                }
                else
                {
                    failureAggregator[key] = (1, time, ip, workstation, logonType);
                }
            }
            else if (eventId == 4740) // Account Lockout
            {
                string targetUser = dataDict.GetValueOrDefault("TargetUserName", "Unknown");
                incidents.Add(new BruteForceIncident
                {
                    Timestamp = time,
                    TargetAccount = targetUser,
                    SourceIp = "Local / Domain Controller",
                    LogonTypeDescription = "Account Lockout Event",
                    AttemptCount = 1,
                    EventId = 4740,
                    FailureReason = "Account was locked out due to exceeding failed authentication threshold.",
                    Severity = ThreatSeverity.High,
                    RecommendedAction = "Verify account integrity, unlock if authorized, and check event source."
                });
            }
        }
        catch { }
    }

    private static void ParseRdpRecord(EventRecord record, List<BruteForceIncident> incidents)
    {
        try
        {
            string xml = record.ToXml();
            var doc = XDocument.Parse(xml);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";

            var eventData = doc.Root?.Element(ns + "EventData") ?? doc.Root?.Element("EventData");
            if (eventData == null) return;

            var dataDict = eventData.Elements()
                .Where(e => e.Attribute("Name") != null)
                .ToDictionary(e => e.Attribute("Name")!.Value, e => e.Value);

            string user = dataDict.GetValueOrDefault("Param1", "Unknown");
            string domain = dataDict.GetValueOrDefault("Param2", "");
            string sourceIp = dataDict.GetValueOrDefault("Param3", "Unknown");

            incidents.Add(new BruteForceIncident
            {
                Timestamp = record.TimeCreated ?? DateTime.UtcNow,
                TargetAccount = !string.IsNullOrEmpty(domain) ? $"{domain}\\{user}" : user,
                SourceIp = sourceIp,
                LogonTypeDescription = "RDP Connection Attempt (Event 1149)",
                AttemptCount = 1,
                EventId = 1149,
                FailureReason = "RDP connection initiated from external IP address",
                Severity = ThreatSeverity.Medium,
                RecommendedAction = "Verify if RDP connection attempt is expected. If unexpected, block source IP in Windows Firewall."
            });
        }
        catch { }
    }

    private static string TranslateLogonType(int logonType) => logonType switch
    {
        2 => "Type 2 - Interactive (Console / Local Keyboard)",
        3 => "Type 3 - Network (SMB / Shared Drive / RPC)",
        4 => "Type 4 - Batch (Scheduled Task)",
        5 => "Type 5 - Service Startup",
        7 => "Type 7 - Unlock Workstation",
        8 => "Type 8 - NetworkCleartext (IIS / Web Basic Auth)",
        9 => "Type 9 - NewCredentials (RunAs / NetUse)",
        10 => "Type 10 - RemoteInteractive (RDP / Terminal Services)",
        11 => "Type 11 - CachedInteractive",
        _ => $"Type {logonType}"
    };
}
