using WindowsSecuritySentinel.Core.Models;

namespace WindowsSecuritySentinel.Core.Interfaces;

public interface IDefenderService
{
    Task<DefenderStatusInfo> GetDefenderStatusAsync();
    Task<bool> UpdateSignaturesAsync(IProgress<string>? progress = null);
    Task<bool> StartScanAsync(ScanType type, string? customPath = null, IProgress<string>? progress = null, CancellationToken cancellationToken = default);
    Task<List<DefenderThreatInfo>> GetActiveThreatsAsync();
    void OpenWindowsSecurityCenter();
}

public interface IMalwareScannerService
{
    Task<ScanReport> RunScanAsync(
        ScanType scanType,
        IEnumerable<string>? customPaths,
        IProgress<ScanProgressReport> progress,
        CancellationToken cancellationToken);
}

public interface IRemoteAccessDetectorService
{
    Task<List<RemoteAccessToolInfo>> DetectRemoteAccessToolsAsync(
        IProgress<ScanProgressReport>? progress = null,
        CancellationToken cancellationToken = default);

    Task<(bool Success, string Message)> NeutralizeRmmInstanceAsync(RemoteAccessToolInfo tool);
}

public interface IStartupPersistenceService
{
    Task<List<StartupItemInfo>> InspectStartupAndPersistenceAsync(
        IProgress<ScanProgressReport>? progress = null,
        CancellationToken cancellationToken = default);

    Task<(bool Success, string Message)> DisableStartupItemAsync(StartupItemInfo item);
}

public interface INetworkAnalyzerService
{
    Task<List<NetworkConnectionInfo>> AnalyzeConnectionsAsync(
        IProgress<ScanProgressReport>? progress = null,
        CancellationToken cancellationToken = default);

    Task<(bool Domain, bool Private, bool Public)> GetFirewallStatusAsync();
    Task<List<string>> GetDnsServersAsync();
}

public interface IBruteForceAnalyzerService
{
    Task<List<BruteForceIncident>> AnalyzeLoginEventsAsync(
        TimeSpan timeWindow,
        bool requestElevationIfNeeded = false,
        IProgress<ScanProgressReport>? progress = null,
        CancellationToken cancellationToken = default);
}

public interface IQuarantineService
{
    string QuarantineDirectory { get; }
    Task<List<QuarantineEntry>> GetQuarantineEntriesAsync();
    Task<(bool Success, string Message, QuarantineEntry? Entry)> QuarantineFileAsync(
        string filePath,
        string threatCategory,
        string threatTitle,
        string? associatedMetadataJson = null);
    Task<(bool Success, string Message)> RestoreFileAsync(string quarantineId);
    Task<(bool Success, string Message)> PermanentlyDeleteAsync(string quarantineId);
}

public interface IElevationService
{
    bool IsCurrentProcessElevated();
    Task<string> ExecuteElevatedTaskJsonAsync(string taskName, string? inputPayload = null);
}

public interface IReportService
{
    Task InitializeDatabaseAsync();
    Task SaveScanReportAsync(ScanReport report);
    Task<List<ScanReport>> GetScanHistoryAsync(int limit = 50);
    Task SaveFindingRemediationAsync(string findingId, string remediationNotes);
    string ExportToHtml(ScanReport report);
    string ExportToCsv(ScanReport report);
}
