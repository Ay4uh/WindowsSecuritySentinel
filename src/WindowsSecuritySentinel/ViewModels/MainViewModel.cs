using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WindowsSecuritySentinel.Core.Interfaces;
using WindowsSecuritySentinel.Core.Models;

namespace WindowsSecuritySentinel.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly IDefenderService _defenderService;
    private readonly IMalwareScannerService _malwareScannerService;
    private readonly IRemoteAccessDetectorService _remoteAccessService;
    private readonly IStartupPersistenceService _startupService;
    private readonly INetworkAnalyzerService _networkService;
    private readonly IBruteForceAnalyzerService _bruteForceService;
    private readonly IQuarantineService _quarantineService;
    private readonly IElevationService _elevationService;
    private readonly IReportService _reportService;

    private CancellationTokenSource? _scanCts;

    [ObservableProperty]
    private string _currentView = "Dashboard";

    [ObservableProperty]
    private string _statusHeader = "System Protected";

    [ObservableProperty]
    private ThreatSeverity _overallStatusSeverity = ThreatSeverity.Clean;

    [ObservableProperty]
    private string _lastScanTime = "Never";

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private int _scanProgress;

    [ObservableProperty]
    private string _scanStage = "Idle";

    [ObservableProperty]
    private string _scanCurrentItem = "";

    [ObservableProperty]
    private long _scanFilesCount;

    [ObservableProperty]
    private int _threatsDetectedCount;

    [ObservableProperty]
    private string _scanElapsedTime = "00:00";

    // Dashboard Counters
    [ObservableProperty]
    private int _detectedThreatsCount;

    [ObservableProperty]
    private int _suspiciousAppsCount;

    [ObservableProperty]
    private int _remoteAccessAppsCount;

    [ObservableProperty]
    private int _failedLoginsCount;

    [ObservableProperty]
    private bool _isElevated;

    // Defender Status
    [ObservableProperty]
    private DefenderStatusInfo _defenderStatus = new();

    // Firewall Status
    [ObservableProperty]
    private string _firewallSummary = "Checking...";

    // Collections for Views
    public ObservableCollection<SecurityFinding> Findings { get; } = new();
    public ObservableCollection<RemoteAccessToolInfo> RemoteAccessTools { get; } = new();
    public ObservableCollection<StartupItemInfo> StartupItems { get; } = new();
    public ObservableCollection<NetworkConnectionInfo> NetworkConnections { get; } = new();
    public ObservableCollection<BruteForceIncident> LoginIncidents { get; } = new();
    public ObservableCollection<QuarantineEntry> QuarantineEntries { get; } = new();
    public ObservableCollection<ScanReport> ScanHistory { get; } = new();

    [ObservableProperty]
    private SecurityFinding? _selectedFinding;

    [ObservableProperty]
    private RemoteAccessToolInfo? _selectedRemoteTool;

    [ObservableProperty]
    private StartupItemInfo? _selectedStartupItem;

    [ObservableProperty]
    private QuarantineEntry? _selectedQuarantineEntry;

    public MainViewModel(
        IDefenderService defenderService,
        IMalwareScannerService malwareScannerService,
        IRemoteAccessDetectorService remoteAccessService,
        IStartupPersistenceService startupService,
        INetworkAnalyzerService networkService,
        IBruteForceAnalyzerService bruteForceService,
        IQuarantineService quarantineService,
        IElevationService elevationService,
        IReportService reportService)
    {
        _defenderService = defenderService;
        _malwareScannerService = malwareScannerService;
        _remoteAccessService = remoteAccessService;
        _startupService = startupService;
        _networkService = networkService;
        _bruteForceService = bruteForceService;
        _quarantineService = quarantineService;
        _elevationService = elevationService;
        _reportService = reportService;

        IsElevated = _elevationService.IsCurrentProcessElevated();
    }

    [RelayCommand]
    public async Task InitializeAsync()
    {
        await _reportService.InitializeDatabaseAsync();
        await RefreshDashboardAsync();
        await LoadQuarantineAsync();
        await LoadHistoryAsync();
    }

    [RelayCommand]
    public async Task RefreshDashboardAsync()
    {
        IsElevated = _elevationService.IsCurrentProcessElevated();

        // 1. Fetch Defender Status
        DefenderStatus = await _defenderService.GetDefenderStatusAsync();

        // 2. Fetch Firewall Status
        var (dom, priv, pub) = await _networkService.GetFirewallStatusAsync();
        FirewallSummary = (dom && priv && pub) ? "Protected (Domain, Private, Public ON)" : "Partial / Disabled Warning";

        // 3. Quick count of RMM
        var rmm = await _remoteAccessService.DetectRemoteAccessToolsAsync();
        RemoteAccessAppsCount = rmm.Count;
        RemoteAccessTools.Clear();
        foreach (var r in rmm) RemoteAccessTools.Add(r);

        // 4. Update overall status severity
        if (DefenderStatus.ActiveThreats.Count > 0 || Findings.Any(f => f.Severity == ThreatSeverity.Critical))
        {
            OverallStatusSeverity = ThreatSeverity.Critical;
            StatusHeader = "Action Required: Active Security Threats Detected";
        }
        else if (rmm.Any(r => r.RiskLevel == ThreatSeverity.Critical || r.RiskLevel == ThreatSeverity.High))
        {
            OverallStatusSeverity = ThreatSeverity.High;
            StatusHeader = "High Risk: Unauthorized Remote Access Software Detected";
        }
        else if (DefenderStatus.SignatureAgeInDays > 5 || !dom || !priv || !pub)
        {
            OverallStatusSeverity = ThreatSeverity.Medium;
            StatusHeader = "Security Notice: Updates or Firewall Adjustments Needed";
        }
        else
        {
            OverallStatusSeverity = ThreatSeverity.Clean;
            StatusHeader = "System Protected and Operational";
        }
    }

    [RelayCommand]
    public void Navigate(string viewName)
    {
        CurrentView = viewName;
    }

    #region Scan Commands
    [RelayCommand]
    public async Task StartQuickScanAsync() => await ExecuteScanAsync(ScanType.Quick);

    [RelayCommand]
    public async Task StartFullScanAsync() => await ExecuteScanAsync(ScanType.Full);

    [RelayCommand]
    public async Task StartCustomScanAsync()
    {
        // Default to AppData & Temp if no dialog shown
        await ExecuteScanAsync(ScanType.Custom, new[] { Path.GetTempPath(), Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) });
    }

    private async Task ExecuteScanAsync(ScanType type, IEnumerable<string>? customPaths = null)
    {
        if (IsScanning) return;

        IsScanning = true;
        _scanCts = new CancellationTokenSource();
        CurrentView = "Scanner";
        Findings.Clear();

        var progress = new Progress<ScanProgressReport>(report =>
        {
            ScanStage = report.CurrentStage;
            ScanCurrentItem = report.CurrentItemPath;
            ScanProgress = report.ProgressPercentage;
            ScanFilesCount = report.ItemsExaminedCount;
            ThreatsDetectedCount = report.ThreatsFoundCount;
            ScanElapsedTime = $"{report.ElapsedTime.Minutes:00}:{report.ElapsedTime.Seconds:00}";
        });

        try
        {
            var report = await _malwareScannerService.RunScanAsync(type, customPaths, progress, _scanCts.Token);
            report.WasElevated = IsElevated;

            foreach (var f in report.Findings)
            {
                Findings.Add(f);
            }

            DetectedThreatsCount = Findings.Count;
            LastScanTime = $"{DateTime.Now:yyyy-MM-dd HH:mm}";

            await _reportService.SaveScanReportAsync(report);
            await LoadHistoryAsync();
        }
        catch (OperationCanceledException)
        {
            ScanStage = "Scan Cancelled by User";
        }
        catch (Exception ex)
        {
            ScanStage = $"Scan Failed: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
            await RefreshDashboardAsync();
        }
    }

    [RelayCommand]
    public void CancelScan()
    {
        _scanCts?.Cancel();
    }
    #endregion

    #region Dedicated Feature Scanners
    [RelayCommand]
    public async Task ScanRemoteAccessAsync()
    {
        CurrentView = "RemoteAccess";
        var progress = new Progress<ScanProgressReport>(p => ScanStage = p.CurrentStage);
        var tools = await _remoteAccessService.DetectRemoteAccessToolsAsync(progress);
        RemoteAccessTools.Clear();
        foreach (var t in tools) RemoteAccessTools.Add(t);
        RemoteAccessAppsCount = tools.Count;
    }

    [RelayCommand]
    public async Task NeutralizeSelectedRmmAsync()
    {
        if (SelectedRemoteTool == null) return;
        var (ok, msg) = await _remoteAccessService.NeutralizeRmmInstanceAsync(SelectedRemoteTool);
        await ScanRemoteAccessAsync();
        await RefreshDashboardAsync();
    }

    [RelayCommand]
    public async Task ScanStartupAsync()
    {
        CurrentView = "Startup";
        var progress = new Progress<ScanProgressReport>(p => ScanStage = p.CurrentStage);
        var items = await _startupService.InspectStartupAndPersistenceAsync(progress);
        StartupItems.Clear();
        foreach (var item in items) StartupItems.Add(item);
        SuspiciousAppsCount = items.Count(i => i.IsSuspicious);
    }

    [RelayCommand]
    public async Task DisableSelectedStartupItemAsync()
    {
        if (SelectedStartupItem == null) return;
        var (ok, msg) = await _startupService.DisableStartupItemAsync(SelectedStartupItem);
        await ScanStartupAsync();
    }

    [RelayCommand]
    public async Task ScanNetworkAsync()
    {
        CurrentView = "Network";
        var progress = new Progress<ScanProgressReport>(p => ScanStage = p.CurrentStage);
        var conns = await _networkService.AnalyzeConnectionsAsync(progress);
        NetworkConnections.Clear();
        foreach (var c in conns) NetworkConnections.Add(c);
    }

    [RelayCommand]
    public async Task ScanLoginsAsync()
    {
        CurrentView = "BruteForce";
        var progress = new Progress<ScanProgressReport>(p => ScanStage = p.CurrentStage);
        var incidents = await _bruteForceService.AnalyzeLoginEventsAsync(TimeSpan.FromDays(7), false, progress);
        LoginIncidents.Clear();
        foreach (var inc in incidents) LoginIncidents.Add(inc);
        FailedLoginsCount = incidents.Count;
    }

    [RelayCommand]
    public async Task ScanLoginsElevatedAsync()
    {
        CurrentView = "BruteForce";
        var progress = new Progress<ScanProgressReport>(p => ScanStage = p.CurrentStage);
        var incidents = await _bruteForceService.AnalyzeLoginEventsAsync(TimeSpan.FromDays(7), true, progress);
        LoginIncidents.Clear();
        foreach (var inc in incidents) LoginIncidents.Add(inc);
        FailedLoginsCount = incidents.Count;
        IsElevated = _elevationService.IsCurrentProcessElevated();
    }

    [RelayCommand]
    public async Task RunDefenderQuickScanAsync()
    {
        CurrentView = "Defender";
        ScanStage = "Initiating Windows Defender scan...";
        await _defenderService.StartScanAsync(ScanType.Quick);
        DefenderStatus = await _defenderService.GetDefenderStatusAsync();
    }

    [RelayCommand]
    public async Task UpdateDefenderSignaturesAsync()
    {
        ScanStage = "Updating Defender signatures...";
        await _defenderService.UpdateSignaturesAsync();
        DefenderStatus = await _defenderService.GetDefenderStatusAsync();
        await RefreshDashboardAsync();
    }

    [RelayCommand]
    public void OpenDefenderSecurityCenter()
    {
        _defenderService.OpenWindowsSecurityCenter();
    }
    #endregion

    #region Quarantine & Remediation
    [RelayCommand]
    public async Task QuarantineSelectedFindingAsync()
    {
        if (SelectedFinding == null || string.IsNullOrEmpty(SelectedFinding.TargetPath)) return;

        var (ok, msg, entry) = await _quarantineService.QuarantineFileAsync(
            SelectedFinding.TargetPath,
            SelectedFinding.Category,
            SelectedFinding.Title,
            SelectedFinding.Evidence);

        if (ok && entry != null)
        {
            SelectedFinding.IsRemediated = true;
            SelectedFinding.RemediationNotes = msg;
            await _reportService.SaveFindingRemediationAsync(SelectedFinding.Id, msg);
            await LoadQuarantineAsync();
        }
    }

    [RelayCommand]
    public async Task RestoreSelectedQuarantineAsync()
    {
        if (SelectedQuarantineEntry == null) return;
        var (ok, msg) = await _quarantineService.RestoreFileAsync(SelectedQuarantineEntry.QuarantineId);
        await LoadQuarantineAsync();
    }

    [RelayCommand]
    public async Task PurgeSelectedQuarantineAsync()
    {
        if (SelectedQuarantineEntry == null) return;
        var (ok, msg) = await _quarantineService.PermanentlyDeleteAsync(SelectedQuarantineEntry.QuarantineId);
        await LoadQuarantineAsync();
    }

    private async Task LoadQuarantineAsync()
    {
        var entries = await _quarantineService.GetQuarantineEntriesAsync();
        QuarantineEntries.Clear();
        foreach (var e in entries) QuarantineEntries.Add(e);
    }
    #endregion

    #region Reports & History
    private async Task LoadHistoryAsync()
    {
        var list = await _reportService.GetScanHistoryAsync();
        ScanHistory.Clear();
        foreach (var item in list) ScanHistory.Add(item);
    }

    [RelayCommand]
    public void ExportReportHtml(ScanReport? report)
    {
        report ??= ScanHistory.FirstOrDefault();
        if (report == null) return;

        string html = _reportService.ExportToHtml(report);
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"Sentinel_Report_{report.ScanId}.html");
        File.WriteAllText(path, html);

        Process.Start(new ProcessStartInfo { FileName = path, UseShellExecute = true });
    }

    [RelayCommand]
    public void ExportReportCsv(ScanReport? report)
    {
        report ??= ScanHistory.FirstOrDefault();
        if (report == null) return;

        string csv = _reportService.ExportToCsv(report);
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"Sentinel_Report_{report.ScanId}.csv");
        File.WriteAllText(path, csv);

        Process.Start(new ProcessStartInfo { FileName = path, UseShellExecute = true });
    }
    #endregion
}
