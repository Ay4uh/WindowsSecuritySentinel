namespace WindowsSecuritySentinel.Core.Models;

public enum ThreatSeverity
{
    Clean,
    Low,
    Medium,
    High,
    Critical,
    Unknown
}

public enum ScanType
{
    Quick,
    Full,
    Custom,
    RemoteAccess,
    Startup,
    Network,
    BruteForce,
    Defender
}

public enum RemediationAction
{
    None,
    QuarantineFile,
    DeleteFile,
    TerminateProcess,
    DisableStartupItem,
    StopAndDisableService,
    NeutralizeRmmInstance,
    BlockFirewallRule,
    RestoreQuarantine
}

public class SecurityFinding
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Category { get; set; } = string.Empty; // Malware, RMM, Startup, Network, BruteForce, Ransomware, Defender
    public string Title { get; set; } = string.Empty;
    public ThreatSeverity Severity { get; set; } = ThreatSeverity.Medium;
    public string Description { get; set; } = string.Empty;
    public string Evidence { get; set; } = string.Empty;
    public string RecommendedAction { get; set; } = string.Empty;
    public string? TargetPath { get; set; }
    public string? Sha256Hash { get; set; }
    public string? DigitalSignatureStatus { get; set; }
    public int? ProcessId { get; set; }
    public string? ServiceName { get; set; }
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    public bool IsRemediated { get; set; }
    public string? RemediationNotes { get; set; }
}

public class ScanProgressReport
{
    public string CurrentStage { get; set; } = string.Empty;
    public string CurrentItemPath { get; set; } = string.Empty;
    public int ProgressPercentage { get; set; }
    public long ItemsExaminedCount { get; set; }
    public int ThreatsFoundCount { get; set; }
    public TimeSpan ElapsedTime { get; set; }
    public bool IsIndeterminate { get; set; }
}

public class ScanReport
{
    public string ScanId { get; set; } = Guid.NewGuid().ToString("N");
    public ScanType Type { get; set; }
    public DateTime StartTime { get; set; } = DateTime.UtcNow;
    public DateTime EndTime { get; set; } = DateTime.UtcNow;
    public TimeSpan Duration => EndTime - StartTime;
    public string MachineName { get; set; } = Environment.MachineName;
    public string WindowsVersion { get; set; } = Environment.OSVersion.VersionString;
    public bool WasElevated { get; set; }
    public long TotalFilesScanned { get; set; }
    public List<SecurityFinding> Findings { get; set; } = new();
    public List<string> SkippedLocations { get; set; } = new();
}

public class RemoteAccessToolInfo
{
    public string InstanceId { get; set; } = string.Empty;
    public string ToolName { get; set; } = string.Empty;
    public string InstallType { get; set; } = string.Empty; // Standard, Portable, ClickOnce, Service
    public string Visibility { get; set; } = string.Empty; // Visible in Installed Apps, Hidden via SystemComponent=1, Portable / Uninstalled
    public string ExecutablePath { get; set; } = string.Empty;
    public string DigitalSignatureStatus { get; set; } = string.Empty;
    public string UnattendedAccessStatus { get; set; } = "Unknown"; // Enabled, Disabled, Unknown
    public string? RelayHost { get; set; }
    public int? RelayPort { get; set; }
    public string? SessionGuidOrId { get; set; }
    public string? InstanceThumbprint { get; set; }
    public string? AssociatedServiceName { get; set; }
    public List<string> AssociatedTasks { get; set; } = new();
    public List<string> FirewallRules { get; set; } = new();
    public List<string> RecentIncomingConnections { get; set; } = new();
    public ThreatSeverity RiskLevel { get; set; } = ThreatSeverity.Low;
    public string RecommendedAction { get; set; } = string.Empty;
    public bool IsHiddenComponent { get; set; }
    public bool IsMultipleInstance { get; set; }
}

public class StartupItemInfo
{
    public string Name { get; set; } = string.Empty;
    public string LocationType { get; set; } = string.Empty; // Registry Run, Startup Folder, Scheduled Task, Service, Winlogon, WMI
    public string LocationPath { get; set; } = string.Empty;
    public string CommandOrTarget { get; set; } = string.Empty;
    public string Arguments { get; set; } = string.Empty;
    public string DigitalSignatureStatus { get; set; } = string.Empty;
    public bool IsElevatedRequiredToDisable { get; set; }
    public bool IsSuspicious { get; set; }
    public string SuspicionReason { get; set; } = string.Empty;
    public ThreatSeverity Severity { get; set; } = ThreatSeverity.Clean;
    public bool IsEnabled { get; set; } = true;
}

public class NetworkConnectionInfo
{
    public string Protocol { get; set; } = "TCP";
    public string LocalAddress { get; set; } = string.Empty;
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = string.Empty;
    public int RemotePort { get; set; }
    public string State { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string ExecutablePath { get; set; } = string.Empty;
    public string DigitalSignatureStatus { get; set; } = string.Empty;
    public bool IsSuspicious { get; set; }
    public string SuspicionReason { get; set; } = string.Empty;
    public ThreatSeverity Severity { get; set; } = ThreatSeverity.Clean;
}

public class BruteForceIncident
{
    public DateTime Timestamp { get; set; }
    public string TargetAccount { get; set; } = string.Empty;
    public string SourceIp { get; set; } = string.Empty;
    public string WorkstationName { get; set; } = string.Empty;
    public string LogonTypeDescription { get; set; } = string.Empty;
    public int AttemptCount { get; set; } = 1;
    public int EventId { get; set; }
    public string FailureReason { get; set; } = string.Empty;
    public ThreatSeverity Severity { get; set; } = ThreatSeverity.Low;
    public string RecommendedAction { get; set; } = string.Empty;
    public bool SucceededAfterFailures { get; set; }
}

public class QuarantineEntry
{
    public string QuarantineId { get; set; } = Guid.NewGuid().ToString("N");
    public string OriginalPath { get; set; } = string.Empty;
    public string QuarantinedFileName { get; set; } = string.Empty;
    public string QuarantinedFilePath { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public string Sha256Hash { get; set; } = string.Empty;
    public DateTime QuarantinedAt { get; set; } = DateTime.UtcNow;
    public string ThreatCategory { get; set; } = string.Empty;
    public string ThreatTitle { get; set; } = string.Empty;
    public string BackupMetadataJson { get; set; } = string.Empty;
    public bool IsRestored { get; set; }
}

public class DefenderStatusInfo
{
    public bool IsDefenderInstalled { get; set; }
    public bool AntivirusEnabled { get; set; }
    public bool RealTimeProtectionEnabled { get; set; }
    public bool AntispywareEnabled { get; set; }
    public bool BehaviorMonitorEnabled { get; set; }
    public bool IoavProtectionEnabled { get; set; }
    public bool TamperProtectionEnabled { get; set; }
    public bool ControlledFolderAccessEnabled { get; set; }
    public string AntivirusSignatureVersion { get; set; } = string.Empty;
    public DateTime AntivirusSignatureLastUpdated { get; set; }
    public int SignatureAgeInDays { get; set; }
    public string ThirdPartyAntivirusName { get; set; } = string.Empty;
    public bool IsThirdPartyAvActive { get; set; }
    public string EngineVersion { get; set; } = string.Empty;
    public List<DefenderThreatInfo> ActiveThreats { get; set; } = new();
}

public class DefenderThreatInfo
{
    public string ThreatId { get; set; } = string.Empty;
    public string ThreatName { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string ResourcePath { get; set; } = string.Empty;
    public DateTime DetectionTime { get; set; }
}
