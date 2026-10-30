using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using WindowsSecuritySentinel.Core.Interfaces;
using WindowsSecuritySentinel.Core.Models;

namespace WindowsSecuritySentinel.Services;

public class ReportService : IReportService
{
    private readonly string _connectionString;

    public ReportService()
    {
        string baseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WindowsSecuritySentinel");
        Directory.CreateDirectory(baseDir);
        string dbPath = Path.Combine(baseDir, "sentinel.db");
        _connectionString = $"Data Source={dbPath}";
    }

    public async Task InitializeDatabaseAsync()
    {
        using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync();

        string ddl = @"
            CREATE TABLE IF NOT EXISTS ScanReports (
                ScanId TEXT PRIMARY KEY,
                ScanType INTEGER,
                StartTime TEXT,
                EndTime TEXT,
                MachineName TEXT,
                WindowsVersion TEXT,
                WasElevated INTEGER,
                TotalFilesScanned INTEGER,
                FindingsJson TEXT,
                SkippedLocationsJson TEXT
            );

            CREATE TABLE IF NOT EXISTS QuarantineEntries (
                QuarantineId TEXT PRIMARY KEY,
                OriginalPath TEXT,
                QuarantinedFileName TEXT,
                QuarantinedFilePath TEXT,
                FileSizeBytes INTEGER,
                Sha256Hash TEXT,
                QuarantinedAt TEXT,
                ThreatCategory TEXT,
                ThreatTitle TEXT,
                BackupMetadataJson TEXT,
                IsRestored INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS RemediationAuditLogs (
                LogId TEXT PRIMARY KEY,
                FindingId TEXT,
                ActionTaken TEXT,
                Timestamp TEXT,
                Details TEXT
            );
        ";

        using var cmd = new SqliteCommand(ddl, conn);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task SaveScanReportAsync(ScanReport report)
    {
        try
        {
            using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync();

            string sql = @"INSERT INTO ScanReports (ScanId, ScanType, StartTime, EndTime, MachineName, WindowsVersion, WasElevated, TotalFilesScanned, FindingsJson, SkippedLocationsJson)
                           VALUES (@id, @type, @start, @end, @machine, @os, @elevated, @total, @findings, @skipped)";

            using var cmd = new SqliteCommand(sql, conn);
            cmd.Parameters.AddWithValue("@id", report.ScanId);
            cmd.Parameters.AddWithValue("@type", (int)report.Type);
            cmd.Parameters.AddWithValue("@start", report.StartTime.ToString("o"));
            cmd.Parameters.AddWithValue("@end", report.EndTime.ToString("o"));
            cmd.Parameters.AddWithValue("@machine", report.MachineName);
            cmd.Parameters.AddWithValue("@os", report.WindowsVersion);
            cmd.Parameters.AddWithValue("@elevated", report.WasElevated ? 1 : 0);
            cmd.Parameters.AddWithValue("@total", report.TotalFilesScanned);
            cmd.Parameters.AddWithValue("@findings", JsonSerializer.Serialize(report.Findings));
            cmd.Parameters.AddWithValue("@skipped", JsonSerializer.Serialize(report.SkippedLocations));

            await cmd.ExecuteNonQueryAsync();
        }
        catch { }
    }

    public async Task<List<ScanReport>> GetScanHistoryAsync(int limit = 50)
    {
        var list = new List<ScanReport>();
        try
        {
            using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync();

            string sql = $"SELECT ScanId, ScanType, StartTime, EndTime, MachineName, WindowsVersion, WasElevated, TotalFilesScanned, FindingsJson, SkippedLocationsJson FROM ScanReports ORDER BY StartTime DESC LIMIT {limit}";
            using var cmd = new SqliteCommand(sql, conn);
            using var reader = await cmd.ExecuteReaderAsync();

            while (await reader.ReadAsync())
            {
                var r = new ScanReport
                {
                    ScanId = reader.GetString(0),
                    Type = (ScanType)reader.GetInt32(1),
                    StartTime = DateTime.Parse(reader.GetString(2)),
                    EndTime = DateTime.Parse(reader.GetString(3)),
                    MachineName = reader.GetString(4),
                    WindowsVersion = reader.GetString(5),
                    WasElevated = reader.GetInt32(6) == 1,
                    TotalFilesScanned = reader.GetInt64(7)
                };

                string findingsJson = reader.GetString(8);
                if (!string.IsNullOrEmpty(findingsJson))
                {
                    r.Findings = JsonSerializer.Deserialize<List<SecurityFinding>>(findingsJson) ?? new();
                }

                string skippedJson = reader.GetString(9);
                if (!string.IsNullOrEmpty(skippedJson))
                {
                    r.SkippedLocations = JsonSerializer.Deserialize<List<string>>(skippedJson) ?? new();
                }

                list.Add(r);
            }
        }
        catch { }

        return list;
    }

    public async Task SaveFindingRemediationAsync(string findingId, string remediationNotes)
    {
        try
        {
            using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync();

            string sql = @"INSERT INTO RemediationAuditLogs (LogId, FindingId, ActionTaken, Timestamp, Details)
                           VALUES (@lid, @fid, @action, @time, @details)";
            using var cmd = new SqliteCommand(sql, conn);
            cmd.Parameters.AddWithValue("@lid", Guid.NewGuid().ToString("N"));
            cmd.Parameters.AddWithValue("@fid", findingId);
            cmd.Parameters.AddWithValue("@action", "Remediation Executed");
            cmd.Parameters.AddWithValue("@time", DateTime.UtcNow.ToString("o"));
            cmd.Parameters.AddWithValue("@details", remediationNotes);
            await cmd.ExecuteNonQueryAsync();
        }
        catch { }
    }

    public string ExportToHtml(ScanReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("  <meta charset=\"UTF-8\">");
        sb.AppendLine($" <title>Security Report - {report.ScanId}</title>");
        sb.AppendLine("  <style>");
        sb.AppendLine("    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #F8FAFC; color: #0F172A; margin: 0; padding: 24px; }");
        sb.AppendLine("    .container { max-width: 1000px; margin: 0 auto; background: #FFFFFF; border-radius: 8px; border: 1px solid #E2E8F0; padding: 32px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }");
        sb.AppendLine("    .header { border-bottom: 2px solid #E2E8F0; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; }");
        sb.AppendLine("    .title { font-size: 24px; font-weight: 700; color: #0284C7; }");
        sb.AppendLine("    .meta-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; background: #F1F5F9; padding: 16px; border-radius: 6px; margin-bottom: 24px; }");
        sb.AppendLine("    .meta-item { font-size: 13px; }");
        sb.AppendLine("    .meta-label { color: #64748B; font-weight: 600; text-transform: uppercase; font-size: 11px; }");
        sb.AppendLine("    .meta-val { font-weight: 600; color: #0F172A; font-size: 14px; margin-top: 2px; }");
        sb.AppendLine("    table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }");
        sb.AppendLine("    th { background: #F8FAFC; text-align: left; padding: 10px 12px; border-bottom: 2px solid #E2E8F0; color: #475569; }");
        sb.AppendLine("    td { padding: 10px 12px; border-bottom: 1px solid #E2E8F0; vertical-align: top; }");
        sb.AppendLine("    .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; text-transform: uppercase; }");
        sb.AppendLine("    .badge-Critical { background: #FEE2E2; color: #991B1B; }");
        sb.AppendLine("    .badge-High { background: #FFEDD5; color: #9A3412; }");
        sb.AppendLine("    .badge-Medium { background: #FEF3C7; color: #92400E; }");
        sb.AppendLine("    .badge-Low { background: #E0F2FE; color: #075985; }");
        sb.AppendLine("    .badge-Clean { background: #DCFCE7; color: #166534; }");
        sb.AppendLine("    .code { font-family: monospace; background: #F1F5F9; padding: 2px 4px; border-radius: 3px; font-size: 12px; word-break: break-all; }");
        sb.AppendLine("  </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine("  <div class=\"container\">");
        sb.AppendLine("    <div class=\"header\">");
        sb.AppendLine("      <div>");
        sb.AppendLine("        <div class=\"title\">Windows Security Sentinel</div>");
        sb.AppendLine("        <div style=\"color: #64748B; font-size: 13px;\">Comprehensive System Security Scan Report</div>");
        sb.AppendLine("      </div>");
        sb.AppendLine($"     <div style=\"text-align: right; font-size: 12px; color: #64748B;\">Scan ID: <span class=\"code\">{report.ScanId}</span></div>");
        sb.AppendLine("    </div>");

        sb.AppendLine("    <div class=\"meta-grid\">");
        sb.AppendLine($"     <div class=\"meta-item\"><div class=\"meta-label\">Scan Type</div><div class=\"meta-val\">{report.Type} Scan</div></div>");
        sb.AppendLine($"     <div class=\"meta-item\"><div class=\"meta-label\">Start Time</div><div class=\"meta-val\">{report.StartTime:yyyy-MM-dd HH:mm:ss} UTC</div></div>");
        sb.AppendLine($"     <div class=\"meta-item\"><div class=\"meta-label\">Duration</div><div class=\"meta-val\">{report.Duration.TotalSeconds:F1} seconds</div></div>");
        sb.AppendLine($"     <div class=\"meta-item\"><div class=\"meta-label\">Machine Name</div><div class=\"meta-val\">{report.MachineName}</div></div>");
        sb.AppendLine($"     <div class=\"meta-item\"><div class=\"meta-label\">Privilege Level</div><div class=\"meta-val\">{(report.WasElevated ? "Administrator (Elevated)" : "Standard User (asInvoker)")}</div></div>");
        sb.AppendLine($"     <div class=\"meta-item\"><div class=\"meta-label\">Total Examined</div><div class=\"meta-val\">{report.TotalFilesScanned:N0} items</div></div>");
        sb.AppendLine("    </div>");

        sb.AppendLine($"   <h3>Detected Security Findings ({report.Findings.Count})</h3>");
        if (report.Findings.Count == 0)
        {
            sb.AppendLine("    <div style=\"padding: 16px; background: #DCFCE7; color: #166534; border-radius: 6px; font-weight: 500;\">No security threats or malicious indicators detected during this inspection.</div>");
        }
        else
        {
            sb.AppendLine("    <table>");
            sb.AppendLine("      <thead><tr><th>Severity</th><th>Category</th><th>Title & Details</th><th>Evidence / Path</th><th>Recommendation</th></tr></thead>");
            sb.AppendLine("      <tbody>");
            foreach (var f in report.Findings)
            {
                sb.AppendLine("        <tr>");
                sb.AppendLine($"         <td><span class=\"badge badge-{f.Severity}\">{f.Severity}</span></td>");
                sb.AppendLine($"         <td><strong>{f.Category}</strong></td>");
                sb.AppendLine($"         <td><strong>{f.Title}</strong><br><span style=\"color: #64748B;\">{f.Description}</span></td>");
                sb.AppendLine($"         <td><span class=\"code\">{f.Evidence}</span>{(string.IsNullOrEmpty(f.Sha256Hash) ? "" : $"<br><small>SHA256: {f.Sha256Hash}</small>")}</td>");
                sb.AppendLine($"         <td>{f.RecommendedAction}</td>");
                sb.AppendLine("        </tr>");
            }
            sb.AppendLine("      </tbody>");
            sb.AppendLine("    </table>");
        }

        if (report.SkippedLocations.Count > 0)
        {
            sb.AppendLine("   <h3 style=\"margin-top: 32px; color: #64748B;\">Inaccessible / Skipped Locations</h3>");
            sb.AppendLine("   <ul>");
            foreach (var skip in report.SkippedLocations)
            {
                sb.AppendLine($"     <li style=\"color: #64748B; font-size: 12px;\">{skip}</li>");
            }
            sb.AppendLine("   </ul>");
        }

        sb.AppendLine("  </div>");
        sb.AppendLine("</body>");
        sb.AppendLine("</html>");

        return sb.ToString();
    }

    public string ExportToCsv(ScanReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("ScanId,Timestamp,Category,Severity,Title,Description,Evidence,TargetPath,Sha256,RecommendedAction");

        foreach (var f in report.Findings)
        {
            sb.AppendLine(string.Join(",",
                EscapeCsv(report.ScanId),
                EscapeCsv(f.DetectedAt.ToString("o")),
                EscapeCsv(f.Category),
                EscapeCsv(f.Severity.ToString()),
                EscapeCsv(f.Title),
                EscapeCsv(f.Description),
                EscapeCsv(f.Evidence),
                EscapeCsv(f.TargetPath ?? ""),
                EscapeCsv(f.Sha256Hash ?? ""),
                EscapeCsv(f.RecommendedAction)
            ));
        }

        return sb.ToString();
    }

    private static string EscapeCsv(string s)
    {
        if (string.IsNullOrEmpty(s)) return "\"\"";
        return $"\"{s.Replace("\"", "\"\"")}\"";
    }
}
