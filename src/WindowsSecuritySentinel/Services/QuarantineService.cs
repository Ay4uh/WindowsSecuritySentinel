using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using WindowsSecuritySentinel.Core.Interfaces;
using WindowsSecuritySentinel.Core.Models;

namespace WindowsSecuritySentinel.Services;

public class QuarantineService : IQuarantineService
{
    private static readonly byte[] ObfuscationKey = new byte[]
    {
        0x57, 0x53, 0x53, 0x5F, 0x51, 0x55, 0x41, 0x52, 0x41, 0x4E, 0x54, 0x49, 0x4E, 0x45, 0x5F, 0x4B,
        0x45, 0x59, 0x5F, 0x32, 0x30, 0x32, 0x36, 0x5F, 0x53, 0x45, 0x43, 0x55, 0x52, 0x49, 0x54, 0x59
    };

    public string QuarantineDirectory { get; }
    private readonly string _connectionString;

    public QuarantineService()
    {
        string baseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WindowsSecuritySentinel");
        QuarantineDirectory = Path.Combine(baseDir, "Quarantine");
        Directory.CreateDirectory(QuarantineDirectory);

        string dbPath = Path.Combine(baseDir, "sentinel.db");
        _connectionString = $"Data Source={dbPath}";
    }

    public async Task<List<QuarantineEntry>> GetQuarantineEntriesAsync()
    {
        var list = new List<QuarantineEntry>();
        try
        {
            using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync();

            string sql = "SELECT QuarantineId, OriginalPath, QuarantinedFileName, QuarantinedFilePath, FileSizeBytes, Sha256Hash, QuarantinedAt, ThreatCategory, ThreatTitle, BackupMetadataJson, IsRestored FROM QuarantineEntries WHERE IsRestored = 0 ORDER BY QuarantinedAt DESC";
            using var cmd = new SqliteCommand(sql, conn);
            using var reader = await cmd.ExecuteReaderAsync();

            while (await reader.ReadAsync())
            {
                list.Add(new QuarantineEntry
                {
                    QuarantineId = reader.GetString(0),
                    OriginalPath = reader.GetString(1),
                    QuarantinedFileName = reader.GetString(2),
                    QuarantinedFilePath = reader.GetString(3),
                    FileSizeBytes = reader.GetInt64(4),
                    Sha256Hash = reader.GetString(5),
                    QuarantinedAt = DateTime.Parse(reader.GetString(6)),
                    ThreatCategory = reader.GetString(7),
                    ThreatTitle = reader.GetString(8),
                    BackupMetadataJson = reader.IsDBNull(9) ? "" : reader.GetString(9),
                    IsRestored = reader.GetInt32(10) == 1
                });
            }
        }
        catch { }

        return list;
    }

    public async Task<(bool Success, string Message, QuarantineEntry? Entry)> QuarantineFileAsync(
        string filePath,
        string threatCategory,
        string threatTitle,
        string? associatedMetadataJson = null)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return (false, "Target file does not exist on disk.", null);

        // System safety check: never quarantine essential Windows System directories
        string fullPath = Path.GetFullPath(filePath);
        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string sys32 = Path.Combine(winDir, "System32");
        string winSxS = Path.Combine(winDir, "WinSxS");

        if (fullPath.StartsWith(sys32, StringComparison.OrdinalIgnoreCase) ||
            fullPath.StartsWith(winSxS, StringComparison.OrdinalIgnoreCase))
        {
            return (false, "Safety Guard: Critical Windows system directory protected. Quarantine refused.", null);
        }

        try
        {
            var fileInfo = new FileInfo(fullPath);
            long size = fileInfo.Length;
            string sha256 = await ComputeSha256Async(fullPath);

            string qId = Guid.NewGuid().ToString("N");
            string qFileName = $"{qId}.qtn";
            string qFilePath = Path.Combine(QuarantineDirectory, qFileName);

            // Read original file, XOR-obfuscate bytes so it is neutralized from execution and Defender, write to .qtn
            using (var inStream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (var outStream = new FileStream(qFilePath, FileMode.CreateNew, FileAccess.Write))
            {
                byte[] buffer = new byte[81920];
                int bytesRead;
                int keyIndex = 0;
                while ((bytesRead = await inStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    for (int i = 0; i < bytesRead; i++)
                    {
                        buffer[i] ^= ObfuscationKey[keyIndex % ObfuscationKey.Length];
                        keyIndex++;
                    }
                    await outStream.WriteAsync(buffer, 0, bytesRead);
                }
            }

            // Securely delete original file
            File.Delete(fullPath);

            var entry = new QuarantineEntry
            {
                QuarantineId = qId,
                OriginalPath = fullPath,
                QuarantinedFileName = qFileName,
                QuarantinedFilePath = qFilePath,
                FileSizeBytes = size,
                Sha256Hash = sha256,
                QuarantinedAt = DateTime.UtcNow,
                ThreatCategory = threatCategory,
                ThreatTitle = threatTitle,
                BackupMetadataJson = associatedMetadataJson ?? "",
                IsRestored = false
            };

            // Save to SQLite
            using (var conn = new SqliteConnection(_connectionString))
            {
                await conn.OpenAsync();
                string sql = @"INSERT INTO QuarantineEntries (QuarantineId, OriginalPath, QuarantinedFileName, QuarantinedFilePath, FileSizeBytes, Sha256Hash, QuarantinedAt, ThreatCategory, ThreatTitle, BackupMetadataJson, IsRestored)
                               VALUES (@id, @orig, @qname, @qpath, @size, @hash, @time, @cat, @title, @meta, 0)";
                using var cmd = new SqliteCommand(sql, conn);
                cmd.Parameters.AddWithValue("@id", entry.QuarantineId);
                cmd.Parameters.AddWithValue("@orig", entry.OriginalPath);
                cmd.Parameters.AddWithValue("@qname", entry.QuarantinedFileName);
                cmd.Parameters.AddWithValue("@qpath", entry.QuarantinedFilePath);
                cmd.Parameters.AddWithValue("@size", entry.FileSizeBytes);
                cmd.Parameters.AddWithValue("@hash", entry.Sha256Hash);
                cmd.Parameters.AddWithValue("@time", entry.QuarantinedAt.ToString("o"));
                cmd.Parameters.AddWithValue("@cat", entry.ThreatCategory);
                cmd.Parameters.AddWithValue("@title", entry.ThreatTitle);
                cmd.Parameters.AddWithValue("@meta", entry.BackupMetadataJson);
                await cmd.ExecuteNonQueryAsync();
            }

            return (true, $"File successfully quarantined and neutralized to {qFileName}", entry);
        }
        catch (Exception ex)
        {
            return (false, $"Quarantine failed: {ex.Message}", null);
        }
    }

    public async Task<(bool Success, string Message)> RestoreFileAsync(string quarantineId)
    {
        try
        {
            QuarantineEntry? entry = null;
            using (var conn = new SqliteConnection(_connectionString))
            {
                await conn.OpenAsync();
                string sql = "SELECT QuarantineId, OriginalPath, QuarantinedFileName, QuarantinedFilePath, FileSizeBytes, Sha256Hash, QuarantinedAt, ThreatCategory, ThreatTitle, BackupMetadataJson, IsRestored FROM QuarantineEntries WHERE QuarantineId = @id";
                using var cmd = new SqliteCommand(sql, conn);
                cmd.Parameters.AddWithValue("@id", quarantineId);
                using var reader = await cmd.ExecuteReaderAsync();
                if (await reader.ReadAsync())
                {
                    entry = new QuarantineEntry
                    {
                        QuarantineId = reader.GetString(0),
                        OriginalPath = reader.GetString(1),
                        QuarantinedFileName = reader.GetString(2),
                        QuarantinedFilePath = reader.GetString(3),
                        FileSizeBytes = reader.GetInt64(4),
                        Sha256Hash = reader.GetString(5),
                        QuarantinedAt = DateTime.Parse(reader.GetString(6)),
                        ThreatCategory = reader.GetString(7),
                        ThreatTitle = reader.GetString(8),
                        BackupMetadataJson = reader.IsDBNull(9) ? "" : reader.GetString(9),
                        IsRestored = reader.GetInt32(10) == 1
                    };
                }
            }

            if (entry == null) return (false, "Quarantine record not found.");
            if (!File.Exists(entry.QuarantinedFilePath)) return (false, "Encrypted quarantine file missing on disk.");

            string targetDir = Path.GetDirectoryName(entry.OriginalPath) ?? string.Empty;
            if (!string.IsNullOrEmpty(targetDir) && !Directory.Exists(targetDir))
            {
                Directory.CreateDirectory(targetDir);
            }

            // De-obfuscate and restore
            using (var inStream = new FileStream(entry.QuarantinedFilePath, FileMode.Open, FileAccess.Read))
            using (var outStream = new FileStream(entry.OriginalPath, FileMode.Create, FileAccess.Write))
            {
                byte[] buffer = new byte[81920];
                int bytesRead;
                int keyIndex = 0;
                while ((bytesRead = await inStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    for (int i = 0; i < bytesRead; i++)
                    {
                        buffer[i] ^= ObfuscationKey[keyIndex % ObfuscationKey.Length];
                        keyIndex++;
                    }
                    await outStream.WriteAsync(buffer, 0, bytesRead);
                }
            }

            // Verify SHA-256 match
            string restoredHash = await ComputeSha256Async(entry.OriginalPath);
            if (!restoredHash.Equals(entry.Sha256Hash, StringComparison.OrdinalIgnoreCase))
            {
                return (false, "Restoration warning: Hash mismatch after de-obfuscation.");
            }

            // Mark restored in SQLite and delete .qtn
            using (var conn = new SqliteConnection(_connectionString))
            {
                await conn.OpenAsync();
                string sql = "UPDATE QuarantineEntries SET IsRestored = 1 WHERE QuarantineId = @id";
                using var cmd = new SqliteCommand(sql, conn);
                cmd.Parameters.AddWithValue("@id", quarantineId);
                await cmd.ExecuteNonQueryAsync();
            }

            File.Delete(entry.QuarantinedFilePath);
            return (true, $"File successfully restored to original location: {entry.OriginalPath}");
        }
        catch (Exception ex)
        {
            return (false, $"Restore failed: {ex.Message}");
        }
    }

    public async Task<(bool Success, string Message)> PermanentlyDeleteAsync(string quarantineId)
    {
        try
        {
            string? qPath = null;
            using (var conn = new SqliteConnection(_connectionString))
            {
                await conn.OpenAsync();
                string sql = "SELECT QuarantinedFilePath FROM QuarantineEntries WHERE QuarantineId = @id";
                using var cmd = new SqliteCommand(sql, conn);
                cmd.Parameters.AddWithValue("@id", quarantineId);
                var res = await cmd.ExecuteScalarAsync();
                if (res != null) qPath = res.ToString();
            }

            if (!string.IsNullOrEmpty(qPath) && File.Exists(qPath))
            {
                File.Delete(qPath);
            }

            using (var conn = new SqliteConnection(_connectionString))
            {
                await conn.OpenAsync();
                string sql = "DELETE FROM QuarantineEntries WHERE QuarantineId = @id";
                using var cmd = new SqliteCommand(sql, conn);
                cmd.Parameters.AddWithValue("@id", quarantineId);
                await cmd.ExecuteNonQueryAsync();
            }

            return (true, "Quarantined threat permanently purged from system.");
        }
        catch (Exception ex)
        {
            return (false, $"Permanent deletion error: {ex.Message}");
        }
    }

    private static async Task<string> ComputeSha256Async(string filePath)
    {
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sha = SHA256.Create();
            byte[] hash = await sha.ComputeHashAsync(fs);
            return BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();
        }
        catch { return string.Empty; }
    }
}
