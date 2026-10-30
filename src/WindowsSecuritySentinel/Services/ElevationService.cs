using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;
using WindowsSecuritySentinel.Core.Interfaces;

namespace WindowsSecuritySentinel.Services;

public class ElevationService : IElevationService
{
    public bool IsCurrentProcessElevated()
    {
        if (!OperatingSystem.IsWindows())
            return false;

        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    public async Task<string> ExecuteElevatedTaskJsonAsync(string taskName, string? inputPayload = null)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Elevation tasks are only supported on Windows.");

        string tempInputFile = Path.Combine(Path.GetTempPath(), $"wss_in_{Guid.NewGuid():N}.json");
        string tempOutputFile = Path.Combine(Path.GetTempPath(), $"wss_out_{Guid.NewGuid():N}.json");

        try
        {
            if (!string.IsNullOrEmpty(inputPayload))
            {
                await File.WriteAllTextAsync(tempInputFile, inputPayload);
            }

            string exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? "WindowsSecuritySentinel.exe";

            var startInfo = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = $"--elevated-task \"{taskName}\" --input \"{tempInputFile}\" --output \"{tempOutputFile}\"",
                UseShellExecute = true,
                Verb = "runas", // Triggers standard Windows UAC prompt
                WindowStyle = ProcessWindowStyle.Hidden
            };

            using var process = Process.Start(startInfo);
            if (process == null)
            {
                throw new InvalidOperationException("Failed to initiate elevated task process.");
            }

            await process.WaitForExitAsync();

            if (File.Exists(tempOutputFile))
            {
                string jsonResult = await File.ReadAllTextAsync(tempOutputFile);
                return jsonResult;
            }

            throw new InvalidOperationException($"Elevated task finished with code {process.ExitCode} but produced no output.");
        }
        finally
        {
            try
            {
                if (File.Exists(tempInputFile)) File.Delete(tempInputFile);
                if (File.Exists(tempOutputFile)) File.Delete(tempOutputFile);
            }
            catch { }
        }
    }
}
