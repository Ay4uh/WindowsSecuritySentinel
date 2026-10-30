using System.Diagnostics.Eventing.Reader;
using System.Text.Json;
using System.Windows;
using WindowsSecuritySentinel.Core.Interfaces;
using WindowsSecuritySentinel.Core.Models;
using WindowsSecuritySentinel.Services;
using WindowsSecuritySentinel.ViewModels;
using WindowsSecuritySentinel.Views;

namespace WindowsSecuritySentinel;

public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Check if launched as an elevated worker instance:
        // Syntax: --elevated-task <task-name> --input <input.json> --output <output.json>
        if (e.Args.Length >= 4 && e.Args[0] == "--elevated-task")
        {
            await HandleElevatedTaskAsync(e.Args);
            Shutdown(0);
            return;
        }

        // Standard user GUI startup
        var elevationService = new ElevationService();
        var reportService = new ReportService();
        var defenderService = new DefenderService();
        var malwareScannerService = new MalwareScannerService();
        var remoteAccessService = new RemoteAccessDetectorService();
        var startupService = new StartupPersistenceService(elevationService);
        var networkService = new NetworkAnalyzerService();
        var bruteForceService = new BruteForceAnalyzerService(elevationService);
        var quarantineService = new QuarantineService();

        var viewModel = new MainViewModel(
            defenderService,
            malwareScannerService,
            remoteAccessService,
            startupService,
            networkService,
            bruteForceService,
            quarantineService,
            elevationService,
            reportService);

        var mainWindow = new MainWindow(viewModel);
        mainWindow.Show();

        await viewModel.InitializeAsync();
    }

    private static async Task HandleElevatedTaskAsync(string[] args)
    {
        string taskName = args[1];
        string inputFile = string.Empty;
        string outputFile = string.Empty;

        for (int i = 2; i < args.Length - 1; i++)
        {
            if (args[i] == "--input") inputFile = args[i + 1];
            if (args[i] == "--output") outputFile = args[i + 1];
        }

        try
        {
            if (taskName.Equals("AnalyzeLogins", StringComparison.OrdinalIgnoreCase))
            {
                int hours = 168; // default 7 days
                if (File.Exists(inputFile))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(File.ReadAllText(inputFile));
                        if (doc.RootElement.TryGetProperty("Hours", out var hProp)) hours = hProp.GetInt32();
                    }
                    catch { }
                }

                var elevationService = new ElevationService();
                var bruteForceService = new BruteForceAnalyzerService(elevationService);
                var incidents = await bruteForceService.AnalyzeLoginEventsAsync(TimeSpan.FromHours(hours), false);

                string json = JsonSerializer.Serialize(incidents, new JsonSerializerOptions { WriteIndented = true });
                if (!string.IsNullOrEmpty(outputFile))
                {
                    await File.WriteAllTextAsync(outputFile, json);
                }
            }
        }
        catch (Exception ex)
        {
            if (!string.IsNullOrEmpty(outputFile))
            {
                await File.WriteAllTextAsync(outputFile, JsonSerializer.Serialize(new { Error = ex.Message }));
            }
        }
    }
}
