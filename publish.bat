@echo off
setlocal
echo ============================================================
echo   Building and Publishing Windows Security Sentinel (x64)
echo ============================================================
echo.

where dotnet >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] .NET 8.0 SDK was not found on PATH.
    echo Please install the .NET 8.0 SDK from https://dotnet.microsoft.com/download
    pause
    exit /b 1
)

echo [1/3] Restoring NuGet Packages...
dotnet restore src\WindowsSecuritySentinel\WindowsSecuritySentinel.csproj
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Package restore failed.
    pause
    exit /b %ERRORLEVEL%
)

echo [2/3] Building Solution (Release)...
dotnet build WindowsSecuritySentinel.sln -c Release
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build failed.
    pause
    exit /b %ERRORLEVEL%
)

echo [3/3] Publishing executable (win-x64)...
dotnet publish src\WindowsSecuritySentinel\WindowsSecuritySentinel.csproj -c Release -r win-x64 --self-contained false -o bin\Release\Publish
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Publish failed.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo ============================================================
echo   Build Successful!
echo   Output Location: bin\Release\Publish\WindowsSecuritySentinel.exe
echo ============================================================
pause
