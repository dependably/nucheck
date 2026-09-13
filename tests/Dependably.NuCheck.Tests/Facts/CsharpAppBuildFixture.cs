using System.Diagnostics;

namespace Dependably.NuCheck.Tests.Facts;

/// <summary>
/// Builds App.csproj (which project-references Lib) once per test run so the
/// IL tests read *real* compiled output. `bin/` is deliberately not committed —
/// every IL test therefore MUST compile the fixture first, or it would be
/// asserting against an empty `il` list and proving nothing.
///
/// Builds a temp COPY of fixtures/csharp-app (via
/// <see cref="Fixtures.CopyToScratch"/>), never the committed tree in place:
/// `dotnet build` implicitly restores, which would otherwise overwrite the
/// deliberately-committed, machine-independent `App/obj/project.assets.json`
/// with real (and machine-specific) restore output — and race with the
/// unrestored-fixture tests (a different xUnit collection, run in parallel)
/// reading that same tracked file.
/// </summary>
public sealed class CsharpAppBuildFixture : IDisposable
{
    public string BuiltCsharpApp { get; }

    public CsharpAppBuildFixture()
    {
        BuiltCsharpApp = Fixtures.CopyToScratch("il-build");
        BuildProject(Path.Combine(BuiltCsharpApp, "App", "App.csproj"));
    }

    public static void BuildProject(string csprojPath)
    {
        var psi = new ProcessStartInfo("dotnet", $"build \"{csprojPath}\" --nologo -v quiet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("failed to start dotnet build");
        var stdout = proc.StandardOutput.ReadToEnd();
        var stderr = proc.StandardError.ReadToEnd();
        if (!proc.WaitForExit(180_000))
        {
            proc.Kill(entireProcessTree: true);
            throw new InvalidOperationException($"dotnet build of {csprojPath} timed out");
        }
        if (proc.ExitCode != 0)
        {
            throw new InvalidOperationException($"dotnet build of {csprojPath} failed (exit {proc.ExitCode}):\n{stdout}\n{stderr}");
        }
    }

    public void Dispose() => Fixtures.DeleteScratch(BuiltCsharpApp);
}

[CollectionDefinition("CsharpAppBuild")]
public sealed class CsharpAppBuildCollection : ICollectionFixture<CsharpAppBuildFixture>
{
}
