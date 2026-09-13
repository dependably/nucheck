using System.Text.Json;
using Dependably.NuCheck.Facts;

namespace Dependably.NuCheck.Tests.Facts;

/// <summary>
/// "Nothing references it" and "it isn't on disk" are different facts, and the
/// document must carry the second one — per project, per built output — so a
/// consumer can tell a package that merely sits unreferenced in the shipped
/// artefact (where MSBuild, a DI container or plain reflection could still load
/// it: the shape of CVE-2025-26646 / Microsoft.Build.Tasks.Core) from one that
/// contributed nothing loadable at all. The document states what each
/// `*.deps.json` says and which project it belongs to; what "in a test
/// project's output" means is the consumer's call.
/// </summary>
public class RuntimeOutputTests
{
    private const string ShippedPackage = "Ships.Package";
    private const string CompileOnlyPackage = "CompileOnly.Package";

    [Fact]
    public void APackageCopiedIntoTheBuildOutputIsListedWithItsExactVersion()
    {
        using var fixture = new Fixture(built: true);
        var doc = FactsCommand.Build(fixture.Root, "test");

        var app = Assert.Single(doc.Projects, p => p.Path == "App/App.csproj");
        var output = Assert.Single(app.RuntimeOutput!);
        Assert.Equal("App/bin/Debug/net8.0/App.deps.json", output.DepsJson);
        // Keyed on id AND version: a consumer asking about a different version of
        // the same id must be able to see that THIS is the one on disk.
        var shipped = Assert.Single(output.Packages);
        Assert.Equal(ShippedPackage, shipped.Id);
        Assert.Equal("1.0.0", shipped.Version);
    }

    [Fact]
    public void APackageThatContributesNoAssembliesIsNotListed()
    {
        using var fixture = new Fixture(built: true);
        var doc = FactsCommand.Build(fixture.Root, "test");

        var app = Assert.Single(doc.Projects, p => p.Path == "App/App.csproj");
        Assert.DoesNotContain(app.RuntimeOutput!.SelectMany(o => o.Packages), p => p.Id == CompileOnlyPackage);
    }

    /// A test project's bin/ is a developer's disk, not the product. The document
    /// does not decide that — it attributes the output to the project that owns
    /// it, and that project's `isTestProject` fact is right beside it.
    [Fact]
    public void OutputIsAttributedToTheProjectThatOwnsIt()
    {
        using var fixture = new Fixture(built: true, shippedPackageOnlyInTestOutput: true);
        var doc = FactsCommand.Build(fixture.Root, "test");

        var app = Assert.Single(doc.Projects, p => p.Path == "App/App.csproj");
        Assert.Null(app.RuntimeOutput);

        var tests = Assert.Single(doc.Projects, p => p.Path == "Tests/Tests.csproj");
        Assert.True(tests.IsTestProject);
        Assert.Equal("<IsTestProject>", tests.TestMarker);
        var output = Assert.Single(tests.RuntimeOutput!);
        Assert.Contains(output.Packages, p => p.Id == ShippedPackage && p.Version == "1.0.0");
    }

    /// Without build output nothing is known about what ships — and the document
    /// must not guess. The key is OMITTED (undetermined), never an empty list
    /// (which would claim the project ships no package at all).
    [Fact]
    public void WithoutBuildOutputRuntimeOutputIsOmitted()
    {
        using var fixture = new Fixture(built: false);
        var doc = FactsCommand.Build(fixture.Root, "test");

        var app = Assert.Single(doc.Projects, p => p.Path == "App/App.csproj");
        Assert.Null(app.RuntimeOutput);
        Assert.Null(app.OutputAssembly);

        using var json = JsonDocument.Parse(FactsCommand.Serialize(doc));
        var wireApp = json.RootElement.GetProperty("projects")[0];
        Assert.False(wireApp.TryGetProperty("runtimeOutput", out _));
        // Whereas "no output assembly found" is a stated fact, written as null.
        Assert.Equal(JsonValueKind.Null, wireApp.GetProperty("outputAssembly").ValueKind);
    }

    /// When every deps file under bin/ is unparseable the output exists but says
    /// nothing readable: `runtimeOutput` is OMITTED (cannot tell), never `[]`
    /// (which would read as "built, ships nothing"), and the gap is reported.
    [Fact]
    public void AMalformedDepsFileIsReportedAndRuntimeOutputIsOmitted()
    {
        using var fixture = new Fixture(built: true);
        File.WriteAllText(Path.Combine(fixture.Root, "App", "bin", "Debug", "net8.0", "App.deps.json"), "{ not json");

        var doc = FactsCommand.Build(fixture.Root, "test");

        var app = Assert.Single(doc.Projects, p => p.Path == "App/App.csproj");
        Assert.Null(app.RuntimeOutput);
        var gap = Assert.Single(doc.Unanalyzable, u => u.Kind == UnanalyzableEntry.KindDeps);
        Assert.Equal("App/bin/Debug/net8.0/App.deps.json", gap.File);
        Assert.StartsWith("unparseable deps file: ", gap.Reason);
        Assert.DoesNotContain(fixture.Root, gap.Reason);

        using var json = JsonDocument.Parse(FactsCommand.Serialize(doc));
        var wireApp = json.RootElement.GetProperty("projects")[0];
        Assert.False(wireApp.TryGetProperty("runtimeOutput", out _));
    }

    /// One readable deps file beside an unparseable one: the readable one is
    /// reported and the other is a gap — a partial view, stated as such.
    [Fact]
    public void AReadableDepsFileBesideAMalformedOneIsStillReported()
    {
        using var fixture = new Fixture(built: true);
        var releaseDir = Path.Combine(fixture.Root, "App", "bin", "Release", "net8.0");
        Directory.CreateDirectory(releaseDir);
        File.WriteAllText(Path.Combine(releaseDir, "App.deps.json"), "{ not json");

        var doc = FactsCommand.Build(fixture.Root, "test");

        var app = Assert.Single(doc.Projects, p => p.Path == "App/App.csproj");
        var output = Assert.Single(app.RuntimeOutput!);
        Assert.Equal("App/bin/Debug/net8.0/App.deps.json", output.DepsJson);
        Assert.Equal("App/bin/Release/net8.0/App.deps.json", Assert.Single(doc.Unanalyzable).File);
    }

    private sealed class Fixture : IDisposable
    {
        public string Root { get; }

        public Fixture(bool built, bool shippedPackageOnlyInTestOutput = false)
        {
            Root = Fixtures.NewScratch("runtime");
            var app = Path.Combine(Root, "App");
            Directory.CreateDirectory(app);

            File.WriteAllText(Path.Combine(app, "App.csproj"), $"""
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="{ShippedPackage}" Version="1.0.0" />
                    <PackageReference Include="{CompileOnlyPackage}" Version="1.0.0" />
                  </ItemGroup>
                </Project>
                """);
            File.WriteAllText(Path.Combine(app, "Program.cs"), "class Program { static void Main() { } }");

            if (!built) return;

            // What `dotnet build` leaves behind: one package contributes a runtime
            // assembly, the other contributes none (analyzer/targets/compile-only).
            //
            // When shippedPackageOnlyInTestOutput, that output belongs to a TEST
            // project instead — on disk, but not in the product.
            var owner = app;
            if (shippedPackageOnlyInTestOutput)
            {
                owner = Path.Combine(Root, "Tests");
                Directory.CreateDirectory(owner);
                File.WriteAllText(Path.Combine(owner, "Tests.csproj"), """
                    <Project Sdk="Microsoft.NET.Sdk">
                      <PropertyGroup><IsTestProject>true</IsTestProject></PropertyGroup>
                    </Project>
                    """);
            }
            var outDir = Path.Combine(owner, "bin", "Debug", "net8.0");
            Directory.CreateDirectory(outDir);
            var deps = new
            {
                libraries = new Dictionary<string, object>
                {
                    [$"{ShippedPackage}/1.0.0"] = new { type = "package" },
                    [$"{CompileOnlyPackage}/1.0.0"] = new { type = "package" },
                },
                targets = new Dictionary<string, object>
                {
                    [".NETCoreApp,Version=v8.0"] = new Dictionary<string, object>
                    {
                        [$"{ShippedPackage}/1.0.0"] = new
                        {
                            runtime = new Dictionary<string, object>
                            {
                                ["lib/net8.0/Ships.Package.dll"] = new { },
                            },
                        },
                        // Present in the graph, but nothing lands next to the binary.
                        [$"{CompileOnlyPackage}/1.0.0"] = new { },
                    },
                },
            };
            File.WriteAllText(
                Path.Combine(outDir, Path.GetFileName(owner) + ".deps.json"),
                JsonSerializer.Serialize(deps));
        }

        public void Dispose() => Fixtures.DeleteScratch(Root);
    }
}
