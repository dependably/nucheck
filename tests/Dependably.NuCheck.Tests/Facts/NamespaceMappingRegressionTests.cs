using System.Text.Json;
using Dependably.NuCheck.Facts;

namespace Dependably.NuCheck.Tests.Facts;

/// <summary>
/// Regression tests for the false negative that motivated the "never guess a
/// namespace from the id" rule: a package whose namespace does NOT match its id.
///
/// `Microsoft.CodeAnalysis.Workspaces.MSBuild` ships the namespace
/// `Microsoft.CodeAnalysis.MSBuild`; every `AWSSDK.*` package ships `Amazon.*`.
/// When the package's assembly is readable the document learns the real
/// namespace. When it is NOT (no `dotnet restore`) the document must OMIT
/// `namespaces` for that package: a consumer handed the id as a namespace would
/// search for one the package never had, find nothing, and conclude "unused"
/// about a package the code demonstrably imports.
///
/// The fixture is built at run time (a real assembly emitted with Roslyn), so no
/// binaries are committed.
/// </summary>
public class NamespaceMappingRegressionTests
{
    private const string PackageId = "Contoso.Toolkit";
    private const string PackageVersion = "1.0.0";

    /// Deliberately unrelated to the package id — this is the whole point.
    private const string RealNamespace = "Fabrikam.Tools";

    [Fact]
    public void RealNamespaceIsPublishedWhenTheDllIsReadable()
    {
        using var fixture = new Fixture(globalPackagesResolvable: true);

        var doc = FactsCommand.Build(fixture.SrcDir, "test");

        var package = Assert.Single(doc.Packages);
        Assert.Equal(PackageId, package.Id);
        Assert.Equal([RealNamespace], package.Namespaces);
        Assert.Equal(1, doc.Summary.PackagesWithNamespaces);
        Assert.Equal(1, doc.Summary.AssembliesRead);
        Assert.True(Assert.Single(doc.PackageFolders).Readable);

        // The using of the REAL namespace is a plain source fact either way.
        var file = Assert.Single(doc.Source.Files);
        Assert.Contains(file.Usings, u => u.Namespace == RealNamespace && u.Line == 1);
    }

    /// The regression itself: same source, same `using`, only the package's
    /// assembly is unreadable. The document must not invent a namespace.
    [Fact]
    public void NamespacesAreOmittedNotGuessedWhenTheDllIsUnreadable()
    {
        using var fixture = new Fixture(globalPackagesResolvable: false);

        var doc = FactsCommand.Build(fixture.SrcDir, "test");

        var package = Assert.Single(doc.Packages);
        Assert.Null(package.Namespaces);
        Assert.Equal(0, doc.Summary.PackagesWithNamespaces);
        Assert.False(Assert.Single(doc.PackageFolders).Readable);

        // On the wire the key is absent — not `null`, not `[]`, and never `["Contoso.Toolkit"]`.
        using var json = JsonDocument.Parse(FactsCommand.Serialize(doc));
        var wirePackage = json.RootElement.GetProperty("packages")[0];
        Assert.False(wirePackage.TryGetProperty("namespaces", out _));
        // The assembly list is still a fact the assets file states.
        Assert.Equal([PackageId], package.Assemblies);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _root;
        public string SrcDir { get; }

        public Fixture(bool globalPackagesResolvable)
        {
            _root = Fixtures.NewScratch("nsregression");
            SrcDir = Path.Combine(_root, "src");
            var appDir = Path.Combine(SrcDir, "App");
            Directory.CreateDirectory(Path.Combine(appDir, "obj"));

            // A package that ships `Fabrikam.Tools`, not `Contoso.Toolkit`.
            var globalPackages = Path.Combine(_root, "gp");
            var libRelPath = $"lib/netstandard2.0/{PackageId}.dll";
            var dllDir = Path.Combine(globalPackages, PackageId.ToLowerInvariant(), PackageVersion, "lib", "netstandard2.0");
            Directory.CreateDirectory(dllDir);
            Fixtures.EmitAssembly(
                PackageId,
                $$"""namespace {{RealNamespace}} { public static class Widget { public static void Go() { } } }""",
                Path.Combine(dllDir, $"{PackageId}.dll"));

            File.WriteAllText(Path.Combine(appDir, "App.csproj"), $"""
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup>
                    <TargetFramework>netstandard2.0</TargetFramework>
                  </PropertyGroup>
                  <ItemGroup>
                    <PackageReference Include="{PackageId}" Version="{PackageVersion}" />
                  </ItemGroup>
                </Project>
                """);

            // First-party code imports the package by its REAL namespace.
            File.WriteAllText(Path.Combine(appDir, "Program.cs"), $$"""
                using {{RealNamespace}};

                class Program
                {
                    static void Main() => Widget.Go();
                }
                """);

            // When `globalPackagesResolvable` is false the assets file points at a
            // folder that does not exist — exactly what an un-restored checkout
            // (or a CI runner that scans before it builds) looks like.
            var packageFolder = globalPackagesResolvable
                ? globalPackages
                : Path.Combine(_root, "no-such-global-packages");
            var assets = new
            {
                version = 3,
                packageFolders = new Dictionary<string, object> { [packageFolder] = new { } },
                libraries = new Dictionary<string, object>
                {
                    [$"{PackageId}/{PackageVersion}"] = new
                    {
                        type = "package",
                        files = new[] { libRelPath },
                    },
                },
            };
            File.WriteAllText(
                Path.Combine(appDir, "obj", "project.assets.json"),
                JsonSerializer.Serialize(assets));
        }

        public void Dispose() => Fixtures.DeleteScratch(_root);
    }
}
