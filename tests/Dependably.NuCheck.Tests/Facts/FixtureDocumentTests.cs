using System.Text.Json;
using Dependably.NuCheck.Facts;

namespace Dependably.NuCheck.Tests.Facts;

/// <summary>
/// The facts document for the committed, deliberately UN-restored
/// fixtures/csharp-app: its assets file points `packageFolders` at a path that
/// does not exist, so no package DLL is readable. Read-only against the
/// committed tree — nothing here builds or restores it.
/// </summary>
public class FixtureDocumentTests
{
    private static FactsDocument Doc() => FactsCommand.Build(Fixtures.CsharpApp, "test");

    [Fact]
    public void EnumeratesResolvedClosureWithVersions()
    {
        var doc = Doc();

        // Version resolution reads `libraries` keys ("PackageId/Version") out of
        // project.assets.json directly — it needs no readable DLL.
        var newtonsoft = Assert.Single(doc.Packages, p => p.Id == "Newtonsoft.Json");
        Assert.Equal("12.0.1", newtonsoft.Version);

        var serilog = Assert.Single(doc.Packages, p => p.Id == "Serilog");
        Assert.Equal("2.10.0", serilog.Version);
        Assert.Equal(5, doc.Summary.Packages);
    }

    [Fact]
    public void ClosureIsOrderedByIdAndHasNoDuplicates()
    {
        var ids = Doc().Packages.Select(p => p.Id).ToList();
        Assert.Equal(ids.OrderBy(id => id, StringComparer.OrdinalIgnoreCase), ids);
        Assert.Equal(ids.Distinct(StringComparer.OrdinalIgnoreCase).Count(), ids.Count);
    }

    /// The un-restored case: every package's namespaces are OMITTED — never
    /// inferred from the id — and the document says why (the one package folder is
    /// unreadable). The assets file still enumerates each package's files, so the
    /// assembly names ARE stated.
    [Fact]
    public void UnrestoredFixtureHasNoNamespacesForAnyPackage()
    {
        var doc = Doc();

        Assert.All(doc.Packages, p => Assert.Null(p.Namespaces));
        Assert.Equal(0, doc.Summary.PackagesWithNamespaces);
        Assert.Equal(0, doc.Summary.AssembliesRead);
        var folder = Assert.Single(doc.PackageFolders);
        Assert.Equal("/nonexistent/fixture-global-packages", folder.Path);
        Assert.False(folder.Readable);
        Assert.Equal(["Newtonsoft.Json"], Assert.Single(doc.Packages, p => p.Id == "Newtonsoft.Json").Assemblies);

        using var json = JsonDocument.Parse(FactsCommand.Serialize(doc));
        foreach (var package in json.RootElement.GetProperty("packages").EnumerateArray())
        {
            Assert.False(package.TryGetProperty("namespaces", out _), $"{package.GetProperty("id")} must not carry a guessed namespace list");
        }
    }

    /// Both App.csproj and Lib.csproj are non-test, with no marker of any kind —
    /// a stated `null`, never a guess from a directory name.
    [Fact]
    public void ProjectsAreNonTestWithNullMarkers()
    {
        var doc = Doc();
        Assert.Equal(["App/App.csproj", "Lib/Lib.csproj"], doc.Projects.Select(p => p.Path));
        Assert.All(doc.Projects, p =>
        {
            Assert.False(p.IsTestProject);
            Assert.Null(p.TestMarker);
        });

        using var json = JsonDocument.Parse(FactsCommand.Serialize(doc));
        var app = json.RootElement.GetProperty("projects")[0];
        Assert.Equal(JsonValueKind.Null, app.GetProperty("testMarker").ValueKind);
    }

    /// App.csproj declares Newtonsoft.Json/Serilog/Polly/CsvHelper directly (at real
    /// line numbers past the first); Lib.csproj declares Newtonsoft.Json and has no
    /// restore artefact of its own — so its closure is OMITTED, not empty.
    [Fact]
    public void DirectReferencesAssetsAndClosureArePerProject()
    {
        var doc = Doc();

        var app = doc.Projects[0];
        Assert.Equal(
            ["CsvHelper", "Newtonsoft.Json", "Polly", "Serilog"],
            app.DirectReferences.Select(d => d.Id).OrderBy(id => id, StringComparer.OrdinalIgnoreCase));
        Assert.All(app.DirectReferences, d =>
        {
            Assert.Equal("App/App.csproj", d.File);
            Assert.True(d.Line > 1);
        });
        Assert.Equal(new AssetsSourceFacts("App/obj/project.assets.json", "assets"), app.Assets);
        Assert.Equal(
            [
                new PackageIdentity("CsvHelper", "27.0.0"),
                new PackageIdentity("Microsoft.Bcl.AsyncInterfaces", "5.0.0"),
                new PackageIdentity("Newtonsoft.Json", "12.0.1"),
                new PackageIdentity("Polly", "7.2.0"),
                new PackageIdentity("Serilog", "2.10.0"),
            ],
            app.Closure);

        var lib = doc.Projects[1];
        Assert.Equal(["Newtonsoft.Json"], lib.DirectReferences.Select(d => d.Id));
        Assert.Null(lib.Assets);
        Assert.Null(lib.Closure);

        using var json = JsonDocument.Parse(FactsCommand.Serialize(doc));
        var wireLib = json.RootElement.GetProperty("projects")[1];
        Assert.Equal(JsonValueKind.Null, wireLib.GetProperty("assets").ValueKind);
        Assert.False(wireLib.TryGetProperty("closure", out _));
    }

    /// CsvHelper/27.0.0 depends on Microsoft.Bcl.AsyncInterfaces/5.0.0 per the
    /// fixture's committed project.assets.json `targets` section.
    [Fact]
    public void DependenciesComeFromTheAssetsTargets()
    {
        var doc = Doc();
        var csv = Assert.Single(doc.Packages, p => p.Id == "CsvHelper");
        Assert.Equal(["Microsoft.Bcl.AsyncInterfaces"], csv.Dependencies);
        Assert.Empty(Assert.Single(doc.Packages, p => p.Id == "Serilog").Dependencies);
    }

    [Fact]
    public void CentralPackageVersionsAreListedWithLines()
    {
        var doc = Doc();
        Assert.Equal(
            ["Newtonsoft.Json", "Serilog", "Polly", "CsvHelper"],
            doc.CentralPackageVersions.Select(d => d.Id));
        Assert.All(doc.CentralPackageVersions, d =>
        {
            Assert.Equal("Directory.Packages.props", d.File);
            Assert.True(d.Line > 1);
        });
    }

    /// Every C# file is listed, attributed to its project, with its usings and
    /// qualified identifiers as source facts: a plain using, a `#if`-disabled one
    /// (marked, not dropped), a global using, a fully-qualified use with no using
    /// at all, and a file with nothing — still listed.
    [Fact]
    public void SourceFactsCoverEveryFileAndEveryDirectiveShape()
    {
        var doc = Doc();
        Assert.Equal(3, doc.Summary.FilesScanned);
        Assert.Equal(["App/Program.cs", "Lib/GlobalUsings.cs", "Lib/Parser.cs"], doc.Source.Files.Select(f => f.File));

        var program = doc.Source.Files[0];
        Assert.Equal("App/App.csproj", program.Project);
        var newtonsoft = Assert.Single(program.Usings, u => u.Namespace == "Newtonsoft.Json");
        Assert.Equal(1, newtonsoft.Line);
        Assert.False(newtonsoft.Disabled);
        Assert.False(newtonsoft.Global);
        Assert.False(newtonsoft.Static);
        Assert.Null(newtonsoft.Alias);
        // Inside `#if NET472`: a fact about the file, flagged so the consumer can weigh it.
        var csv = Assert.Single(program.Usings, u => u.Namespace == "CsvHelper");
        Assert.True(csv.Disabled);
        Assert.Equal(4, csv.Line);
        var qualified = Assert.Single(program.Qualified);
        Assert.Equal("Serilog.Log.Information", qualified.Namespace);
        Assert.Equal(15, qualified.Line);

        var globals = doc.Source.Files[1];
        Assert.Equal("Lib/Lib.csproj", globals.Project);
        var global = Assert.Single(globals.Usings);
        Assert.Equal("Newtonsoft.Json.Linq", global.Namespace);
        Assert.True(global.Global);

        var parser = doc.Source.Files[2];
        Assert.Empty(parser.Usings);
        Assert.Empty(parser.Qualified);
    }

    [Fact]
    public void QualifiedRootsNameTheClosureAndDeclaredRoots()
    {
        var doc = Doc();
        Assert.Equal(["CsvHelper", "Microsoft", "Newtonsoft", "Polly", "Serilog"], doc.Source.QualifiedRoots);
    }

    [Fact]
    public void UnbuiltFixtureHasNoIlAndNoOutputAssemblies()
    {
        var doc = Doc();
        Assert.Empty(doc.Il);
        Assert.All(doc.Projects, p => Assert.Null(p.OutputAssembly));
        Assert.Empty(doc.Unanalyzable);
    }

    [Fact]
    public void DocumentIsDeterministic()
    {
        Assert.Equal(FactsCommand.Serialize(Doc()), FactsCommand.Serialize(Doc()));
    }

    // ---- test-project markers on synthetic projects ----------------------------------

    [Fact]
    public void ExplicitIsTestProjectPropertyIsTheMarker()
    {
        var root = Fixtures.NewScratch("marker-explicit");
        try
        {
            WriteProject(root, "T", """
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup><IsTestProject>true</IsTestProject></PropertyGroup>
                </Project>
                """);
            var project = Assert.Single(FactsCommand.Build(root, "test").Projects);
            Assert.True(project.IsTestProject);
            Assert.Equal("<IsTestProject>", project.TestMarker);
        }
        finally
        {
            Fixtures.DeleteScratch(root);
        }
    }

    [Fact]
    public void TestFrameworkReferenceIsTheMarkerNamingThatPackage()
    {
        var root = Fixtures.NewScratch("marker-package");
        try
        {
            WriteProject(root, "T", """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Some.Library" Version="1.0.0" />
                    <PackageReference Include="xunit.runner.visualstudio" Version="2.8.2" />
                  </ItemGroup>
                </Project>
                """);
            var project = Assert.Single(FactsCommand.Build(root, "test").Projects);
            Assert.True(project.IsTestProject);
            Assert.Equal("xunit.runner.visualstudio", project.TestMarker);
        }
        finally
        {
            Fixtures.DeleteScratch(root);
        }
    }

    /// Explicit `<IsTestProject>false</IsTestProject>` wins over a test-framework
    /// reference (the property the SDK itself honours lets a project opt out).
    [Fact]
    public void ExplicitFalseOverridesATestFrameworkReference()
    {
        var root = Fixtures.NewScratch("marker-optout");
        try
        {
            WriteProject(root, "T", """
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup><IsTestProject>false</IsTestProject></PropertyGroup>
                  <ItemGroup><PackageReference Include="xunit" Version="2.9.2" /></ItemGroup>
                </Project>
                """);
            var project = Assert.Single(FactsCommand.Build(root, "test").Projects);
            Assert.False(project.IsTestProject);
            Assert.Null(project.TestMarker);
        }
        finally
        {
            Fixtures.DeleteScratch(root);
        }
    }

    /// A directory called `tests/` proves nothing: a shipping project that lives
    /// there must not be marked. NEVER from a directory name.
    [Fact]
    public void DirectoryNameIsNeverAMarker()
    {
        var root = Fixtures.NewScratch("marker-dir");
        try
        {
            WriteProject(root, Path.Combine("tests", "Product"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup><PackageReference Include="Some.Library" Version="1.0.0" /></ItemGroup>
                </Project>
                """);
            var project = Assert.Single(FactsCommand.Build(root, "test").Projects);
            Assert.Equal("tests/Product/Product.csproj", project.Path);
            Assert.False(project.IsTestProject);
            Assert.Null(project.TestMarker);
        }
        finally
        {
            Fixtures.DeleteScratch(root);
        }
    }

    private static void WriteProject(string root, string relDir, string csproj)
    {
        var dir = Path.Combine(root, relDir);
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, Path.GetFileName(relDir) + ".csproj"), csproj);
    }
}
