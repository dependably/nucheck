using Dependably.NuCheck.Facts;

namespace Dependably.NuCheck.Tests.Facts;

/// <summary>
/// IL facts against REAL compiled output. `fixtures/csharp-app` commits no
/// `bin/`, so every test here shares <see cref="CsharpAppBuildFixture"/> — a real
/// `dotnet build` of a temp *copy* of the fixture, never the committed tree in
/// place — and asserts on `il-member-ref`/`il-type-ref` entries, so an unbuilt
/// tree (which yields an empty `il`) fails the test instead of passing it.
/// </summary>
[Collection("CsharpAppBuild")]
public class IlReferenceReaderTests
{
    private readonly string _srcDir;

    public IlReferenceReaderTests(CsharpAppBuildFixture fixture)
    {
        _srcDir = fixture.BuiltCsharpApp;
    }

    private FactsDocument Doc() => FactsCommand.Build(_srcDir, "test");

    [Fact]
    public void EveryBuiltProjectHasAnIlEntryNamingItsAssembly()
    {
        var doc = Doc();

        Assert.Equal(["App/App.csproj", "Lib/Lib.csproj"], doc.Il.Select(i => i.Project));
        Assert.All(doc.Il, i => Assert.EndsWith(".dll", i.Assembly));
        Assert.All(doc.Projects, p => Assert.NotNull(p.OutputAssembly));
        Assert.Equal(doc.Projects.Select(p => p.OutputAssembly), doc.Il.Select(i => i.Assembly));
    }

    [Fact]
    public void MemberReferencesNameTheSymbolAndTheDefiningAssembly()
    {
        var app = Assert.Single(Doc().Il, i => i.Project == "App/App.csproj");

        // App calls JsonConvert.SerializeObject; the reference resolves to the
        // Newtonsoft.Json assembly — the join key a consumer maps to a package via
        // `packages[].assemblies`.
        var serialize = Assert.Single(app.References, r => r.Symbol == "Newtonsoft.Json.JsonConvert.SerializeObject");
        Assert.Equal("il-member-ref", serialize.Kind);
        Assert.Equal("Newtonsoft.Json", serialize.Assembly);
        Assert.Contains(app.References, r => r.Kind == "il-type-ref" && r.Symbol == "Newtonsoft.Json.JsonConvert");

        // Fully-qualified in source, no using directive — still an IL reference.
        Assert.Contains(app.References, r => r.Symbol.StartsWith("Serilog.", StringComparison.Ordinal) && r.Assembly == "Serilog");
    }

    [Fact]
    public void ReferencesAreDistinctAndSorted()
    {
        var app = Assert.Single(Doc().Il, i => i.Project == "App/App.csproj");
        var keys = app.References.Select(r => (r.Kind, r.Symbol, r.Assembly)).ToList();
        Assert.Equal(keys.Distinct().Count(), keys.Count);
        Assert.Equal(
            keys.OrderBy(k => k.Kind, StringComparer.Ordinal).ThenBy(k => k.Symbol, StringComparer.Ordinal).ThenBy(k => k.Assembly, StringComparer.Ordinal),
            keys);
    }

    /// CsvHelper is referenced only inside `#if NET472`, which is not compiled for
    /// net8.0. The source scan still reports the textual using (flagged
    /// `disabled`); the IL scan reads the real compiled output and must NOT — a
    /// real, useful divergence between the two fact sources, not a bug.
    [Fact]
    public void PreprocessorDisabledUsageIsInSourceFactsButNotInIl()
    {
        var doc = Doc();
        var app = Assert.Single(doc.Il, i => i.Project == "App/App.csproj");
        Assert.DoesNotContain(app.References, r => r.Assembly == "CsvHelper" || r.Symbol.StartsWith("CsvHelper", StringComparison.Ordinal));

        var program = Assert.Single(doc.Source.Files, f => f.File == "App/Program.cs");
        Assert.Contains(program.Usings, u => u.Namespace == "CsvHelper" && u.Disabled);
    }

    [Fact]
    public void LibReferencesJObjectThroughItsGlobalUsing()
    {
        var lib = Assert.Single(Doc().Il, i => i.Project == "Lib/Lib.csproj");
        Assert.Contains(lib.References, r => r.Kind == "il-member-ref" && r.Symbol == "Newtonsoft.Json.Linq.JObject.Parse" && r.Assembly == "Newtonsoft.Json");
    }

    /// The build also restored the copy for real, so the same document now
    /// carries DLL-read namespaces and per-output runtime facts — the restored
    /// counterpart of FixtureDocumentTests' un-restored assertions.
    [Fact]
    public void RestoredCopyHasDllReadNamespacesAndRuntimeOutput()
    {
        var doc = Doc();

        var newtonsoft = Assert.Single(doc.Packages, p => p.Id == "Newtonsoft.Json");
        Assert.NotNull(newtonsoft.Namespaces);
        Assert.Contains("Newtonsoft.Json", newtonsoft.Namespaces);
        Assert.Contains("Newtonsoft.Json.Linq", newtonsoft.Namespaces);
        Assert.True(doc.Summary.PackagesWithNamespaces >= 1);
        Assert.True(doc.Summary.AssembliesRead > 2, "package DLLs plus the two first-party assemblies");
        Assert.Contains(doc.PackageFolders, f => f.Readable);

        var app = Assert.Single(doc.Projects, p => p.Path == "App/App.csproj");
        var output = Assert.Single(app.RuntimeOutput!);
        Assert.EndsWith("App.deps.json", output.DepsJson);
        Assert.Contains(output.Packages, p => p.Id == "Newtonsoft.Json" && p.Version == "12.0.1");
    }

    /// A corrupt output assembly is reported (kind `assembly`) and the project
    /// simply has no `il` entry — never a silently empty reference list.
    [Fact]
    public void UnreadableOutputAssemblyIsReported()
    {
        var scratch = Fixtures.NewScratch("il-corrupt");
        try
        {
            Fixtures.CopyExcludingBin(_srcDir, scratch);
            var binDir = Path.Combine(scratch, "Lib", "bin", "Debug", "net8.0");
            Directory.CreateDirectory(binDir);
            File.WriteAllText(Path.Combine(binDir, "Lib.dll"), "not a PE file");

            var doc = FactsCommand.Build(scratch, "test");

            Assert.DoesNotContain(doc.Il, i => i.Project == "Lib/Lib.csproj");
            var lib = Assert.Single(doc.Projects, p => p.Path == "Lib/Lib.csproj");
            Assert.Equal("Lib/bin/Debug/net8.0/Lib.dll", lib.OutputAssembly);
            var gap = Assert.Single(doc.Unanalyzable, u => u.Kind == UnanalyzableEntry.KindAssembly);
            Assert.Equal("Lib/bin/Debug/net8.0/Lib.dll", gap.File);
        }
        finally
        {
            Fixtures.DeleteScratch(scratch);
        }
    }

    /// Build ONLY Lib (standalone — Lib.csproj is not a ProjectReference of
    /// anything). The document is per project: Lib has IL and runtime facts, App
    /// has neither and says so — the consumer sees exactly which projects were
    /// built rather than a merged view that hides the gap.
    [Fact]
    public void MixedBuildReportsPerProjectWhichHaveOutput()
    {
        var scratch = Fixtures.CopyToScratch("il-mixed");
        try
        {
            CsharpAppBuildFixture.BuildProject(Path.Combine(scratch, "Lib", "Lib.csproj"));
            Assert.False(
                Directory.Exists(Path.Combine(scratch, "App", "bin")),
                "test setup assumption violated: building Lib.csproj alone must not also build App");

            var doc = FactsCommand.Build(scratch, "test");

            var ilLib = Assert.Single(doc.Il);
            Assert.Equal("Lib/Lib.csproj", ilLib.Project);
            Assert.Contains(ilLib.References, r => r.Assembly == "Newtonsoft.Json");

            var app = Assert.Single(doc.Projects, p => p.Path == "App/App.csproj");
            Assert.Null(app.OutputAssembly);
            Assert.Null(app.RuntimeOutput);
            var lib = Assert.Single(doc.Projects, p => p.Path == "Lib/Lib.csproj");
            Assert.NotNull(lib.OutputAssembly);
            Assert.NotNull(lib.RuntimeOutput);
        }
        finally
        {
            Fixtures.DeleteScratch(scratch);
        }
    }
}
