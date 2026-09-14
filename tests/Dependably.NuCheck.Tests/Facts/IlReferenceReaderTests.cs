using Dependably.NuCheck.Facts;
using Dependably.NuCheck.Facts.Il;
using Microsoft.CodeAnalysis;

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

/// <summary>
/// The three normalization/resolution refinements ported for parity with
/// sbom-reach's sidecar analyzer, exercised against Roslyn-emitted DLLs
/// (<see cref="Fixtures.EmitAssembly"/>) rather than the shared real
/// `dotnet build` fixture — fast, and isolated to exactly the metadata shapes
/// each refinement targets: a property (accessor naming), a generic class and
/// a closed-generic member access (arity stripping + the pre-existing
/// TypeSpecification resolution) all in one small "library + consumer"
/// assembly pair.
/// </summary>
public class IlReferenceReaderNormalizationTests
{
    /// <summary>
    /// Emits a library DLL with a public class and an auto-property, and a
    /// consumer DLL that both reads and writes that property and puts the
    /// library type into a <c>List&lt;T&gt;</c> — real IL exercising all three
    /// refinements at once. Returns the consumer's raw reference list
    /// (un-deduplicated — that's <c>FactsCommand</c>'s job, not the reader's).
    /// </summary>
    private static List<ReferenceInfo> EmitConsumerReferences()
    {
        var root = Fixtures.NewScratch("il-normalization");
        try
        {
            var libPath = Path.Combine(root, "TestLib.dll");
            Fixtures.EmitAssembly("TestLib", """
                namespace TestLib
                {
                    public class Widget
                    {
                        public string Name { get; set; } = "";
                    }
                }
                """, libPath);

            var consumerPath = Path.Combine(root, "Consumer.dll");
            Fixtures.EmitAssembly("Consumer", """
                using System.Collections.Generic;
                using TestLib;

                namespace TestApp
                {
                    public static class Program
                    {
                        public static void Run()
                        {
                            var widget = new Widget();
                            widget.Name = "x";
                            var read = widget.Name;
                            var list = new List<Widget>();
                            list.Add(widget);
                        }
                    }
                }
                """, consumerPath, [MetadataReference.CreateFromFile(libPath)]);

            var unanalyzable = new List<UnanalyzableEntry>();
            var ok = IlReferenceReader.TryEnumerateReferences(consumerPath, root, unanalyzable, out var references);
            Assert.True(ok);
            Assert.Empty(unanalyzable);
            return references;
        }
        finally
        {
            Fixtures.DeleteScratch(root);
        }
    }

    [Fact]
    public void AccessorReferencesAreAlsoRecordedUnderTheirNaturalPropertyName()
    {
        var references = EmitConsumerReferences();

        // Raw compiled accessor names are still reported...
        Assert.Contains(references, r => r.Kind == "il-member-ref" && r.Symbol == "TestLib.Widget.set_Name" && r.AssemblyName == "TestLib");
        Assert.Contains(references, r => r.Kind == "il-member-ref" && r.Symbol == "TestLib.Widget.get_Name" && r.AssemblyName == "TestLib");

        // ...and additionally normalized to the natural property name, so a
        // consumer correlating source-level `Name` usage doesn't miss them.
        Assert.Contains(references, r => r.Kind == "il-member-ref" && r.Symbol == "TestLib.Widget.Name" && r.AssemblyName == "TestLib");
    }

    [Fact]
    public void GenericTypeReferencesAreAlsoRecordedWithArityStripped()
    {
        var references = EmitConsumerReferences();

        var rawListRef = Assert.Single(references, r => r.Kind == "il-type-ref" && r.Symbol == "System.Collections.Generic.List`1");
        // Arity-stripped form additionally recorded, same defining assembly.
        Assert.Contains(references, r =>
            r.Kind == "il-type-ref" && r.Symbol == "System.Collections.Generic.List" && r.AssemblyName == rawListRef.AssemblyName);
    }

    /// <c>list.Add(widget)</c> is a member invoked on the CLOSED generic type
    /// <c>List&lt;Widget&gt;</c> — MemberReference.Parent is a
    /// TypeSpecification, not a TypeReference directly. This is the
    /// pre-existing GENERICINST resolution path (unchanged by this port);
    /// asserted here to pin that it keeps working now that both the raw and
    /// arity-stripped type spellings flow through it.
    [Fact]
    public void MemberOnAClosedGenericTypeResolvesUnderBothTypeSpellings()
    {
        var references = EmitConsumerReferences();

        Assert.Contains(references, r => r.Kind == "il-member-ref" && r.Symbol == "System.Collections.Generic.List`1.Add");
        Assert.Contains(references, r => r.Kind == "il-member-ref" && r.Symbol == "System.Collections.Generic.List.Add");
    }
}
