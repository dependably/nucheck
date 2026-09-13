using Dependably.NuCheck.Facts;
using Dependably.NuCheck.Facts.Nuget;

namespace Dependably.NuCheck.Tests.Facts;

public class NamespaceMapTests
{
    private static AssetsInfo Assets(Dictionary<string, ResolvedPackage>? closure = null, List<string>? folders = null) =>
        new(
            Closure: closure ?? new(StringComparer.OrdinalIgnoreCase),
            PackageFolders: folders ?? [],
            PackageIdsByProject: new(StringComparer.OrdinalIgnoreCase),
            DependencyEdges: new(StringComparer.OrdinalIgnoreCase),
            AssetsFileByProject: new(StringComparer.OrdinalIgnoreCase));

    /// <summary>
    /// The DLL-backed path: emit a real assembly with Roslyn into a fake
    /// global-packages layout and verify System.Reflection.Metadata reads its
    /// public namespaces (no committed binary fixtures needed).
    /// </summary>
    [Fact]
    public void ReadsPublicNamespacesFromPackageDll()
    {
        var tempRoot = Fixtures.NewScratch("nsmap");
        try
        {
            var pkgDir = Path.Combine(tempRoot, "acme.widgets", "1.2.3", "lib", "netstandard2.0");
            Directory.CreateDirectory(pkgDir);
            Fixtures.EmitAssembly("Acme.Widgets", """
                namespace Acme.Widgets.Core { public class Widget { } }
                namespace Acme.Widgets.Extras { public static class Helper { } }
                namespace Acme.Widgets.Hidden { internal class Secret { } }
                """, Path.Combine(pkgDir, "Acme.Widgets.dll"));

            var assets = Assets(
                new Dictionary<string, ResolvedPackage>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Acme.Widgets"] = new("Acme.Widgets", "1.2.3", ["lib/netstandard2.0/Acme.Widgets.dll"], FilesKnown: true),
                },
                [tempRoot]);

            var unanalyzable = new List<UnanalyzableEntry>();
            var map = NamespaceMap.Build(["Acme.Widgets"], assets, unanalyzable);

            var entry = map["Acme.Widgets"];
            Assert.True(entry.DllBacked);
            Assert.Equal(NamespaceMapping.DllVerified, entry.Mapping);
            Assert.Equal(1, entry.AssembliesRead);
            Assert.Contains("Acme.Widgets.Core", entry.Namespaces);
            Assert.Contains("Acme.Widgets.Extras", entry.Namespaces);
            // Internal types must not contribute namespaces.
            Assert.DoesNotContain("Acme.Widgets.Hidden", entry.Namespaces);
            Assert.Empty(unanalyzable);
        }
        finally
        {
            Fixtures.DeleteScratch(tempRoot);
        }
    }

    [Fact]
    public void FallsBackToPackageIdWhenNoDllIsAvailable()
    {
        var map = NamespaceMap.Build(["Some.Package"], Assets(), []);
        Assert.False(map["Some.Package"].DllBacked);
        Assert.Equal(NamespaceMapping.IdConvention, map["Some.Package"].Mapping);
        Assert.Equal(0, map["Some.Package"].AssembliesRead);
        // The convention root is kept for `qualifiedRoots`; the document itself
        // never publishes it as a namespace (see FixtureDocumentTests).
        Assert.Contains("Some.Package", map["Some.Package"].Namespaces);
    }

    /// The guess is wrong for whole families of real packages (AWSSDK.S3 exposes
    /// `Amazon.S3`), so the mapping must SAY it is a guess — the document omits
    /// `namespaces` on this tier rather than publishing the id.
    [Fact]
    public void IdConventionMappingIsRecordedAsAGuess()
    {
        var map = NamespaceMap.Build(["AWSSDK.S3"], Assets(), []);
        Assert.Equal(NamespaceMapping.IdConvention, map["AWSSDK.S3"].Mapping);
        Assert.False(map["AWSSDK.S3"].DllBacked);
    }

    /// A package whose file list IS known and contains no assembly (analyzer- or
    /// targets-only) exposes no types at all: its emptiness is provable, not
    /// guessed, and it contributes no namespaces to match against.
    [Fact]
    public void PackageWithNoAssembliesHasNoNamespacesAndAProvableMapping()
    {
        var assets = Assets(new Dictionary<string, ResolvedPackage>(StringComparer.OrdinalIgnoreCase)
        {
            ["StyleCop.Analyzers"] = new("StyleCop.Analyzers", "1.1.1", [], FilesKnown: true),
        });

        var entry = NamespaceMap.Build(["StyleCop.Analyzers"], assets, [])["StyleCop.Analyzers"];
        Assert.Equal(NamespaceMapping.NoLibAssemblies, entry.Mapping);
        Assert.Empty(entry.Namespaces);
    }

    /// A lock file names the closure but never lists package files. An empty DLL
    /// list there means "unknown", not "ships no assemblies" — conflating them
    /// would let a lockfile-only repo claim packages expose no referenceable types.
    [Fact]
    public void LockfileOnlyClosureIsIdConventionNotNoAssemblies()
    {
        var assets = Assets(new Dictionary<string, ResolvedPackage>(StringComparer.OrdinalIgnoreCase)
        {
            ["Newtonsoft.Json"] = new("Newtonsoft.Json", "13.0.1", [], FilesKnown: false),
        });

        var entry = NamespaceMap.Build(["Newtonsoft.Json"], assets, [])["Newtonsoft.Json"];
        Assert.Equal(NamespaceMapping.IdConvention, entry.Mapping);
    }

    /// A DLL that exists but is not a readable PE file is reported, not skipped:
    /// the package then falls to the guessed tier AND the document says why.
    [Fact]
    public void UnreadableAssemblyIsReportedAsUnanalyzable()
    {
        var tempRoot = Fixtures.NewScratch("nsmap-bad");
        try
        {
            var pkgDir = Path.Combine(tempRoot, "acme.widgets", "1.2.3", "lib", "netstandard2.0");
            Directory.CreateDirectory(pkgDir);
            File.WriteAllText(Path.Combine(pkgDir, "Acme.Widgets.dll"), "this is not a PE file");

            var assets = Assets(
                new Dictionary<string, ResolvedPackage>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Acme.Widgets"] = new("Acme.Widgets", "1.2.3", ["lib/netstandard2.0/Acme.Widgets.dll"], FilesKnown: true),
                },
                [tempRoot]);

            var unanalyzable = new List<UnanalyzableEntry>();
            var entry = NamespaceMap.Build(["Acme.Widgets"], assets, unanalyzable)["Acme.Widgets"];

            Assert.Equal(NamespaceMapping.IdConvention, entry.Mapping);
            var gap = Assert.Single(unanalyzable);
            Assert.Equal(UnanalyzableEntry.KindAssembly, gap.Kind);
            Assert.EndsWith("Acme.Widgets.dll", gap.File);
        }
        finally
        {
            Fixtures.DeleteScratch(tempRoot);
        }
    }
}
