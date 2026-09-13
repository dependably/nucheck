using Dependably.NuCheck.Facts;
using Dependably.NuCheck.Facts.Nuget;

namespace Dependably.NuCheck.Tests.Facts;

public class NamespaceMapTests
{
    private static Dictionary<string, PackageNamespaces> Build(ResolvedPackage package, string folder, List<UnanalyzableEntry> unanalyzable) =>
        NamespaceMap.Build([package], [folder], folder, unanalyzable);

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

            var unanalyzable = new List<UnanalyzableEntry>();
            var map = Build(new("Acme.Widgets", "1.2.3", ["lib/netstandard2.0/Acme.Widgets.dll"], FilesKnown: true), tempRoot, unanalyzable);

            var entry = map["Acme.Widgets/1.2.3"];
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
        var map = NamespaceMap.Build([new ResolvedPackage("Some.Package", "1.0.0", ["lib/net8.0/Some.Package.dll"], FilesKnown: true)], [], ".", []);
        var entry = map["Some.Package/1.0.0"];
        Assert.False(entry.DllBacked);
        Assert.Equal(NamespaceMapping.IdConvention, entry.Mapping);
        Assert.Equal(0, entry.AssembliesRead);
        // The convention root is kept for `qualifiedRoots`; the document itself
        // never publishes it as a namespace (see FixtureDocumentTests).
        Assert.Contains("Some.Package", entry.Namespaces);
    }

    /// The guess is wrong for whole families of real packages (AWSSDK.S3 exposes
    /// `Amazon.S3`), so the mapping must SAY it is a guess — the document omits
    /// `namespaces` on this tier rather than publishing the id.
    [Fact]
    public void IdConventionMappingIsRecordedAsAGuess()
    {
        var map = NamespaceMap.Build([new ResolvedPackage("AWSSDK.S3", "3.7.0", ["lib/netstandard2.0/AWSSDK.S3.dll"], FilesKnown: true)], ["/definitely/not/a/dir"], ".", []);
        Assert.Equal(NamespaceMapping.IdConvention, map["AWSSDK.S3/3.7.0"].Mapping);
        Assert.False(map["AWSSDK.S3/3.7.0"].DllBacked);
    }

    /// A package whose file list IS known and contains no assembly (analyzer- or
    /// targets-only) exposes no types at all: its emptiness is provable, not
    /// guessed, and it contributes no namespaces to match against.
    [Fact]
    public void PackageWithNoAssembliesHasNoNamespacesAndAProvableMapping()
    {
        var map = NamespaceMap.Build([new ResolvedPackage("StyleCop.Analyzers", "1.1.1", [], FilesKnown: true)], [], ".", []);
        var entry = map["StyleCop.Analyzers/1.1.1"];
        Assert.Equal(NamespaceMapping.NoLibAssemblies, entry.Mapping);
        Assert.Empty(entry.Namespaces);
    }

    /// A lock file names the closure but never lists package files. An empty DLL
    /// list there means "unknown", not "ships no assemblies" — conflating them
    /// would let a lockfile-only repo claim packages expose no referenceable types.
    [Fact]
    public void LockfileOnlyClosureIsIdConventionNotNoAssemblies()
    {
        var map = NamespaceMap.Build([new ResolvedPackage("Newtonsoft.Json", "13.0.1", [], FilesKnown: false)], [], ".", []);
        Assert.Equal(NamespaceMapping.IdConvention, map["Newtonsoft.Json/13.0.1"].Mapping);
    }

    /// Two versions of one id are two entries, each read from its own folder.
    [Fact]
    public void TwoVersionsOfOneIdAreReadSeparately()
    {
        var tempRoot = Fixtures.NewScratch("nsmap-versions");
        try
        {
            foreach (var (version, ns) in new[] { ("1.0.0", "Acme.V1"), ("2.0.0", "Acme.V2") })
            {
                var pkgDir = Path.Combine(tempRoot, "acme.widgets", version, "lib", "netstandard2.0");
                Directory.CreateDirectory(pkgDir);
                Fixtures.EmitAssembly("Acme.Widgets", $"namespace {ns} {{ public class Widget {{ }} }}", Path.Combine(pkgDir, "Acme.Widgets.dll"));
            }

            var map = NamespaceMap.Build(
                [
                    new ResolvedPackage("Acme.Widgets", "1.0.0", ["lib/netstandard2.0/Acme.Widgets.dll"], FilesKnown: true),
                    new ResolvedPackage("Acme.Widgets", "2.0.0", ["lib/netstandard2.0/Acme.Widgets.dll"], FilesKnown: true),
                ],
                [tempRoot], tempRoot, []);

            Assert.Equal(["Acme.V1"], map["Acme.Widgets/1.0.0"].Namespaces);
            Assert.Equal(["Acme.V2"], map["Acme.Widgets/2.0.0"].Namespaces);
        }
        finally
        {
            Fixtures.DeleteScratch(tempRoot);
        }
    }

    /// A DLL that exists but is not a readable PE file is reported, not skipped:
    /// the package then falls to the guessed tier AND the document says why —
    /// with a path relative to the scanned tree and a reason that names no path.
    [Fact]
    public void UnreadableAssemblyIsReportedAsUnanalyzable()
    {
        var tempRoot = Fixtures.NewScratch("nsmap-bad");
        try
        {
            var pkgDir = Path.Combine(tempRoot, "acme.widgets", "1.2.3", "lib", "netstandard2.0");
            Directory.CreateDirectory(pkgDir);
            File.WriteAllText(Path.Combine(pkgDir, "Acme.Widgets.dll"), "this is not a PE file");

            var unanalyzable = new List<UnanalyzableEntry>();
            var entry = Build(new("Acme.Widgets", "1.2.3", ["lib/netstandard2.0/Acme.Widgets.dll"], FilesKnown: true), tempRoot, unanalyzable)["Acme.Widgets/1.2.3"];

            Assert.Equal(NamespaceMapping.IdConvention, entry.Mapping);
            Assert.Equal(
                [new UnanalyzableEntry("acme.widgets/1.2.3/lib/netstandard2.0/Acme.Widgets.dll", "assembly", "could not read metadata: not a valid PE/metadata image")],
                unanalyzable);
        }
        finally
        {
            Fixtures.DeleteScratch(tempRoot);
        }
    }

    /// A DLL the artefact LISTS but the package folder LACKS is a gap, not a
    /// skip: the namespaces read from the sibling that is present would otherwise
    /// be published as the package's complete set.
    [Fact]
    public void ListedButMissingAssemblyIsReportedAndSiblingStillRead()
    {
        var tempRoot = Fixtures.NewScratch("nsmap-missing");
        try
        {
            var pkgDir = Path.Combine(tempRoot, "acme.widgets", "1.2.3", "lib", "netstandard2.0");
            Directory.CreateDirectory(pkgDir);
            Fixtures.EmitAssembly("Acme.Widgets", "namespace Acme.Widgets { public class Widget { } }", Path.Combine(pkgDir, "Acme.Widgets.dll"));

            var unanalyzable = new List<UnanalyzableEntry>();
            var entry = Build(
                new("Acme.Widgets", "1.2.3", ["lib/netstandard2.0/Acme.Widgets.dll", "lib/netstandard2.0/Acme.Widgets.Extras.dll"], FilesKnown: true),
                tempRoot, unanalyzable)["Acme.Widgets/1.2.3"];

            Assert.Equal(NamespaceMapping.DllVerified, entry.Mapping);
            Assert.Equal(["Acme.Widgets"], entry.Namespaces);
            Assert.Equal(1, entry.AssembliesRead);
            Assert.Equal(
                [new UnanalyzableEntry("acme.widgets/1.2.3/lib/netstandard2.0/Acme.Widgets.Extras.dll", "assembly", NamespaceMap.MissingListedAssemblyReason)],
                unanalyzable);
        }
        finally
        {
            Fixtures.DeleteScratch(tempRoot);
        }
    }

    /// A package-cache DLL OUTSIDE the scanned tree keeps its absolute path (POSIX
    /// separators) — never a `../..` chain.
    [Fact]
    public void AssemblyOutsideTheTreeIsReportedWithItsAbsolutePath()
    {
        var tempRoot = Fixtures.NewScratch("nsmap-outside");
        try
        {
            var srcDir = Path.Combine(tempRoot, "src");
            var gp = Path.Combine(tempRoot, "gp");
            Directory.CreateDirectory(srcDir);
            var pkgDir = Path.Combine(gp, "acme.widgets", "1.2.3", "lib", "netstandard2.0");
            Directory.CreateDirectory(pkgDir);
            var dll = Path.Combine(pkgDir, "Acme.Widgets.dll");
            File.WriteAllText(dll, "not a PE file");

            var unanalyzable = new List<UnanalyzableEntry>();
            NamespaceMap.Build([new ResolvedPackage("Acme.Widgets", "1.2.3", ["lib/netstandard2.0/Acme.Widgets.dll"], FilesKnown: true)], [gp], srcDir, unanalyzable);

            Assert.Equal(Path.GetFullPath(dll).Replace('\\', '/'), Assert.Single(unanalyzable).File);
        }
        finally
        {
            Fixtures.DeleteScratch(tempRoot);
        }
    }
}
