using System.Text.Json;
using Dependably.NuCheck.Facts;

namespace Dependably.NuCheck.Tests.Facts;

/// <summary>
/// One monorepo, one package, two artefact KINDS: a restored project's
/// `obj/project.assets.json` enumerates the package's files, an un-restored
/// sibling's `packages.lock.json` cannot. The merged `packages` entry has to
/// carry the enumeration whichever project was discovered first — otherwise the
/// document contradicts itself, omitting `assemblies` (and `namespaces` with it,
/// since <c>NamespaceMap</c> reads the same DLL list) while publishing the very
/// assets file's `sha512` that proves an artefact did enumerate them.
///
/// The one-way direction is the other half of the contract, and the reason these
/// assertions are written at document altitude rather than on the reader: a
/// sighting that could not enumerate files must never overwrite one that did,
/// and a tree with NO enumerating artefact must still OMIT `assemblies` rather
/// than state an empty list — sbom-reach reads that omission as "not looked at"
/// and an empty list as "ships no assemblies".
/// </summary>
public class MixedArtefactClosureTests
{
    private const string PackageId = "Acme.Widgets";
    private const string AssetsSha512 = "AxkxcPR+rheX0SmvpLVIGLhOUXAKG56a64kV9VQZ4y9gR9ZmPXnqZvHJnmwLSwzrEP6junUF11vuc+aqo5r68g==";
    private const string LockContentHash = "6XYi2EusI8JT4y2l/F3VVVS+ISoIX9nqHsZRaG6W5aFeJ5BEuBosHfT/ABb73FN0RZ1Z3cj2j7cL28SToJPXOw==";

    /// Both discovery orders, because before this the answer depended on which
    /// project sorted first: the assets sighting has to win when it arrives second
    /// (the upgrade), and to survive when it arrives first (the lock sighting must
    /// not downgrade it).
    [Theory]
    [InlineData("Alpha", "Beta")]   // assets discovered first: a later lock sighting must not erase the files
    [InlineData("Beta", "Alpha")]   // lock discovered first: the later assets sighting must upgrade it
    public void TheEnumeratingArtefactSuppliesAssembliesAndNamespaces(string assetsProject, string lockProject)
    {
        using var fixture = new Fixture();
        fixture.WriteAssetsProject(assetsProject);
        fixture.WriteLockProject(lockProject);

        var doc = FactsCommand.Build(fixture.SrcDir, "test");
        var package = Assert.Single(doc.Packages);
        Assert.Equal(["Acme.Widgets"], package.Assemblies);
        Assert.Equal(["Acme.Widgets"], package.Namespaces);
        Assert.Equal(1, doc.Summary.PackagesWithNamespaces);

        // The hashes still merge, and still name their own artefacts: the upgrade
        // replaces the record, not its accumulated provenance.
        Assert.Equal(
            [
                new PackageHashFacts("assets", $"{assetsProject}/obj/project.assets.json", "sha512", AssetsSha512),
                new PackageHashFacts("lock", $"{lockProject}/packages.lock.json", "contentHash", LockContentHash),
            ],
            package.Hashes);

        using var json = JsonDocument.Parse(FactsCommand.Serialize(doc));
        var wire = json.RootElement.GetProperty("packages")[0];
        Assert.Equal(["Acme.Widgets"], wire.GetProperty("assemblies").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(["Acme.Widgets"], wire.GetProperty("namespaces").EnumerateArray().Select(e => e.GetString()));
    }

    /// The non-negotiable other side: with no enumerating artefact anywhere, the
    /// key stays OMITTED. `assemblies: []` would tell a consumer the package ships
    /// no assemblies — a false negative about a file list nothing ever read.
    [Fact]
    public void ALockOnlyTreeStillOmitsAssemblies()
    {
        using var fixture = new Fixture();
        fixture.WriteLockProject("Alpha");
        fixture.WriteLockProject("Beta");

        var doc = FactsCommand.Build(fixture.SrcDir, "test");
        var package = Assert.Single(doc.Packages);
        Assert.Null(package.Assemblies);
        Assert.Null(package.Namespaces);

        using var json = JsonDocument.Parse(FactsCommand.Serialize(doc));
        var wire = json.RootElement.GetProperty("packages")[0];
        Assert.False(wire.TryGetProperty("assemblies", out _));
        Assert.False(wire.TryGetProperty("namespaces", out _));
    }

    /// A package genuinely shipping no assemblies (an analyzer- or targets-only
    /// package) keeps its PROVABLE empty list when a lock file also sights it: the
    /// upgrade is about whether an artefact enumerated the files, not about how
    /// many it found, so an enumeration of zero must not be read as ignorance.
    [Fact]
    public void AnEnumeratedEmptyFileListSurvivesALockSighting()
    {
        using var fixture = new Fixture();
        fixture.WriteAssetsProject("Alpha", files: []);
        fixture.WriteLockProject("Beta");

        var package = Assert.Single(FactsCommand.Build(fixture.SrcDir, "test").Packages);
        Assert.Empty(package.Assemblies!);
        Assert.Empty(package.Namespaces!);
    }

    private sealed class Fixture : IDisposable
    {
        private const string DllRelPath = "lib/netstandard2.0/Acme.Widgets.dll";
        private readonly string _root;
        private readonly string _globalPackages;
        public string SrcDir { get; }

        public Fixture()
        {
            _root = Fixtures.NewScratch("mixed-artefact");
            SrcDir = Path.Combine(_root, "src");
            _globalPackages = Path.Combine(_root, "gp");

            var libDir = Path.Combine(_globalPackages, PackageId.ToLowerInvariant(), "1.0.0", "lib", "netstandard2.0");
            Directory.CreateDirectory(libDir);
            Fixtures.EmitAssembly(
                PackageId,
                "namespace Acme.Widgets { public class Widget { } }",
                Path.Combine(libDir, $"{PackageId}.dll"));
        }

        /// A restored project: `libraries` enumerates the package's files, so
        /// FilesKnown is true and the DLL above is readable for its namespaces.
        public void WriteAssetsProject(string name, string[]? files = null)
        {
            var dir = WriteProject(name);
            var key = $"{PackageId}/1.0.0";
            File.WriteAllText(Path.Combine(dir, "obj", "project.assets.json"), JsonSerializer.Serialize(new
            {
                version = 3,
                targets = new Dictionary<string, object> { ["net8.0"] = new Dictionary<string, object> { [key] = new { type = "package" } } },
                libraries = new Dictionary<string, object>
                {
                    [key] = new { type = "package", sha512 = AssetsSha512, files = files ?? [DllRelPath] },
                },
                packageFolders = new Dictionary<string, object> { [_globalPackages] = new { } },
            }));
        }

        /// An un-restored project: the lock file names the closure and never its
        /// contents, so FilesKnown is false.
        public void WriteLockProject(string name)
        {
            var dir = WriteProject(name);
            File.WriteAllText(Path.Combine(dir, "packages.lock.json"), JsonSerializer.Serialize(new
            {
                version = 1,
                dependencies = new Dictionary<string, object>
                {
                    ["net8.0"] = new Dictionary<string, object>
                    {
                        [PackageId] = new { type = "Direct", requested = "[1.0.0, )", resolved = "1.0.0", contentHash = LockContentHash },
                    },
                },
            }));
        }

        private string WriteProject(string name)
        {
            var dir = Path.Combine(SrcDir, name);
            Directory.CreateDirectory(Path.Combine(dir, "obj"));
            File.WriteAllText(Path.Combine(dir, $"{name}.csproj"), $"""
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup><PackageReference Include="{PackageId}" Version="1.0.0" /></ItemGroup>
                </Project>
                """);
            return dir;
        }

        public void Dispose() => Fixtures.DeleteScratch(_root);
    }
}
