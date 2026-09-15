using System.Text.Json;
using Dependably.NuCheck.Facts;

namespace Dependably.NuCheck.Tests.Facts;

/// <summary>
/// What the document states about WHERE a package came from: the hash each
/// restore artefact records for it, and the producer strings its own .nuspec
/// states. Both are published verbatim and both are labelled by source — a lock
/// file's <c>contentHash</c> and an assets file's <c>sha512</c> are different
/// fields of different artefacts, and a consumer that has to guess which one it
/// is holding cannot say what its own hash entry describes.
/// </summary>
public class PackageProvenanceTests
{
    private const string PackageId = "Acme.Widgets";
    private const string AssetsSha512 = "AxkxcPR+rheX0SmvpLVIGLhOUXAKG56a64kV9VQZ4y9gR9ZmPXnqZvHJnmwLSwzrEP6junUF11vuc+aqo5r68g==";
    private const string LockContentHash = "6XYi2EusI8JT4y2l/F3VVVS+ISoIX9nqHsZRaG6W5aFeJ5BEuBosHfT/ABb73FN0RZ1Z3cj2j7cL28SToJPXOw==";

    /// A restored project: the assets file states `sha512`, the package folder
    /// holds the .nuspec, so both halves of the provenance are readable.
    [Fact]
    public void AnAssetsFileYieldsASha512LabelledWithItsFile()
    {
        using var fixture = new Fixture();
        fixture.WriteAssetsProject("App", sha512: AssetsSha512);
        var package = Assert.Single(FactsCommand.Build(fixture.SrcDir, "test").Packages);

        var hash = Assert.Single(package.Hashes);
        Assert.Equal("assets", hash.Source);
        Assert.Equal("App/obj/project.assets.json", hash.File);
        Assert.Equal("sha512", hash.Field);
        Assert.Equal(AssetsSha512, hash.Value);
    }

    /// An un-restored project with a committed lock file: a `contentHash`, named
    /// as such. It is NOT relabelled "sha512" to match the other artefact — the
    /// file does not say that, and a consumer writing a CycloneDX `hashes[].alg`
    /// would be carrying nucheck's guess as NuGet's statement.
    [Fact]
    public void ALockFileYieldsAContentHashLabelledWithItsFile()
    {
        using var fixture = new Fixture();
        fixture.WriteLockProject("App", contentHash: LockContentHash);
        var package = Assert.Single(FactsCommand.Build(fixture.SrcDir, "test").Packages);

        var hash = Assert.Single(package.Hashes);
        Assert.Equal("lock", hash.Source);
        Assert.Equal("App/packages.lock.json", hash.File);
        Assert.Equal("contentHash", hash.Field);
        Assert.Equal(LockContentHash, hash.Value);

        // The lock file names the closure, not its contents, and declares no
        // package folder: no assemblies, and no .nuspec to read a producer from.
        // Those absences are the artefact kind's, not this feature's — they stay
        // omitted rather than being filled with an empty answer.
        using var json = JsonDocument.Parse(FactsCommand.Serialize(FactsCommand.Build(fixture.SrcDir, "test")));
        var wire = json.RootElement.GetProperty("packages")[0];
        Assert.False(wire.TryGetProperty("assemblies", out _));
        Assert.False(wire.TryGetProperty("producer", out _));
        Assert.Equal(1, wire.GetProperty("hashes").GetArrayLength());
    }

    /// One monorepo, one package, two artefacts: a restored project states
    /// `sha512` and an un-restored sibling states `contentHash` for the same
    /// id+version. The merged `packages` entry carries BOTH — first-sighting-wins
    /// would silently drop whichever project was discovered second.
    [Theory]
    [InlineData("Alpha", "Beta")]   // assets discovered first
    [InlineData("Beta", "Alpha")]   // lock discovered first
    public void TwoArtefactsForOnePackageAreBothPublished(string assetsProject, string lockProject)
    {
        using var fixture = new Fixture();
        fixture.WriteAssetsProject(assetsProject, sha512: AssetsSha512);
        fixture.WriteLockProject(lockProject, contentHash: LockContentHash);

        var package = Assert.Single(FactsCommand.Build(fixture.SrcDir, "test").Packages);
        Assert.Equal(
            [
                new PackageHashFacts("assets", $"{assetsProject}/obj/project.assets.json", "sha512", AssetsSha512),
                new PackageHashFacts("lock", $"{lockProject}/packages.lock.json", "contentHash", LockContentHash),
            ],
            package.Hashes);
    }

    /// A multi-targeted project's lock file states one `dependencies` block PER
    /// TFM, and a package resolved for every TFM is restated in each — same file,
    /// same field, same value. That is ONE statement about the artefact: the TFM is
    /// no part of what a hash entry says, so the entry appears once. Without the
    /// dedupe in <c>MergeHashes</c> a consumer mapping entries into a CycloneDX
    /// `hashes[]` would emit a duplicate SHA per framework the project targets,
    /// scaling with the TFM count for no added evidence.
    [Fact]
    public void OneLockFileRestatingAHashPerTfmYieldsOneEntry()
    {
        using var fixture = new Fixture();
        fixture.WriteLockProject("App", LockContentHash, "net8.0", "net9.0", "net10.0");

        var package = Assert.Single(FactsCommand.Build(fixture.SrcDir, "test").Packages);
        Assert.Equal(
            [new PackageHashFacts("lock", "App/packages.lock.json", "contentHash", LockContentHash)],
            package.Hashes);
    }

    /// An artefact entry that states no hash: read, and it said none. Empty, not
    /// omitted and not invented — every package in the document came from an entry
    /// this reader parsed.
    [Fact]
    public void AnArtefactThatStatesNoHashYieldsAnEmptyList()
    {
        using var fixture = new Fixture();
        fixture.WriteAssetsProject("App", sha512: null);

        var doc = FactsCommand.Build(fixture.SrcDir, "test");
        Assert.Empty(Assert.Single(doc.Packages).Hashes);

        using var json = JsonDocument.Parse(FactsCommand.Serialize(doc));
        Assert.Equal(0, json.RootElement.GetProperty("packages")[0].GetProperty("hashes").GetArrayLength());
    }

    /// The producer strings ride verbatim from the .nuspec into the document,
    /// unsplit: `authors` is free text, and the consumer — not nucheck — decides
    /// what "Acme Corp, contributors" means.
    [Fact]
    public void ProducerIsPublishedVerbatimFromTheNuspec()
    {
        using var fixture = new Fixture();
        fixture.WriteAssetsProject("App", sha512: AssetsSha512);
        var doc = FactsCommand.Build(fixture.SrcDir, "test");

        var producer = Assert.Single(doc.Packages).Producer;
        Assert.NotNull(producer);
        Assert.Equal("Acme Corp, contributors", producer.Authors);
        Assert.Equal("acme-bot", producer.Owners);

        using var json = JsonDocument.Parse(FactsCommand.Serialize(doc));
        var wire = json.RootElement.GetProperty("packages")[0].GetProperty("producer");
        Assert.Equal("Acme Corp, contributors", wire.GetProperty("authors").GetString());
        Assert.Equal("acme-bot", wire.GetProperty("owners").GetString());
    }

    /// A .nuspec that was read and states no `owners`: an explicit null on the
    /// wire. That is a different statement from the omitted `producer` of a
    /// package whose .nuspec could not be read at all, and a consumer that has to
    /// decide between "unknown provenance" and "not checked" needs both.
    [Fact]
    public void ANuspecThatStatesNoOwnersWritesAnExplicitNull()
    {
        using var fixture = new Fixture();
        fixture.WriteAssetsProject("App", sha512: AssetsSha512, authors: "Acme Corp", owners: null);

        using var json = JsonDocument.Parse(FactsCommand.Serialize(FactsCommand.Build(fixture.SrcDir, "test")));
        var producer = json.RootElement.GetProperty("packages")[0].GetProperty("producer");
        Assert.Equal("Acme Corp", producer.GetProperty("authors").GetString());
        Assert.Equal(JsonValueKind.Null, producer.GetProperty("owners").ValueKind);
    }

    /// A tree that names a package folder which does not exist — the permanently
    /// un-restored case — reads no .nuspec, so `producer` is OMITTED. Filling it
    /// with nulls here would say "the package states no author" about a file
    /// nobody opened.
    [Fact]
    public void AnUnreadableNuspecOmitsProducerRatherThanNullingIt()
    {
        using var fixture = new Fixture();
        fixture.WriteAssetsProject("App", sha512: AssetsSha512, packageFolder: "/nonexistent/global-packages");

        var doc = FactsCommand.Build(fixture.SrcDir, "test");
        Assert.Null(Assert.Single(doc.Packages).Producer);

        using var json = JsonDocument.Parse(FactsCommand.Serialize(doc));
        Assert.False(json.RootElement.GetProperty("packages")[0].TryGetProperty("producer", out _));
        // The hash is unaffected: it comes from the artefact, not the package folder.
        Assert.Equal(1, json.RootElement.GetProperty("packages")[0].GetProperty("hashes").GetArrayLength());
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _root;
        private readonly string _globalPackages;
        public string SrcDir { get; }

        public Fixture()
        {
            _root = Fixtures.NewScratch("provenance");
            SrcDir = Path.Combine(_root, "src");
            _globalPackages = Path.Combine(_root, "gp");
        }

        public void WriteAssetsProject(
            string name,
            string? sha512,
            string? authors = "Acme Corp, contributors",
            string? owners = "acme-bot",
            string? packageFolder = null)
        {
            if (packageFolder is null) WriteNuspec(authors, owners);
            var dir = WriteProject(name);
            var key = $"{PackageId}/1.0.0";
            var library = new Dictionary<string, object> { ["type"] = "package", ["files"] = new[] { "lib/netstandard2.0/Acme.Widgets.dll" } };
            if (sha512 is not null) library["sha512"] = sha512;
            File.WriteAllText(Path.Combine(dir, "obj", "project.assets.json"), JsonSerializer.Serialize(new
            {
                version = 3,
                targets = new Dictionary<string, object> { ["net8.0"] = new Dictionary<string, object> { [key] = new { type = "package" } } },
                libraries = new Dictionary<string, object> { [key] = library },
                packageFolders = new Dictionary<string, object> { [packageFolder ?? _globalPackages] = new { } },
            }));
        }

        /// <param name="tfms">
        /// The target frameworks the lock file states a `dependencies` block for.
        /// A real multi-targeted project has one block PER TFM, each restating the
        /// same package and the same `contentHash` — the shape the dedupe exists
        /// for. Defaults to the single-TFM case.
        /// </param>
        public void WriteLockProject(string name, string contentHash, params string[] tfms)
        {
            var dir = WriteProject(name);
            var dependencies = new Dictionary<string, object>();
            foreach (var tfm in tfms.Length == 0 ? new[] { "net8.0" } : tfms)
            {
                dependencies[tfm] = new Dictionary<string, object>
                {
                    [PackageId] = new { type = "Direct", requested = "[1.0.0, )", resolved = "1.0.0", contentHash },
                };
            }
            File.WriteAllText(Path.Combine(dir, "packages.lock.json"), JsonSerializer.Serialize(new
            {
                version = 1,
                dependencies,
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

        private void WriteNuspec(string? authors, string? owners)
        {
            var idLower = PackageId.ToLowerInvariant();
            var pkgDir = Path.Combine(_globalPackages, idLower, "1.0.0");
            Directory.CreateDirectory(pkgDir);
            var metadata = $"<id>{PackageId}</id><version>1.0.0</version>"
                + (authors is null ? "" : $"<authors>{authors}</authors>")
                + (owners is null ? "" : $"<owners>{owners}</owners>");
            File.WriteAllText(Path.Combine(pkgDir, $"{idLower}.nuspec"), $"""
                <?xml version="1.0" encoding="utf-8"?>
                <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
                  <metadata>{metadata}</metadata>
                </package>
                """);
        }

        public void Dispose() => Fixtures.DeleteScratch(_root);
    }
}
