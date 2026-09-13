using System.Text.Json;
using Dependably.NuCheck.Facts;

namespace Dependably.NuCheck.Tests.Facts;

/// <summary>
/// One tree, two versions of one package id: App resolves Acme.Widgets 1.0.0,
/// Tests resolves 2.0.0, each from its own artefact. sbom-reach's dedup key is
/// vuln + package + VERSION + manifest, so the document must state both — each
/// with its own assemblies, namespaces, license and dependencies read from its
/// own package folder — and each project's closure must name the version it
/// resolved. Collapsing to the first-seen version would silently drop the
/// facts for the other one.
/// </summary>
public class VersionedClosureTests
{
    private const string PackageId = "Acme.Widgets";

    [Fact]
    public void BothVersionsArePublishedWithTheirOwnFacts()
    {
        using var fixture = new Fixture();
        var doc = FactsCommand.Build(fixture.SrcDir, "test");

        Assert.Equal(2, doc.Summary.Packages);
        Assert.Equal(2, doc.Summary.PackagesWithNamespaces);
        Assert.Equal(
            [new PackageIdentity(PackageId, "1.0.0"), new PackageIdentity(PackageId, "2.0.0")],
            doc.Packages.Select(p => new PackageIdentity(p.Id, p.Version)));

        var v1 = doc.Packages[0];
        Assert.Equal(["Acme.V1"], v1.Namespaces);
        Assert.Equal("MIT", v1.License);
        Assert.Equal(["Acme.Widgets"], v1.Assemblies);
        Assert.Empty(v1.Dependencies);

        var v2 = doc.Packages[1];
        Assert.Equal(["Acme.V2"], v2.Namespaces);
        Assert.Equal("Apache-2.0", v2.License);
        Assert.Equal(["Acme.Widgets", "Acme.Widgets.Extras"], v2.Assemblies);
        Assert.Equal(["Dep.X"], v2.Dependencies);
    }

    [Fact]
    public void EachProjectClosureNamesTheVersionItResolved()
    {
        using var fixture = new Fixture();
        var doc = FactsCommand.Build(fixture.SrcDir, "test");

        var app = Assert.Single(doc.Projects, p => p.Path == "App/App.csproj");
        Assert.Equal([new PackageIdentity(PackageId, "1.0.0")], app.Closure);
        var tests = Assert.Single(doc.Projects, p => p.Path == "Tests/Tests.csproj");
        Assert.Equal([new PackageIdentity(PackageId, "2.0.0")], tests.Closure);

        using var json = JsonDocument.Parse(FactsCommand.Serialize(doc));
        var wireClosure = json.RootElement.GetProperty("projects")[0].GetProperty("closure")[0];
        Assert.Equal("Acme.Widgets", wireClosure.GetProperty("id").GetString());
        Assert.Equal("1.0.0", wireClosure.GetProperty("version").GetString());
        // One root for the id, however many versions. A dependency-edge TARGET
        // (Dep.X) that no artefact resolved contributes no root: roots come from
        // resolved and declared ids and DLL-read namespaces, and `--roots` exists
        // for exactly this gap.
        Assert.Equal(["Acme"], doc.Source.QualifiedRoots);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _root;
        public string SrcDir { get; }

        public Fixture()
        {
            _root = Fixtures.NewScratch("versions");
            SrcDir = Path.Combine(_root, "src");
            var gp = Path.Combine(_root, "gp");

            WritePackage(gp, "1.0.0", "MIT", ("Acme.Widgets", "namespace Acme.V1 { public class Widget { } }"));
            WritePackage(gp, "2.0.0", "Apache-2.0",
                ("Acme.Widgets", "namespace Acme.V2 { public class Widget { } }"),
                ("Acme.Widgets.Extras", "namespace Acme.V2 { public class Extra { } }"));

            WriteProject("App", "1.0.0", gp, files: ["lib/netstandard2.0/Acme.Widgets.dll"], dependencies: null);
            WriteProject("Tests", "2.0.0", gp,
                files: ["lib/netstandard2.0/Acme.Widgets.dll", "lib/netstandard2.0/Acme.Widgets.Extras.dll"],
                dependencies: new Dictionary<string, string> { ["Dep.X"] = "1.0.0" });
        }

        private static void WritePackage(string gp, string version, string license, params (string Name, string Source)[] assemblies)
        {
            var pkgRoot = Path.Combine(gp, PackageId.ToLowerInvariant(), version);
            var libDir = Path.Combine(pkgRoot, "lib", "netstandard2.0");
            Directory.CreateDirectory(libDir);
            foreach (var (name, source) in assemblies)
            {
                Fixtures.EmitAssembly(name, source, Path.Combine(libDir, $"{name}.dll"));
            }
            File.WriteAllText(Path.Combine(pkgRoot, $"{PackageId.ToLowerInvariant()}.nuspec"), $"""
                <?xml version="1.0" encoding="utf-8"?>
                <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
                  <metadata><id>{PackageId}</id><version>{version}</version><license type="expression">{license}</license></metadata>
                </package>
                """);
        }

        private void WriteProject(string name, string version, string gp, string[] files, Dictionary<string, string>? dependencies)
        {
            var dir = Path.Combine(SrcDir, name);
            Directory.CreateDirectory(Path.Combine(dir, "obj"));
            File.WriteAllText(Path.Combine(dir, $"{name}.csproj"), $"""
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup><PackageReference Include="{PackageId}" Version="{version}" /></ItemGroup>
                </Project>
                """);
            var key = $"{PackageId}/{version}";
            var target = new Dictionary<string, object>
            {
                [key] = dependencies is null
                    ? new { type = "package" }
                    : new { type = "package", dependencies },
            };
            File.WriteAllText(Path.Combine(dir, "obj", "project.assets.json"), JsonSerializer.Serialize(new
            {
                version = 3,
                targets = new Dictionary<string, object> { ["net8.0"] = target },
                libraries = new Dictionary<string, object> { [key] = new { type = "package", files } },
                packageFolders = new Dictionary<string, object> { [gp] = new { } },
            }));
        }

        public void Dispose() => Fixtures.DeleteScratch(_root);
    }
}
