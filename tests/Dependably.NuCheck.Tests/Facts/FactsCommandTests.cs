using System.Text.Json;
using Dependably.NuCheck.Facts;
using Dependably.NuCheck.Facts.Nuget;
using Dependably.NuCheck.Models;
using Dependably.NuCheck.Tests.Fakes;

namespace Dependably.NuCheck.Tests.Facts;

/// <summary>
/// The <c>--facts</c> command surface: the envelope, the exit codes, the flags
/// that must be inert, the absence of any network or advisory-source path, and
/// <c>unanalyzable</c> for every kind of read failure. The Program-level tests
/// redirect Console, so the class sits in the non-parallel "Console" collection.
/// </summary>
[Collection("Console")]
public class FactsCommandTests : IDisposable
{
    private readonly TextWriter _originalOut = Console.Out;
    private readonly TextWriter _originalError = Console.Error;
    private readonly string? _originalToken = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
    private readonly List<string> _tempDirs = [];

    private static (int Exit, string Out, string Error) Run(params string[] args)
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        Console.SetOut(stdout);
        Console.SetError(stderr);
        var exit = Program.RunAsync(args).GetAwaiter().GetResult();
        return (exit, stdout.ToString(), stderr.ToString());
    }

    // ---- envelope ------------------------------------------------------------------

    [Fact]
    public void Envelope_carries_identity_and_documentType_facts()
    {
        var (exit, output, _) = Run("--facts", Fixtures.CsharpApp);

        Assert.Equal(0, exit);
        using var json = JsonDocument.Parse(output);
        var root = json.RootElement;
        Assert.Equal(
            ["tool", "toolVersion", "schemaVersion", "documentType", "target", "summary", "projects",
             "centralPackageVersions", "packages", "packageFolders", "source", "il", "unanalyzable"],
            root.EnumerateObject().Select(p => p.Name));
        Assert.Equal("nucheck", root.GetProperty("tool").GetString());
        Assert.Equal("1.0", root.GetProperty("schemaVersion").GetString());
        Assert.Equal("facts", root.GetProperty("documentType").GetString());
        Assert.Equal(Fixtures.CsharpApp, root.GetProperty("target").GetString());
        Assert.Matches(@"^\d+\.\d+\.\d+", root.GetProperty("toolVersion").GetString());
        Assert.Equal(0, root.GetProperty("summary").GetProperty("exitCode").GetInt32());
        Assert.False(root.TryGetProperty("findings", out _));
    }

    /// The ownership rule, pinned: nothing verdict-shaped leaves this tool.
    [Fact]
    public void Document_carries_no_verdicts_purls_or_sbom_fields()
    {
        var (_, output, _) = Run("--facts", Fixtures.CsharpApp);

        foreach (var forbidden in new[] { "\"status\"", "\"confidence\"", "\"purl\"", "\"bomRef\"", "\"devOnly\"", "\"runtimePresent\"", "\"severity\"", "\"findings\"" })
        {
            Assert.DoesNotContain(forbidden, output);
        }
    }

    /// The findings envelope is unchanged: no `documentType` means "findings
    /// document", so a consumer of the existing JSON output sees no new key.
    [Fact]
    public async Task Findings_envelope_still_has_no_documentType()
    {
        var path = WritePackagesConfig("Safe.Pkg", "1.0.0");
        var stdout = new StringWriter();
        Console.SetOut(stdout);
        Console.SetError(new StringWriter());
        var exit = await Program.RunAsync([path, "--format", "json"], _ => new FakeAdvisorySource(new Dictionary<string, IReadOnlyList<Advisory>>()));

        Assert.Equal(0, exit);
        using var json = JsonDocument.Parse(stdout.ToString());
        Assert.False(json.RootElement.TryGetProperty("documentType", out _));
        Assert.True(json.RootElement.TryGetProperty("findings", out _));
    }

    // ---- exit codes ----------------------------------------------------------------

    [Fact]
    public void Missing_target_is_operational_error_exit_two_without_help()
    {
        var (exit, output, error) = Run("--facts", "/definitely/not/a/dir");

        Assert.Equal(2, exit);
        Assert.Contains("does not exist", error);
        Assert.DoesNotContain("Usage:", output);
        Assert.Equal("", output);
    }

    [Fact]
    public void Facts_without_a_directory_is_usage_error_exit_two()
    {
        var (exit, output, error) = Run("--facts");

        Assert.Equal(2, exit);
        Assert.Contains("--facts requires a target directory", error);
        Assert.Contains("Usage:", output);
    }

    [Fact]
    public void Unknown_flag_alongside_facts_is_still_rejected()
    {
        // The capability probe a consumer runs: an older nucheck answers
        // "unknown option: '--facts'" + exit 2. That path must keep working for
        // any unknown flag, facts mode included.
        var (exit, _, error) = Run("--facts", Fixtures.CsharpApp, "--bogus");

        Assert.Equal(2, exit);
        Assert.Contains("unknown option: '--bogus'", error);
    }

    [Fact]
    public void Unanalyzable_entries_do_not_change_the_exit_code()
    {
        var root = NewTempDir("facts-gap");
        Directory.CreateDirectory(Path.Combine(root, "App", "obj"));
        File.WriteAllText(Path.Combine(root, "App", "App.csproj"), "<Project />");
        File.WriteAllText(Path.Combine(root, "App", "obj", "project.assets.json"), "{ not json");

        var (exit, output, _) = Run("--facts", root);

        Assert.Equal(0, exit);
        using var json = JsonDocument.Parse(output);
        Assert.Equal(1, json.RootElement.GetProperty("summary").GetProperty("unanalyzable").GetInt32());
        Assert.Equal(0, json.RootElement.GetProperty("summary").GetProperty("exitCode").GetInt32());
    }

    // ---- inert flags, no network ---------------------------------------------------

    [Fact]
    public void Audit_flags_are_inert_in_facts_mode()
    {
        var (exit, output, _) = Run(
            "--facts", Fixtures.CsharpApp,
            "--fail-on", "severity=low", "--fail-on", "count=0",
            "--severity", "critical", "--format", "table", "--rule", "pinned-versions:error",
            "--rest", "--config", "/no/such/.dependably");

        Assert.Equal(0, exit);
        using var json = JsonDocument.Parse(output);
        Assert.Equal("facts", json.RootElement.GetProperty("documentType").GetString());
    }

    [Fact]
    public void No_advisory_source_is_created_and_no_token_notice_is_printed()
    {
        // `--source bogus` would exit 2 in audit mode (unknown source) and a missing
        // GITHUB_TOKEN would print the OSV fallback notice: facts mode branches before
        // either exists, so neither happens and nothing touches the network.
        Environment.SetEnvironmentVariable("GITHUB_TOKEN", null);

        var (exit, output, error) = Run("--facts", Fixtures.CsharpApp, "--source", "bogus");

        Assert.Equal(0, exit);
        Assert.Equal("", error);
        Assert.DoesNotContain("GITHUB_TOKEN", error);
        Assert.DoesNotContain("OSV", error);
        using var _ = JsonDocument.Parse(output);
    }

    [Fact]
    public void Verbose_progress_goes_to_stderr_and_stdout_stays_pure_json()
    {
        var (exit, output, error) = Run("--facts", Fixtures.CsharpApp, "--verbose");

        Assert.Equal(0, exit);
        Assert.Contains("Discovered 2 project(s)", error);
        Assert.Contains("Scanned 3 C# file(s)", error);
        using var _ = JsonDocument.Parse(output); // would throw on any stray progress line
    }

    // ---- unanalyzable: one entry per read failure, never a silent skip ------------

    [Fact]
    public void Unreadable_source_file_is_unanalyzable_kind_file()
    {
        var root = NewTempDir("facts-unreadable-file");
        File.WriteAllText(Path.Combine(root, "Ok.cs"), "using System;");
        // A dangling symlink is unreadable on every platform, root included.
        File.CreateSymbolicLink(Path.Combine(root, "Gone.cs"), Path.Combine(root, "no-such-target.cs"));

        var doc = FactsCommand.Build(root, "test");

        Assert.Equal(["Ok.cs"], doc.Source.Files.Select(f => f.File));
        // Exact: the reason names the failure class, never the machine's path.
        Assert.Equal([new UnanalyzableEntry("Gone.cs", "file", "unreadable: not found")], doc.Unanalyzable);
        Assert.Equal(1, doc.Summary.Unanalyzable);
    }

    /// A symlinked directory is never followed. `a/loop -> a` would otherwise
    /// enumerate `a/A.cs`, `a/loop/A.cs`, `a/loop/loop/A.cs`, ... until the path
    /// overflowed, and the overflowed entry then fell out of BOTH lists.
    [Fact]
    public void Symlink_loop_is_not_followed_and_is_reported()
    {
        if (OperatingSystem.IsWindows()) return; // symlink creation needs a privilege there.
        var root = NewTempDir("facts-symlink-loop");
        var a = Path.Combine(root, "a");
        Directory.CreateDirectory(a);
        File.WriteAllText(Path.Combine(a, "A.cs"), "using System;");
        Directory.CreateSymbolicLink(Path.Combine(a, "loop"), a);

        var doc = FactsCommand.Build(root, "test");

        Assert.Equal(["a/A.cs"], doc.Source.Files.Select(f => f.File));
        Assert.Equal(1, doc.Summary.FilesScanned);
        Assert.Equal(
            [new UnanalyzableEntry("a/loop", "directory", ProjectDiscovery.SymlinkedDirectoryReason)],
            doc.Unanalyzable);
    }

    /// `vendor -> /somewhere/else` would scan code that is not the target. It is
    /// reported and skipped, and nothing from outside the tree reaches the document.
    [Fact]
    public void Symlink_out_of_tree_is_not_followed_and_is_reported()
    {
        if (OperatingSystem.IsWindows()) return;
        var root = NewTempDir("facts-symlink-out");
        var elsewhere = NewTempDir("facts-symlink-target");
        File.WriteAllText(Path.Combine(elsewhere, "Outside.cs"), "using Outside.Only;");
        File.WriteAllText(Path.Combine(root, "Inside.cs"), "using System;");
        Directory.CreateSymbolicLink(Path.Combine(root, "vendor"), elsewhere);

        var doc = FactsCommand.Build(root, "test");

        Assert.Equal(["Inside.cs"], doc.Source.Files.Select(f => f.File));
        Assert.DoesNotContain("Outside", FactsCommand.Serialize(doc));
        Assert.Equal(
            [new UnanalyzableEntry("vendor", "directory", ProjectDiscovery.SymlinkedDirectoryReason)],
            doc.Unanalyzable);
    }

    [Fact]
    public void Unlistable_directory_is_unanalyzable_kind_directory()
    {
        if (OperatingSystem.IsWindows()) return; // Unix file modes only.
        var root = NewTempDir("facts-unreadable-dir");
        var locked = Path.Combine(root, "locked");
        Directory.CreateDirectory(locked);
        File.WriteAllText(Path.Combine(locked, "Hidden.cs"), "using System;");
        File.SetUnixFileMode(locked, UnixFileMode.None);
        try
        {
            try
            {
                Directory.GetFileSystemEntries(locked);
                // Root ignores mode bits (CI runs as root): the directory cannot be
                // made unlistable here, so there is nothing this test can prove.
                return;
            }
            catch (UnauthorizedAccessException)
            {
                // Expected for a non-root user: the walk must report, not skip.
            }

            var doc = FactsCommand.Build(root, "test");

            Assert.Equal([new UnanalyzableEntry("locked", "directory", "unlistable directory: access denied")], doc.Unanalyzable);
            Assert.Empty(doc.Source.Files);
        }
        finally
        {
            File.SetUnixFileMode(locked, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    [Fact]
    public void Unparseable_assets_file_is_unanalyzable_kind_assets_and_closure_is_omitted()
    {
        var root = NewTempDir("facts-bad-assets");
        Directory.CreateDirectory(Path.Combine(root, "App", "obj"));
        File.WriteAllText(Path.Combine(root, "App", "App.csproj"), "<Project />");
        File.WriteAllText(Path.Combine(root, "App", "obj", "project.assets.json"), "{ not json");

        var doc = FactsCommand.Build(root, "test");

        var gap = Assert.Single(doc.Unanalyzable);
        Assert.Equal("App/obj/project.assets.json", gap.File);
        Assert.Equal(UnanalyzableEntry.KindAssets, gap.Kind);
        var project = Assert.Single(doc.Projects);
        // The artefact was found (a fact) but yielded nothing (not a fact about the closure).
        Assert.Equal(new AssetsSourceFacts("App/obj/project.assets.json", "assets"), project.Assets);
        Assert.Null(project.Closure);
    }

    [Fact]
    public void Unparseable_lock_file_is_unanalyzable_kind_assets()
    {
        var root = NewTempDir("facts-bad-lock");
        Directory.CreateDirectory(Path.Combine(root, "App"));
        File.WriteAllText(Path.Combine(root, "App", "App.csproj"), "<Project />");
        File.WriteAllText(Path.Combine(root, "App", "packages.lock.json"), "{ not json");

        var doc = FactsCommand.Build(root, "test");

        var gap = Assert.Single(doc.Unanalyzable);
        Assert.Equal("App/packages.lock.json", gap.File);
        Assert.Equal(UnanalyzableEntry.KindAssets, gap.Kind);
        Assert.Equal(new AssetsSourceFacts("App/packages.lock.json", "lock"), Assert.Single(doc.Projects).Assets);
    }

    [Fact]
    public void Unparseable_project_file_is_unanalyzable_kind_file()
    {
        var root = NewTempDir("facts-bad-csproj");
        File.WriteAllText(Path.Combine(root, "Broken.csproj"), "<Project><Unclosed></Project>");

        var doc = FactsCommand.Build(root, "test");

        Assert.Empty(doc.Projects);
        var gap = Assert.Single(doc.Unanalyzable);
        Assert.Equal("Broken.csproj", gap.File);
        Assert.Equal(UnanalyzableEntry.KindFile, gap.Kind);
        // The XML parser's position is kept; the machine's path is not.
        Assert.StartsWith("unparseable project file: ", gap.Reason);
        Assert.Contains("Line 1", gap.Reason);
        Assert.DoesNotContain(root, gap.Reason);
        Assert.DoesNotContain("/", gap.Reason);
    }

    [Fact]
    public void Unparseable_assets_reason_is_path_free()
    {
        var root = NewTempDir("facts-bad-assets-reason");
        Directory.CreateDirectory(Path.Combine(root, "App", "obj"));
        File.WriteAllText(Path.Combine(root, "App", "App.csproj"), "<Project />");
        File.WriteAllText(Path.Combine(root, "App", "obj", "project.assets.json"), "{ not json");

        var gap = Assert.Single(FactsCommand.Build(root, "test").Unanalyzable);

        Assert.StartsWith("unparseable assets file: ", gap.Reason);
        Assert.DoesNotContain(root, gap.Reason);
        Assert.DoesNotContain("/", gap.Reason);
    }

    [Fact]
    public void Unreadable_package_assembly_is_unanalyzable_kind_assembly()
    {
        var root = NewTempDir("facts-bad-dll");
        var gp = Path.Combine(root, "gp");
        var dllDir = Path.Combine(gp, "acme.widgets", "1.0.0", "lib", "netstandard2.0");
        Directory.CreateDirectory(dllDir);
        File.WriteAllText(Path.Combine(dllDir, "Acme.Widgets.dll"), "not a PE file");
        Directory.CreateDirectory(Path.Combine(root, "App", "obj"));
        File.WriteAllText(Path.Combine(root, "App", "App.csproj"), "<Project />");
        File.WriteAllText(Path.Combine(root, "App", "obj", "project.assets.json"), JsonSerializer.Serialize(new
        {
            version = 3,
            packageFolders = new Dictionary<string, object> { [gp] = new { } },
            libraries = new Dictionary<string, object>
            {
                ["Acme.Widgets/1.0.0"] = new { type = "package", files = new[] { "lib/netstandard2.0/Acme.Widgets.dll" } },
            },
        }));

        var doc = FactsCommand.Build(root, "test");

        // The package folder is UNDER the target here, so the path is relative.
        Assert.Equal(
            [new UnanalyzableEntry("gp/acme.widgets/1.0.0/lib/netstandard2.0/Acme.Widgets.dll", "assembly", "could not read metadata: not a valid PE/metadata image")],
            doc.Unanalyzable);
        // The package stays in the closure; only its namespaces are unknown.
        var package = Assert.Single(doc.Packages);
        Assert.Null(package.Namespaces);
        Assert.Equal(["Acme.Widgets"], package.Assemblies);
    }

    /// A provably assembly-less package publishes `namespaces: []` but does NOT
    /// count as a package with namespaces; only a non-empty DLL-read list does.
    [Fact]
    public void PackagesWithNamespaces_counts_only_non_empty_dll_read_lists()
    {
        var root = NewTempDir("facts-ns-count");
        var gp = Path.Combine(root, "gp");
        var dllDir = Path.Combine(gp, "acme.widgets", "1.0.0", "lib", "netstandard2.0");
        Directory.CreateDirectory(dllDir);
        Fixtures.EmitAssembly("Acme.Widgets", "namespace Acme.Widgets { public class Widget { } }", Path.Combine(dllDir, "Acme.Widgets.dll"));
        Directory.CreateDirectory(Path.Combine(root, "App", "obj"));
        File.WriteAllText(Path.Combine(root, "App", "App.csproj"), "<Project />");
        File.WriteAllText(Path.Combine(root, "App", "obj", "project.assets.json"), JsonSerializer.Serialize(new
        {
            version = 3,
            packageFolders = new Dictionary<string, object> { [gp] = new { } },
            libraries = new Dictionary<string, object>
            {
                ["Acme.Widgets/1.0.0"] = new { type = "package", files = new[] { "lib/netstandard2.0/Acme.Widgets.dll" } },
                ["Build.Only/1.0.0"] = new { type = "package", files = new[] { "build/Build.Only.targets" } },
            },
        }));

        var doc = FactsCommand.Build(root, "test");

        Assert.Equal(2, doc.Summary.Packages);
        Assert.Equal(["Acme.Widgets"], Assert.Single(doc.Packages, p => p.Id == "Acme.Widgets").Namespaces);
        Assert.Equal([], Assert.Single(doc.Packages, p => p.Id == "Build.Only").Namespaces);
        Assert.Equal(1, doc.Summary.PackagesWithNamespaces);
    }

    // ---- --roots -------------------------------------------------------------------

    /// The tree-derived roots come from the artefacts the tree carries. A package
    /// in no readable artefact loses its fully-qualified uses under the default
    /// filter; `--roots` is how a consumer asks for them, and the applied set is
    /// published either way so the filter stays visible.
    [Fact]
    public void Roots_flag_surfaces_qualified_uses_the_default_filter_drops()
    {
        var root = NewTempDir("facts-roots");
        File.WriteAllText(Path.Combine(root, "Program.cs"), """
            class Program
            {
                static void Main() => Foo.Bar.Client.Send("x");
            }
            """);

        var without = FactsCommand.Build(root, "test");
        Assert.Empty(without.Source.QualifiedRoots);
        Assert.Empty(Assert.Single(without.Source.Files).Qualified);

        var with = FactsCommand.Build(root, "test", extraRoots: ["Foo"]);
        Assert.Equal(["Foo"], with.Source.QualifiedRoots);
        var use = Assert.Single(Assert.Single(with.Source.Files).Qualified);
        Assert.Equal("Foo.Bar.Client.Send", use.Namespace);
        Assert.Equal(3, use.Line);
    }

    [Fact]
    public void Roots_flag_extends_the_tree_derived_roots_end_to_end()
    {
        var (exit, output, _) = Run("--facts", Fixtures.CsharpApp, "--roots", "Fabrikam.Tools,Contoso");

        Assert.Equal(0, exit);
        using var json = JsonDocument.Parse(output);
        var roots = json.RootElement.GetProperty("source").GetProperty("qualifiedRoots").EnumerateArray().Select(r => r.GetString()).ToList();
        Assert.Equal(["Contoso", "CsvHelper", "Fabrikam", "Microsoft", "Newtonsoft", "Polly", "Serilog"], roots);
    }

    [Fact]
    public void Roots_flag_with_a_bad_entry_is_usage_error_exit_two()
    {
        var (exit, _, error) = Run("--facts", Fixtures.CsharpApp, "--roots", "not-an-identifier");

        Assert.Equal(2, exit);
        Assert.Contains("--roots", error);
    }

    [Fact]
    public void Same_gap_seen_by_two_walks_is_reported_once()
    {
        // Project discovery and the source scan both walk the tree; a directory
        // they both fail to list must appear once, not once per walk.
        if (OperatingSystem.IsWindows()) return;
        var root = NewTempDir("facts-dedupe");
        var locked = Path.Combine(root, "locked");
        Directory.CreateDirectory(locked);
        File.SetUnixFileMode(locked, UnixFileMode.None);
        try
        {
            try
            {
                Directory.GetFileSystemEntries(locked);
                return; // root: cannot reproduce, see Unlistable_directory_is_unanalyzable_kind_directory.
            }
            catch (UnauthorizedAccessException)
            {
            }

            var doc = FactsCommand.Build(root, "test");
            Assert.Single(doc.Unanalyzable);
        }
        finally
        {
            File.SetUnixFileMode(locked, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    // ---- helpers -------------------------------------------------------------------

    private string NewTempDir(string label)
    {
        var dir = Fixtures.NewScratch(label);
        _tempDirs.Add(dir);
        return dir;
    }

    private string WritePackagesConfig(string id, string version)
    {
        var dir = NewTempDir("facts-audit");
        File.WriteAllText(Path.Combine(dir, "nuget.config"), """
            <?xml version="1.0" encoding="utf-8"?>
            <configuration>
              <packageSources>
                <clear />
                <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
              </packageSources>
            </configuration>
            """);
        var path = Path.Combine(dir, "packages.config");
        File.WriteAllText(path, $"""
            <?xml version="1.0" encoding="utf-8"?>
            <packages>
              <package id="{id}" version="{version}" targetFramework="net462" />
            </packages>
            """);
        return path;
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
        Console.SetOut(_originalOut);
        Console.SetError(_originalError);
        Environment.SetEnvironmentVariable("GITHUB_TOKEN", _originalToken);
        foreach (var dir in _tempDirs)
        {
            Fixtures.DeleteScratch(dir);
        }
    }
}
