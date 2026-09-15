using System.Text.Json;
using Dependably.NuCheck.Facts.Il;
using Dependably.NuCheck.Facts.Nuget;
using Dependably.NuCheck.Facts.Scan;

namespace Dependably.NuCheck.Facts;

/// <summary>
/// <c>--facts &lt;dir&gt;</c>: gather the .NET language and packaging facts of a
/// source tree and publish them as one JSON document on stdout. A report, not a
/// gate: a successful scan exits 0 even when <c>unanalyzable</c> is non-empty
/// (the document says so); only a missing or unreadable target exits 2.
///
/// The ownership rule this exists for: nucheck owns LANGUAGE FACTS (AST usings
/// and qualified identifiers, restore-artefact and lockfile parsing, assembly
/// namespace reads, IL member references, line locations). What those facts
/// mean for a vulnerability — reachable or not, confidence, dev-only, shipped —
/// is the consumer's verdict, and nothing verdict-shaped is computed here.
/// </summary>
public static class FactsCommand
{
    private const int ExitOk = 0;
    private const int ExitError = 2;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    /// <summary>
    /// Runs the facts scan. Writes the document to <paramref name="stdout"/> and,
    /// under <paramref name="verbose"/>, progress to <paramref name="stderr"/>.
    /// <paramref name="roots"/> are the <c>--roots</c> the caller asked for (see
    /// <see cref="Build"/>).
    /// </summary>
    public static int Run(
        string target,
        string toolVersion,
        IReadOnlyList<string> roots,
        bool verbose,
        TextWriter stdout,
        TextWriter stderr)
    {
        var srcDir = Path.GetFullPath(target);
        if (!Directory.Exists(srcDir))
        {
            stderr.WriteLine($"Error: target directory does not exist: {target}");
            return ExitError;
        }
        try
        {
            Directory.GetFileSystemEntries(srcDir);
        }
        catch (Exception ex)
        {
            stderr.WriteLine($"Error: target directory is not readable: {target} ({ex.Message})");
            return ExitError;
        }

        var document = Build(target, toolVersion, verbose ? stderr : null, roots);
        stdout.WriteLine(Serialize(document));
        return ExitOk;
    }

    /// <summary>The document's wire form: indented JSON, omitted keys where the tool could not tell.</summary>
    public static string Serialize(FactsDocument document) => JsonSerializer.Serialize(document, JsonOptions);

    /// <summary>
    /// Builds the document for an existing, readable directory.
    /// <paramref name="extraRoots"/> EXTENDS <c>source.qualifiedRoots</c> before the
    /// scan: the tree-derived roots come from the artefacts the tree carries, so a
    /// package a consumer cares about that is in no readable artefact (an un-restored
    /// tree, no lock file) would otherwise lose every fully-qualified use of it
    /// (<c>Foo.Bar.Client.Send(...)</c> with no <c>using</c>) with no way to get them
    /// back. The applied set is still published so the filter stays visible.
    /// </summary>
    public static FactsDocument Build(
        string target,
        string toolVersion,
        TextWriter? progress = null,
        IEnumerable<string>? extraRoots = null)
    {
        var srcDir = Path.GetFullPath(target);
        var unanalyzable = new List<UnanalyzableEntry>();

        var (projects, cpmDeclarations) = ProjectDiscovery.Discover(srcDir, unanalyzable);
        progress?.WriteLine($"Discovered {projects.Count} project(s) under {target}");

        var assets = AssetsReader.ReadAll(srcDir, projects, unanalyzable);
        var nsMap = NamespaceMap.Build(assets.Closure.Values, assets.PackageFolders, srcDir, unanalyzable);
        progress?.WriteLine($"Resolved {assets.Closure.Count} package(s); {nsMap.Values.Count(n => n.DllBacked)} with readable assemblies");

        var qualifiedRoots = BuildQualifiedRoots(nsMap, assets, projects, cpmDeclarations);
        foreach (var root in extraRoots ?? [])
        {
            qualifiedRoots.Add(FirstSegment(root));
        }
        var scanned = UsingScanner.ScanAll(srcDir, qualifiedRoots, unanalyzable);
        progress?.WriteLine($"Scanned {scanned.Count} C# file(s)");

        var projectFacts = new List<ProjectFacts>();
        var ilFacts = new List<IlFacts>();
        var ilAssembliesRead = 0;
        foreach (var project in projects)
        {
            var relCsproj = ProjectDiscovery.RelativePath(srcDir, project.CsprojPath);
            var outputAssembly = IlReferenceReader.FindOutputAssembly(project.CsprojPath, srcDir, unanalyzable);
            string? relAssembly = null;
            if (outputAssembly is not null)
            {
                relAssembly = ProjectDiscovery.RelativePath(srcDir, outputAssembly);
                if (IlReferenceReader.TryEnumerateReferences(outputAssembly, srcDir, unanalyzable, out var references))
                {
                    ilAssembliesRead++;
                    ilFacts.Add(new IlFacts
                    {
                        Project = relCsproj,
                        Assembly = relAssembly,
                        References = references
                            .Distinct()
                            .OrderBy(r => r.Kind, StringComparer.Ordinal)
                            .ThenBy(r => r.Symbol, StringComparer.Ordinal)
                            .ThenBy(r => r.AssemblyName, StringComparer.Ordinal)
                            .Select(r => new IlReferenceFacts(r.Kind, r.Symbol, r.AssemblyName))
                            .ToList(),
                    });
                }
            }

            var runtime = DepsReader.Read(srcDir, project, unanalyzable);
            projectFacts.Add(new ProjectFacts
            {
                Path = relCsproj,
                IsTestProject = project.IsTestProject,
                TestMarker = project.TestMarker,
                DirectReferences = project.DirectReferences
                    .Select(d => new DeclarationFacts(d.PackageId, d.File, d.Line))
                    .ToList(),
                Assets = assets.AssetsFileByProject.TryGetValue(project.CsprojPath, out var source)
                    ? new AssetsSourceFacts(source.File, source.Kind)
                    : null,
                Closure = assets.PackagesByProject.TryGetValue(project.CsprojPath, out var closure)
                    ? closure
                        .OrderBy(p => p.Id, StringComparer.OrdinalIgnoreCase)
                        .ThenBy(p => p.Version, StringComparer.Ordinal)
                        .ToList()
                    : null,
                OutputAssembly = relAssembly,
                RuntimeOutput = runtime?
                    .Select(r => new RuntimeOutputFacts(r.DepsJson, r.Packages))
                    .ToList(),
            });
        }
        progress?.WriteLine($"Read {ilFacts.Count} first-party output assembl{(ilFacts.Count == 1 ? "y" : "ies")}");

        var packageFacts = assets.Closure.Values
            .OrderBy(p => p.Id, StringComparer.OrdinalIgnoreCase)
            .ThenBy(p => p.Version, StringComparer.Ordinal)
            .Select(p => PackageFactsOf(p, nsMap[p.Key], assets, srcDir, unanalyzable))
            .ToList();

        var projectDirs = ProjectDirectories(srcDir, projects);
        var sourceFiles = scanned
            .Select(f => new SourceFileFacts
            {
                File = f.File,
                Project = ProjectOf(f.File, projectDirs),
                Usings = f.Uses
                    .Where(u => u.Kind != "qualified-identifier")
                    .Select(u => new UsingFacts
                    {
                        Namespace = u.Namespace,
                        Line = u.Line,
                        Global = u.Kind == "global-using",
                        Static = u.Static,
                        Alias = u.Alias,
                        Disabled = u.Disabled,
                    })
                    .ToList(),
                Qualified = f.Uses
                    .Where(u => u.Kind == "qualified-identifier")
                    .Select(u => new QualifiedFacts { Namespace = u.Namespace, Line = u.Line, Snippet = u.Snippet })
                    .ToList(),
            })
            .ToList();

        var unanalyzableFacts = unanalyzable
            .Distinct()
            .OrderBy(u => u.File, StringComparer.Ordinal)
            .ThenBy(u => u.Kind, StringComparer.Ordinal)
            .ToList();
        if (unanalyzableFacts.Count > 0)
        {
            progress?.WriteLine($"{unanalyzableFacts.Count} path(s) could not be analyzed (see unanalyzable)");
        }

        return new FactsDocument
        {
            ToolVersion = toolVersion,
            Target = target,
            Summary = new FactsSummary
            {
                Projects = projectFacts.Count,
                FilesScanned = sourceFiles.Count,
                AssembliesRead = nsMap.Values.Sum(n => n.AssembliesRead) + ilAssembliesRead,
                Packages = packageFacts.Count,
                PackagesWithNamespaces = packageFacts.Count(p => p.Namespaces is { Count: > 0 }),
                Unanalyzable = unanalyzableFacts.Count,
                ExitCode = ExitOk,
            },
            Projects = projectFacts,
            CentralPackageVersions = cpmDeclarations
                .Select(d => new DeclarationFacts(d.PackageId, d.File, d.Line))
                .ToList(),
            Packages = packageFacts,
            PackageFolders = assets.PackageFolders
                .Select(f => new PackageFolderFacts(f.Replace('\\', '/'), Directory.Exists(f)))
                .ToList(),
            Source = new SourceFacts
            {
                QualifiedRoots = qualifiedRoots.OrderBy(r => r, StringComparer.Ordinal).ToList(),
                Files = sourceFiles,
            },
            Il = ilFacts,
            Unanalyzable = unanalyzableFacts,
        };
    }

    private static PackageFacts PackageFactsOf(
        ResolvedPackage package,
        PackageNamespaces namespaces,
        AssetsInfo assets,
        string srcDir,
        List<UnanalyzableEntry> unanalyzable)
    {
        // The three tiers, made visible: read from DLLs → the list; provably no
        // assemblies → an empty list; nothing readable → OMITTED, never the id.
        List<string>? namespaceFacts = namespaces.Mapping switch
        {
            NamespaceMapping.DllVerified => namespaces.Namespaces.OrderBy(n => n, StringComparer.Ordinal).ToList(),
            NamespaceMapping.NoLibAssemblies => [],
            _ => null,
        };

        // One .nuspec load answers both questions, and its ABSENCE answers a third:
        // no readable file means `producer` is omitted ("cannot tell"), while a file
        // that states no <authors> gets an explicit null ("it says none").
        var nuspec = NuspecReader.Read(assets.PackageFolders, package.Id, package.Version, srcDir, unanalyzable);

        return new PackageFacts
        {
            Id = package.Id,
            Version = package.Version,
            License = nuspec?.License,
            Assemblies = package.FilesKnown
                ? package.LibDllRelPaths
                    .Select(Path.GetFileNameWithoutExtension)
                    .Where(s => !string.IsNullOrEmpty(s))
                    .Select(s => s!)
                    .Distinct(StringComparer.Ordinal)
                    .OrderBy(s => s, StringComparer.Ordinal)
                    .ToList()
                : null,
            Namespaces = namespaceFacts,
            Dependencies = assets.DependencyEdges.TryGetValue(package.Key, out var deps)
                ? deps.OrderBy(d => d, StringComparer.OrdinalIgnoreCase).ToList()
                : [],
            Hashes = package.Hashes
                .OrderBy(h => h.Source, StringComparer.Ordinal)
                .ThenBy(h => h.File, StringComparer.Ordinal)
                .ThenBy(h => h.Field, StringComparer.Ordinal)
                .ThenBy(h => h.Value, StringComparer.Ordinal)
                .ToList(),
            Producer = nuspec?.Producer,
        };
    }

    /// The set of top-level identifier segments worth keeping qualified
    /// identifiers for: first segments of every DLL-read namespace (and of the
    /// id-convention fallback the map records for unread packages) plus of every
    /// closure or declared package id. Published as `source.qualifiedRoots` so a
    /// consumer knows what the `qualified` lists could contain.
    private static HashSet<string> BuildQualifiedRoots(
        Dictionary<string, PackageNamespaces> nsMap,
        AssetsInfo assets,
        List<ProjectInfo> projects,
        List<PackageDeclaration> cpmDeclarations)
    {
        var roots = new HashSet<string>(StringComparer.Ordinal);
        foreach (var pkg in nsMap.Values)
            foreach (var ns in pkg.Namespaces)
            {
                roots.Add(FirstSegment(ns));
            }
        foreach (var id in assets.Closure.Values.Select(p => p.Id)
            .Concat(projects.SelectMany(p => p.DirectReferences).Select(d => d.PackageId))
            .Concat(cpmDeclarations.Select(d => d.PackageId)))
        {
            roots.Add(FirstSegment(id));
        }
        return roots;
    }

    private static string FirstSegment(string dotted)
    {
        var dot = dotted.IndexOf('.');
        return dot > 0 ? dotted[..dot] : dotted;
    }

    /// Project directories relative to srcDir (POSIX separators, no trailing
    /// slash; "" for a project at the root), longest first so the innermost
    /// project wins when projects nest.
    private static List<(string Dir, string Csproj)> ProjectDirectories(string srcDir, List<ProjectInfo> projects)
    {
        var dirs = new List<(string Dir, string Csproj)>();
        foreach (var project in projects)
        {
            var projectDir = Path.GetDirectoryName(project.CsprojPath)!;
            var rel = ProjectDiscovery.RelativePath(srcDir, projectDir);
            dirs.Add((rel == "." ? "" : rel, ProjectDiscovery.RelativePath(srcDir, project.CsprojPath)));
        }
        dirs.Sort((a, b) => b.Dir.Length.CompareTo(a.Dir.Length));
        return dirs;
    }

    /// The innermost discovered project whose directory contains the file, or
    /// null for a file under no project at all. A fact about location; what a
    /// project-less file means is the consumer's call.
    private static string? ProjectOf(string relFile, List<(string Dir, string Csproj)> projectDirs)
    {
        foreach (var (dir, csproj) in projectDirs)
        {
            if (dir.Length == 0 || relFile.StartsWith(dir + "/", StringComparison.Ordinal)) return csproj;
        }
        return null;
    }
}
