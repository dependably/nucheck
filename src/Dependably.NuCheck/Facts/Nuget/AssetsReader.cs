using System.Text.Json;

namespace Dependably.NuCheck.Facts.Nuget;

/// <param name="LibDllRelPaths">
/// Assembly-bearing files the package ships, under `lib/` (runtime) or `ref/`
/// (compile-time reference assemblies — a package that ships only `ref/` still
/// exposes a public API surface to source code, and its metadata is exactly
/// what NamespaceMap wants to read).
/// </param>
/// <param name="FilesKnown">
/// Whether the source document actually enumerated the package's files.
/// obj/project.assets.json does; packages.lock.json does NOT — so an empty
/// <see cref="LibDllRelPaths"/> means "ships no assemblies" only when this is
/// true, and means "we simply don't know" when it is false. Conflating the two
/// would let a lockfile-only repo claim a package exposes no referenceable
/// types, which is a false-negative factory for any consumer.
/// </param>
public sealed record ResolvedPackage(
    string Id,
    string Version,
    List<string> LibDllRelPaths,
    bool FilesKnown)
{
    /// <summary>
    /// Every hash the artefacts state for this id+version, each naming the
    /// artefact and the key it came from. A list rather than one string because
    /// the two artefact kinds carry DIFFERENT fields (a lock file's
    /// <c>contentHash</c>, an assets file's <c>sha512</c>) and one tree can
    /// resolve the same package through both — see
    /// <see cref="AssetsReader.MergeHashes"/>. Empty means the entries were read
    /// and stated none, never "not looked at": every package here came from an
    /// entry this reader parsed.
    /// </summary>
    public List<PackageHashFacts> Hashes { get; init; } = [];

    /// The identity a closure entry is keyed on. A tree can resolve TWO versions
    /// of one id (App on 12.0.1, Tests on 13.0.3, separate artefacts), and each
    /// has its own package folder, assemblies, namespaces and license — a
    /// consumer whose dedup key carries the version must see both.
    public string Key => KeyOf(Id, Version);

    public static string KeyOf(string id, string version) => $"{id}/{version}";

    public PackageIdentity Identity => new(Id, Version);
}

/// <param name="File">Path of the artefact, relative to the scanned tree.</param>
/// <param name="Kind"><c>assets</c> (obj/project.assets.json) or <c>lock</c> (packages.lock.json).</param>
public sealed record AssetsSource(string File, string Kind)
{
    public const string KindAssets = "assets";
    public const string KindLock = "lock";
}

public sealed record AssetsInfo(
    Dictionary<string, ResolvedPackage> Closure, // key: "Id/Version" (case-insensitive), merged across ALL projects
    List<string> PackageFolders,
    /// Per-project resolved packages (key: that project's absolute .csproj
    /// path), i.e. the full resolved closure from THAT project's own
    /// assets/lock file — unlike <see cref="Closure"/> above (which merges
    /// every project's closure into one dict and loses the per-project
    /// association). A project whose artefact could not be parsed has NO
    /// entry here: an unparseable file is not an empty closure.
    Dictionary<string, List<PackageIdentity>> PackagesByProject,
    /// Dependency edges among the closure: "Id/Version" (case-insensitive) ->
    /// the ids it depends on. Read from `targets.<tfm>.*.dependencies`
    /// (project.assets.json) or `dependencies.<tfm>.*.dependencies`
    /// (packages.lock.json fallback). Reported as written: a dependency name
    /// with no matching `Closure` entry (a target-framework-conditional edge
    /// that didn't resolve for this TFM, or similar) is kept, not dropped —
    /// the document states the file's facts and the consumer filters.
    Dictionary<string, List<string>> DependencyEdges,
    /// Which artefact each project's closure was read from (key: absolute
    /// .csproj path). A project with neither file has no entry.
    Dictionary<string, AssetsSource> AssetsFileByProject);

/// <summary>
/// Reads obj/project.assets.json (and packages.lock.json as a fallback) to get
/// the full resolved package closure without running a restore ourselves.
/// </summary>
public static class AssetsReader
{
    /// The key `project.assets.json` states a package hash under — the KEY names
    /// the algorithm, the value is bare base64 of the .nupkg.
    private const string FieldSha512 = "sha512";

    /// The key `packages.lock.json` states a package hash under. Neither the key
    /// nor the value names an algorithm — hence <see cref="PackageHashFacts"/>
    /// naming the field and the artefact rather than asserting one.
    private const string FieldContentHash = "contentHash";

    public static AssetsInfo ReadAll(string srcDir, IEnumerable<ProjectInfo> projects, List<UnanalyzableEntry> unanalyzable)
    {
        var closure = new Dictionary<string, ResolvedPackage>(StringComparer.OrdinalIgnoreCase);
        var folders = new List<string>();
        var packagesByProject = new Dictionary<string, List<PackageIdentity>>(StringComparer.OrdinalIgnoreCase);
        var edges = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var sources = new Dictionary<string, AssetsSource>(StringComparer.OrdinalIgnoreCase);

        foreach (var project in projects)
        {
            var projectPackages = new List<PackageIdentity>();
            var assetsPath = Path.Combine(Path.GetDirectoryName(project.CsprojPath)!, "obj", "project.assets.json");
            if (File.Exists(assetsPath))
            {
                var assetsSource = new AssetsSource(ProjectDiscovery.RelativePath(srcDir, assetsPath), AssetsSource.KindAssets);
                sources[project.CsprojPath] = assetsSource;
                if (ReadAssetsFile(assetsPath, assetsSource, closure, folders, unanalyzable, srcDir, projectPackages, edges))
                {
                    packagesByProject[project.CsprojPath] = projectPackages;
                }
                continue;
            }
            var lockPath = Path.Combine(Path.GetDirectoryName(project.CsprojPath)!, "packages.lock.json");
            if (File.Exists(lockPath))
            {
                var lockSource = new AssetsSource(ProjectDiscovery.RelativePath(srcDir, lockPath), AssetsSource.KindLock);
                sources[project.CsprojPath] = lockSource;
                if (ReadLockFile(lockPath, lockSource, closure, unanalyzable, srcDir, projectPackages, edges))
                {
                    packagesByProject[project.CsprojPath] = projectPackages;
                }
            }
        }

        return new AssetsInfo(closure, folders.Distinct().ToList(), packagesByProject, edges, sources);
    }

    private static bool ReadAssetsFile(
        string path,
        AssetsSource source,
        Dictionary<string, ResolvedPackage> closure,
        List<string> folders,
        List<UnanalyzableEntry> unanalyzable,
        string srcDir,
        List<PackageIdentity> projectPackages,
        Dictionary<string, List<string>> edges)
    {
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var root = doc.RootElement;

            if (root.TryGetProperty("packageFolders", out var pf))
            {
                foreach (var folder in pf.EnumerateObject()) folders.Add(folder.Name);
            }

            if (root.TryGetProperty("libraries", out var libraries))
            {
                ReadLibraries(libraries, source, closure, projectPackages);
            }

            ReadTargetsForEdges(root, edges);
            return true;
        }
        catch (Exception ex)
        {
            unanalyzable.Add(new UnanalyzableEntry(
                ProjectDiscovery.RelativePath(srcDir, path), UnanalyzableEntry.KindAssets, $"unparseable assets file: {UnanalyzableEntry.Describe(ex)}"));
            return false;
        }
    }

    /// One `libraries` entry per "PackageId/Version" key. Split out of
    /// ReadAssetsFile so the two nested loops don't compound its complexity.
    private static void ReadLibraries(JsonElement libraries, AssetsSource source, Dictionary<string, ResolvedPackage> closure, List<PackageIdentity> projectPackages)
    {
        foreach (var lib in libraries.EnumerateObject())
        {
            // Key is "PackageId/Version"
            var slash = lib.Name.IndexOf('/');
            if (slash <= 0) continue;
            var id = lib.Name[..slash];
            var version = lib.Name[(slash + 1)..];
            if (lib.Value.TryGetProperty("type", out var type) && type.GetString() != "package") continue;

            // `lib/` first (runtime assemblies), then `ref/` — a package
            // that ships only reference assemblies (targeting packs,
            // some System.* packages) still exposes public types to
            // source code, so its namespaces are DLL-readable too.
            var libDlls = new List<string>();
            var refDlls = new List<string>();
            var filesKnown = lib.Value.TryGetProperty("files", out var files);
            if (filesKnown)
            {
                foreach (var f in files.EnumerateArray())
                {
                    var s = f.GetString();
                    if (s is null || !s.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) continue;
                    if (s.StartsWith("lib/", StringComparison.OrdinalIgnoreCase)) libDlls.Add(s);
                    else if (s.StartsWith("ref/", StringComparison.OrdinalIgnoreCase)) refDlls.Add(s);
                }
            }
            libDlls.AddRange(refDlls);
            AddPackage(
                closure,
                projectPackages,
                new ResolvedPackage(id, version, libDlls, filesKnown) { Hashes = HashesOf(lib.Value, source, FieldSha512) });
        }
    }

    /// Dependency edges live in `targets`, not `libraries` — a separate
    /// section keyed the same way ("PackageId/Version"), one map per TFM. A
    /// multi-targeted project's TFMs are merged (deduped), the same
    /// simplification `closure` (in <see cref="ReadAssetsFile"/>) already
    /// makes across projects. Split out from ReadAssetsFile to keep that
    /// method's own complexity from compounding with this one.
    private static void ReadTargetsForEdges(JsonElement root, Dictionary<string, List<string>> edges)
    {
        if (!root.TryGetProperty("targets", out var targets)) return;
        foreach (var target in targets.EnumerateObject())
        {
            foreach (var lib in target.Value.EnumerateObject())
            {
                if (lib.Name.IndexOf('/') <= 0) continue;
                if (lib.Value.TryGetProperty("type", out var type) && type.GetString() != "package") continue;
                if (lib.Value.TryGetProperty("dependencies", out var deps)) AddDependencyEdges(edges, lib.Name, deps);
            }
        }
    }

    /// Merges one package's dependency-id list into `edges[fromKey]`, deduped
    /// case-insensitively. A dependency id with no matching `Closure` entry
    /// (e.g. a TFM-conditional edge that didn't resolve) is left as-is: the
    /// document reports it and the consumer decides what an unresolved edge
    /// means.
    private static void AddDependencyEdges(Dictionary<string, List<string>> edges, string fromKey, JsonElement dependenciesElement)
    {
        if (dependenciesElement.ValueKind != JsonValueKind.Object) return;
        var list = edges.TryGetValue(fromKey, out var existing) ? existing : edges[fromKey] = [];
        foreach (var dep in dependenciesElement.EnumerateObject())
        {
            if (!list.Contains(dep.Name, StringComparer.OrdinalIgnoreCase)) list.Add(dep.Name);
        }
    }

    /// The merged closure keeps the first sighting of an id+version (the
    /// artefacts agree on a resolved package's files); the per-project list
    /// records every identity this project resolved, once each.
    private static void AddPackage(Dictionary<string, ResolvedPackage> closure, List<PackageIdentity> projectPackages, ResolvedPackage package)
    {
        if (!closure.TryAdd(package.Key, package)) MergeHashes(closure[package.Key].Hashes, package.Hashes);
        if (!projectPackages.Any(p => p.Id.Equals(package.Id, StringComparison.OrdinalIgnoreCase) && p.Version == package.Version))
        {
            projectPackages.Add(package.Identity);
        }
    }

    /// The one place a second sighting of an already-recorded package still
    /// contributes: a monorepo where one project is restored (assets, `sha512`)
    /// and another is not (lock file, `contentHash`) states BOTH about the same
    /// id+version, and first-sighting-wins would silently drop whichever came
    /// second. Deduped on the whole entry, so two artefacts that agree collapse
    /// and two that DISAGREE are both reported — a conflict is a fact, and
    /// picking a winner here would hide it.
    internal static void MergeHashes(List<PackageHashFacts> into, IEnumerable<PackageHashFacts> incoming)
    {
        foreach (var hash in incoming)
        {
            if (!into.Contains(hash)) into.Add(hash);
        }
    }

    /// Reads one artefact entry's hash field, verbatim. A missing, non-string or
    /// empty value yields nothing at all rather than an empty-string hash: the
    /// artefact stated no hash for this package, which the empty list says.
    private static List<PackageHashFacts> HashesOf(JsonElement entry, AssetsSource source, string field)
    {
        if (!entry.TryGetProperty(field, out var value) || value.ValueKind != JsonValueKind.String) return [];
        var text = value.GetString();
        return string.IsNullOrWhiteSpace(text) ? [] : [new PackageHashFacts(source.Kind, source.File, field, text)];
    }

    private static bool ReadLockFile(
        string path,
        AssetsSource source,
        Dictionary<string, ResolvedPackage> closure,
        List<UnanalyzableEntry> unanalyzable,
        string srcDir,
        List<PackageIdentity> projectPackages,
        Dictionary<string, List<string>> edges)
    {
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            if (!doc.RootElement.TryGetProperty("dependencies", out var deps)) return true;
            foreach (var tfm in deps.EnumerateObject())
            {
                foreach (var pkg in tfm.Value.EnumerateObject())
                {
                    var type = pkg.Value.TryGetProperty("type", out var t) ? t.GetString() : null;
                    if (type == "Project") continue;
                    var version = pkg.Value.TryGetProperty("resolved", out var v) ? v.GetString() ?? "" : "";
                    // A lock file names the closure but never enumerates package
                    // files: FilesKnown = false, so downstream must not read the
                    // empty DLL list as "this package ships no assemblies".
                    var package = new ResolvedPackage(pkg.Name, version, [], FilesKnown: false)
                    {
                        Hashes = HashesOf(pkg.Value, source, FieldContentHash),
                    };
                    AddPackage(closure, projectPackages, package);
                    if (pkg.Value.TryGetProperty("dependencies", out var pkgDeps)) AddDependencyEdges(edges, package.Key, pkgDeps);
                }
            }
            return true;
        }
        catch (Exception ex)
        {
            unanalyzable.Add(new UnanalyzableEntry(
                ProjectDiscovery.RelativePath(srcDir, path), UnanalyzableEntry.KindAssets, $"unparseable lock file: {UnanalyzableEntry.Describe(ex)}"));
            return false;
        }
    }
}
