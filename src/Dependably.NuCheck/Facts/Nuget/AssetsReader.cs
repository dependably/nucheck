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
    bool FilesKnown);

/// <param name="File">Path of the artefact, relative to the scanned tree.</param>
/// <param name="Kind"><c>assets</c> (obj/project.assets.json) or <c>lock</c> (packages.lock.json).</param>
public sealed record AssetsSource(string File, string Kind)
{
    public const string KindAssets = "assets";
    public const string KindLock = "lock";
}

public sealed record AssetsInfo(
    Dictionary<string, ResolvedPackage> Closure, // key: package id (case-insensitive), merged across ALL projects
    List<string> PackageFolders,
    /// Per-project resolved package ids (key: that project's absolute .csproj
    /// path; values case-insensitive), i.e. the full resolved closure from
    /// THAT project's own assets/lock file — unlike <see cref="Closure"/>
    /// above (which merges every project's closure into one dict and loses
    /// the per-project association). A project whose artefact could not be
    /// parsed has NO entry here: an unparseable file is not an empty closure.
    Dictionary<string, HashSet<string>> PackageIdsByProject,
    /// Dependency edges among the closure: package id (case-insensitive) ->
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
    public static AssetsInfo ReadAll(string srcDir, IEnumerable<ProjectInfo> projects, List<UnanalyzableEntry> unanalyzable)
    {
        var closure = new Dictionary<string, ResolvedPackage>(StringComparer.OrdinalIgnoreCase);
        var folders = new List<string>();
        var packageIdsByProject = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var edges = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var sources = new Dictionary<string, AssetsSource>(StringComparer.OrdinalIgnoreCase);

        foreach (var project in projects)
        {
            var projectIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var assetsPath = Path.Combine(Path.GetDirectoryName(project.CsprojPath)!, "obj", "project.assets.json");
            if (File.Exists(assetsPath))
            {
                sources[project.CsprojPath] = new AssetsSource(ProjectDiscovery.RelativePath(srcDir, assetsPath), AssetsSource.KindAssets);
                if (ReadAssetsFile(assetsPath, closure, folders, unanalyzable, srcDir, projectIds, edges))
                {
                    packageIdsByProject[project.CsprojPath] = projectIds;
                }
                continue;
            }
            var lockPath = Path.Combine(Path.GetDirectoryName(project.CsprojPath)!, "packages.lock.json");
            if (File.Exists(lockPath))
            {
                sources[project.CsprojPath] = new AssetsSource(ProjectDiscovery.RelativePath(srcDir, lockPath), AssetsSource.KindLock);
                if (ReadLockFile(lockPath, closure, unanalyzable, srcDir, projectIds, edges))
                {
                    packageIdsByProject[project.CsprojPath] = projectIds;
                }
            }
        }

        return new AssetsInfo(closure, folders.Distinct().ToList(), packageIdsByProject, edges, sources);
    }

    private static bool ReadAssetsFile(
        string path,
        Dictionary<string, ResolvedPackage> closure,
        List<string> folders,
        List<UnanalyzableEntry> unanalyzable,
        string srcDir,
        HashSet<string> projectIds,
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
                ReadLibraries(libraries, closure, projectIds);
            }

            ReadTargetsForEdges(root, edges);
            return true;
        }
        catch (Exception ex)
        {
            unanalyzable.Add(new UnanalyzableEntry(
                ProjectDiscovery.RelativePath(srcDir, path), UnanalyzableEntry.KindAssets, $"unparseable assets file: {ex.Message}"));
            return false;
        }
    }

    /// One `libraries` entry per "PackageId/Version" key. Split out of
    /// ReadAssetsFile so the two nested loops don't compound its complexity.
    private static void ReadLibraries(JsonElement libraries, Dictionary<string, ResolvedPackage> closure, HashSet<string> projectIds)
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
            closure.TryAdd(id, new ResolvedPackage(id, version, libDlls, filesKnown));
            projectIds.Add(id);
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
                var slash = lib.Name.IndexOf('/');
                if (slash <= 0) continue;
                var id = lib.Name[..slash];
                if (lib.Value.TryGetProperty("type", out var type) && type.GetString() != "package") continue;
                if (lib.Value.TryGetProperty("dependencies", out var deps)) AddDependencyEdges(edges, id, deps);
            }
        }
    }

    /// Merges one package's dependency-id list into `edges[fromId]`, deduped
    /// case-insensitively. A dependency id with no matching `Closure` entry
    /// (e.g. a TFM-conditional edge that didn't resolve) is left as-is: the
    /// document reports it and the consumer decides what an unresolved edge
    /// means.
    private static void AddDependencyEdges(Dictionary<string, List<string>> edges, string fromId, JsonElement dependenciesElement)
    {
        if (dependenciesElement.ValueKind != JsonValueKind.Object) return;
        var list = edges.TryGetValue(fromId, out var existing) ? existing : edges[fromId] = [];
        foreach (var dep in dependenciesElement.EnumerateObject())
        {
            if (!list.Contains(dep.Name, StringComparer.OrdinalIgnoreCase)) list.Add(dep.Name);
        }
    }

    private static bool ReadLockFile(
        string path,
        Dictionary<string, ResolvedPackage> closure,
        List<UnanalyzableEntry> unanalyzable,
        string srcDir,
        HashSet<string> projectIds,
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
                    closure.TryAdd(pkg.Name, new ResolvedPackage(pkg.Name, version, [], FilesKnown: false));
                    projectIds.Add(pkg.Name);
                    if (pkg.Value.TryGetProperty("dependencies", out var pkgDeps)) AddDependencyEdges(edges, pkg.Name, pkgDeps);
                }
            }
            return true;
        }
        catch (Exception ex)
        {
            unanalyzable.Add(new UnanalyzableEntry(
                ProjectDiscovery.RelativePath(srcDir, path), UnanalyzableEntry.KindAssets, $"unparseable lock file: {ex.Message}"));
            return false;
        }
    }
}
