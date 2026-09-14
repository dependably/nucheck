using System.Text.Json;

namespace Dependably.NuCheck.Facts.Nuget;

/// <param name="DepsJson">The `*.deps.json` this was read from, relative to the scanned tree.</param>
/// <param name="Packages">
/// `id`+`version` of every package that contributes a runtime assembly to this
/// output — i.e. whose DLLs are copied next to the binary and so are present at
/// run time regardless of what the source references.
/// </param>
public sealed record RuntimeOutput(string DepsJson, List<PackageIdentity> Packages);

/// <summary>
/// Reads a project's built output `*.deps.json` files to learn which packages
/// actually land in that output.
///
/// This is the fact a consumer needs for the missing half of a "nothing
/// references it" conclusion: "no source code references this package" says
/// nothing about whether the package is sitting on disk next to the binary,
/// loadable by reflection, a DI container, a plugin host, or an MSBuild task.
/// The distinction is not hypothetical: it is exactly the shape of
/// CVE-2025-26646 / Microsoft.Build.Tasks.Core, which no first-party C# file
/// references yet which is copied into the build output by a transitive Roslyn
/// dependency.
///
/// `runtime` assets are read (not `compile`): a compile-only reference is not
/// present at run time. Whether an output belongs to a test project — and so
/// whether "on disk" means "in the product" — is the project's own
/// <see cref="ProjectInfo.IsTestProject"/> fact; this reader records what each
/// file says and leaves that join to the consumer.
/// </summary>
public static class DepsReader
{
    /// Null when the project has no `bin/`, no `*.deps.json` under it, or only
    /// deps files that could not be parsed (each of those is in
    /// <paramref name="unanalyzable"/>): nothing is then known about what ships,
    /// and that must not be reported as "ships nothing".
    public static List<RuntimeOutput>? Read(string srcDir, ProjectInfo project, List<UnanalyzableEntry> unanalyzable)
    {
        var binDir = Path.Combine(Path.GetDirectoryName(project.CsprojPath)!, "bin");
        if (!Directory.Exists(binDir)) return null;

        string[] depsFiles;
        try
        {
            depsFiles = Directory.GetFiles(binDir, "*.deps.json", SearchOption.AllDirectories);
        }
        catch (Exception ex)
        {
            unanalyzable.Add(new UnanalyzableEntry(
                ProjectDiscovery.RelativePath(srcDir, binDir), UnanalyzableEntry.KindDirectory, $"unlistable directory: {UnanalyzableEntry.Describe(ex)}"));
            return null;
        }
        if (depsFiles.Length == 0) return null;
        Array.Sort(depsFiles, StringComparer.Ordinal);

        var outputs = new List<RuntimeOutput>();
        foreach (var depsFile in depsFiles)
        {
            var packages = ReadDepsFile(depsFile, srcDir, unanalyzable);
            if (packages is null) continue;
            outputs.Add(new RuntimeOutput(ProjectDiscovery.RelativePath(srcDir, depsFile), packages));
        }
        // Every deps file unparseable: the output exists but says nothing readable.
        // An empty list here would read as "built, ships nothing" — omit instead.
        return outputs.Count > 0 ? outputs : null;
    }

    private static List<PackageIdentity>? ReadDepsFile(string path, string srcDir, List<UnanalyzableEntry> unanalyzable)
    {
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var root = doc.RootElement;

            var packageTyped = PackageTypedLibraries(root);
            var shipped = new List<PackageIdentity>();
            if (root.TryGetProperty("targets", out var targets))
            {
                foreach (var target in targets.EnumerateObject())
                {
                    CollectShipped(target.Value, packageTyped, shipped);
                }
            }

            shipped.Sort((a, b) =>
            {
                var byId = string.Compare(a.Id, b.Id, StringComparison.OrdinalIgnoreCase);
                return byId != 0 ? byId : string.CompareOrdinal(a.Version, b.Version);
            });
            return shipped;
        }
        catch (Exception ex)
        {
            unanalyzable.Add(new UnanalyzableEntry(
                ProjectDiscovery.RelativePath(srcDir, path), UnanalyzableEntry.KindDeps, $"unparseable deps file: {UnanalyzableEntry.Describe(ex)}"));
            return null;
        }
    }

    /// Only NuGet packages count. A `project` entry is first-party code, and
    /// the app's own assembly always "ships" — neither is a package a
    /// vulnerability can be reported against.
    private static HashSet<string> PackageTypedLibraries(JsonElement root)
    {
        var packageTyped = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!root.TryGetProperty("libraries", out var libraries)) return packageTyped;
        foreach (var lib in libraries.EnumerateObject())
        {
            if (lib.Value.TryGetProperty("type", out var type) && type.GetString() == "package")
            {
                packageTyped.Add(lib.Name);
            }
        }
        return packageTyped;
    }

    /// One `targets.<tfm>` map: every package-typed "Id/Version" entry with a
    /// non-empty `runtime` section lands next to the app.
    private static void CollectShipped(JsonElement target, HashSet<string> packageTyped, List<PackageIdentity> shipped)
    {
        foreach (var lib in target.EnumerateObject())
        {
            if (!packageTyped.Contains(lib.Name)) continue;

            var slash = lib.Name.IndexOf('/');
            if (slash <= 0) continue;
            var id = lib.Name[..slash];
            var version = lib.Name[(slash + 1)..];

            if (!ContributesRuntimeAssembly(lib.Value)) continue;
            if (shipped.Any(p => p.Id.Equals(id, StringComparison.OrdinalIgnoreCase) && p.Version == version)) continue;
            shipped.Add(new PackageIdentity(id, version));
        }
    }

    /// A `runtime` section with at least one assembly means the package's DLLs
    /// land next to the app. An empty or absent one means it contributed
    /// nothing loadable (compile-only, analyzer, targets).
    private static bool ContributesRuntimeAssembly(JsonElement lib) =>
        lib.TryGetProperty("runtime", out var runtime)
        && runtime.ValueKind == JsonValueKind.Object
        && runtime.EnumerateObject().Any();
}
