using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;

namespace Dependably.NuCheck.Facts.Nuget;

/// How a package's namespace set was derived — which decides what the document
/// may say about it at all.
public enum NamespaceMapping
{
    /// Read from the package's own assemblies. The namespace set is authoritative
    /// and is published as <c>namespaces</c>.
    DllVerified,

    /// The package demonstrably ships no assemblies (its file list is known and
    /// contains no lib/ or ref/ DLL) — e.g. an analyzer-only or MSBuild-targets
    /// package. It exposes no types, so C# source *cannot* reference it: the
    /// document publishes an EMPTY <c>namespaces</c> list, a provable fact.
    NoLibAssemblies,

    /// Nothing could be read. The convention "package id = namespace prefix"
    /// (`Newtonsoft.Json` → `Newtonsoft.Json.*`) holds for most packages but is
    /// wrong for a large minority (`Microsoft.CodeAnalysis.Workspaces.MSBuild` →
    /// `Microsoft.CodeAnalysis.MSBuild`, the whole `AWSSDK.*` → `Amazon.*` family,
    /// `Serilog.Sinks.Console` → `Serilog.Sinks.SystemConsole`), so the document
    /// OMITS <c>namespaces</c> for such a package rather than publishing a guess:
    /// a consumer searching for a namespace the package never had would find
    /// nothing, indistinguishable from genuine non-use. The guessed root still
    /// feeds <c>qualifiedRoots</c> (so qualified identifiers under it are kept for
    /// the consumer to match), which is the one place the convention is useful.
    IdConvention,
}

/// <param name="AssembliesRead">How many of the package's assemblies were successfully read for <see cref="Namespaces"/>.</param>
public sealed record PackageNamespaces(
    ResolvedPackage Package,
    HashSet<string> Namespaces,
    NamespaceMapping Mapping,
    int AssembliesRead)
{
    /// Namespaces came from real assembly metadata rather than a guess.
    public bool DllBacked => Mapping == NamespaceMapping.DllVerified;
}

/// <summary>
/// Maps each resolved package (id+version) to the namespaces of its public
/// types by reading the package's lib/ref DLLs from the global-packages folder
/// with System.Reflection.Metadata (no assembly loading). Falls back to the
/// package id as a namespace prefix — correct by convention for most packages,
/// but the resulting <see cref="NamespaceMapping.IdConvention"/> mapping is
/// recorded so the document can withhold the guess.
/// </summary>
public static class NamespaceMap
{
    public const string MissingListedAssemblyReason = "listed in assets but not present in package folder";

    /// <returns>Keyed by <see cref="ResolvedPackage.Key"/> (case-insensitive).</returns>
    public static Dictionary<string, PackageNamespaces> Build(
        IEnumerable<ResolvedPackage> packages,
        IReadOnlyList<string> packageFolders,
        string srcDir,
        List<UnanalyzableEntry> unanalyzable)
    {
        var map = new Dictionary<string, PackageNamespaces>(StringComparer.OrdinalIgnoreCase);
        foreach (var package in packages)
        {
            var namespaces = new HashSet<string>(StringComparer.Ordinal);
            var assembliesRead = 0;

            if (package.LibDllRelPaths.Count > 0)
            {
                assembliesRead = ReadFromPackageFolders(packageFolders, package, srcDir, namespaces, unanalyzable);
            }

            NamespaceMapping mapping;
            if (assembliesRead > 0)
            {
                mapping = NamespaceMapping.DllVerified;
            }
            else if (package.FilesKnown && package.LibDllRelPaths.Count == 0)
            {
                // The assets file enumerated this package's files and none of them
                // is an assembly: it exposes no types at all (analyzer/targets-only
                // package). Leave `namespaces` empty — it can never match a `using`,
                // and that emptiness is provable rather than guessed.
                mapping = NamespaceMapping.NoLibAssemblies;
            }
            else
            {
                // Convention: Newtonsoft.Json → Newtonsoft.Json.* — namespaces are
                // case-sensitive while NuGet ids are not, and the artefact's
                // canonical casing is what the closure carries.
                namespaces.Add(package.Id);
                mapping = NamespaceMapping.IdConvention;
            }

            map[package.Key] = new PackageNamespaces(package, namespaces, mapping, assembliesRead);
        }
        return map;
    }

    /// The first package folder that holds the package wins (the same
    /// `folder/id-lowercase/version` layout NuGet itself resolves through);
    /// returns how many assemblies were read from it. A DLL the artefact lists
    /// but the folder lacks is reported, not skipped: a namespace list built from
    /// the assemblies that WERE present would otherwise be published as complete.
    private static int ReadFromPackageFolders(
        IReadOnlyList<string> packageFolders,
        ResolvedPackage resolved,
        string srcDir,
        HashSet<string> namespaces,
        List<UnanalyzableEntry> unanalyzable)
    {
        foreach (var folder in packageFolders)
        {
            var pkgRoot = Path.Combine(folder, resolved.Id.ToLowerInvariant(), resolved.Version);
            if (!Directory.Exists(pkgRoot)) continue;
            var read = 0;
            foreach (var rel in resolved.LibDllRelPaths)
            {
                var dllPath = Path.Combine(pkgRoot, rel.Replace('/', Path.DirectorySeparatorChar));
                var display = ProjectDiscovery.DisplayPath(srcDir, dllPath);
                if (!File.Exists(dllPath))
                {
                    unanalyzable.Add(new UnanalyzableEntry(display, UnanalyzableEntry.KindAssembly, MissingListedAssemblyReason));
                    continue;
                }
                try
                {
                    CollectNamespaces(dllPath, namespaces);
                    read++;
                }
                catch (Exception ex)
                {
                    unanalyzable.Add(new UnanalyzableEntry(
                        display, UnanalyzableEntry.KindAssembly, $"could not read metadata: {UnanalyzableEntry.Describe(ex)}"));
                }
            }
            if (read > 0) return read;
        }
        return 0;
    }

    private static void CollectNamespaces(string dllPath, HashSet<string> namespaces)
    {
        using var stream = File.OpenRead(dllPath);
        using var pe = new PEReader(stream);
        if (!pe.HasMetadata) return;
        var reader = pe.GetMetadataReader();
        foreach (var handle in reader.TypeDefinitions)
        {
            var type = reader.GetTypeDefinition(handle);
            var visibility = type.Attributes & System.Reflection.TypeAttributes.VisibilityMask;
            if (visibility != System.Reflection.TypeAttributes.Public) continue;
            var ns = reader.GetString(type.Namespace);
            if (!string.IsNullOrEmpty(ns)) namespaces.Add(ns);
        }
    }
}
