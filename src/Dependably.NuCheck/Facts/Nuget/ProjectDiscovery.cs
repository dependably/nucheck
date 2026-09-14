using System.Xml.Linq;

namespace Dependably.NuCheck.Facts.Nuget;

public sealed record PackageDeclaration(string PackageId, string File, int Line);

/// <param name="TestMarker">
/// What declares this a test project — the explicit
/// <c>&lt;IsTestProject&gt;true&lt;/IsTestProject&gt;</c> property (reported as
/// <c>"&lt;IsTestProject&gt;"</c>) or the id of the test framework / test SDK
/// package it references — the two ways a .NET project actually declares itself
/// one. Null when it is not a test project. The FACT is recorded; what a test
/// project's references mean for a build gate is the consumer's call.
/// </param>
public sealed record ProjectInfo(
    string CsprojPath,
    List<PackageDeclaration> DirectReferences,
    string? TestMarker)
{
    public bool IsTestProject => TestMarker is not null;
}

/// <summary>
/// Finds .csproj files and their direct PackageReference declarations,
/// including Central Package Management (Directory.Packages.props).
/// XML is parsed with line info so a consumer can point at the declaration.
/// </summary>
public static class ProjectDiscovery
{
    public const string IsTestProjectMarker = "<IsTestProject>";
    public const string SymlinkedDirectoryReason = "symlinked directory not followed";

    private static readonly HashSet<string> SkipDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        "bin", "obj", "node_modules", ".git", ".vs",
    };

    /// Referencing any of these is how a .NET project says "I am a test project".
    /// Matched case-insensitively, as a whole id or as a `<prefix>.` prefix, so
    /// e.g. `xunit.runner.visualstudio` and `NUnit3TestAdapter` both count.
    private static readonly string[] TestPackageMarkers =
    [
        "Microsoft.NET.Test.Sdk", "xunit", "NUnit", "MSTest", "TUnit",
        "Machine.Specifications", "Microsoft.AspNetCore.Mvc.Testing",
    ];

    public static (List<ProjectInfo> Projects, List<PackageDeclaration> CpmDeclarations)
        Discover(string srcDir, List<UnanalyzableEntry> unanalyzable)
    {
        var projects = new List<ProjectInfo>();
        var cpm = new List<PackageDeclaration>();

        foreach (var file in EnumerateFiles(srcDir, unanalyzable))
        {
            var name = Path.GetFileName(file);
            var isCsproj = name.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase);
            var isCpmProps = name.Equals("Directory.Packages.props", StringComparison.OrdinalIgnoreCase);
            if (!isCsproj && !isCpmProps) continue;

            // Load once and read everything off the same document: the project's
            // declarations AND whether it is a test project. Parsing the file a
            // second time to answer the second question would mean a second failure
            // path to handle for a failure already reported here.
            var doc = LoadProjectFile(file, srcDir, unanalyzable);
            if (doc is null) continue;

            if (isCsproj)
            {
                var refs = DeclarationsIn(doc, file, srcDir, "PackageReference");
                projects.Add(new ProjectInfo(file, refs, TestMarker(doc, refs)));
            }
            else
            {
                cpm.AddRange(DeclarationsIn(doc, file, srcDir, "PackageVersion"));
            }
        }

        projects.Sort((a, b) => string.CompareOrdinal(a.CsprojPath, b.CsprojPath));
        cpm.Sort((a, b) =>
        {
            var byFile = string.CompareOrdinal(a.File, b.File);
            return byFile != 0 ? byFile : a.Line.CompareTo(b.Line);
        });
        return (projects, cpm);
    }

    /// <param name="unanalyzable">
    /// A directory the walk could not list is reported here (kind
    /// <c>directory</c>) rather than silently dropped: every file inside it is
    /// then in no list at all, and a consumer must know the search was incomplete.
    /// A SYMLINKED directory is never followed — a link back into the tree
    /// (`a/loop -> a`) would enumerate the same files over and over until the
    /// path length overflowed, and a link out of it (`vendor -> /usr/share`) would
    /// scan code that is not the target — and is reported the same way, with
    /// <see cref="SymlinkedDirectoryReason"/>.
    /// </param>
    public static IEnumerable<string> EnumerateFiles(string root, List<UnanalyzableEntry> unanalyzable)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            var dir = pending.Pop();
            string[] entries;
            try
            {
                entries = Directory.GetFileSystemEntries(dir);
            }
            catch (Exception ex)
            {
                unanalyzable.Add(new UnanalyzableEntry(
                    RelativePath(root, dir), UnanalyzableEntry.KindDirectory, $"unlistable directory: {UnanalyzableEntry.Describe(ex)}"));
                continue;
            }
            foreach (var entry in entries)
            {
                if (!Directory.Exists(entry))
                {
                    yield return entry;
                    continue;
                }
                var dirName = Path.GetFileName(entry);
                if (SkipDirs.Contains(dirName) || dirName.StartsWith('.')) continue;
                if (IsSymbolicLink(entry))
                {
                    unanalyzable.Add(new UnanalyzableEntry(
                        RelativePath(root, entry), UnanalyzableEntry.KindDirectory, SymlinkedDirectoryReason));
                    continue;
                }
                pending.Push(entry);
            }
        }
    }

    private static bool IsSymbolicLink(string path)
    {
        try
        {
            return new DirectoryInfo(path).LinkTarget is not null;
        }
        catch
        {
            // If the link cannot even be inspected, treat it as one: not following
            // is the safe direction (the entry is reported, never silently walked).
            return true;
        }
    }

    /// The one place a project/props file is read from disk, and so the one place
    /// a malformed one is reported. Returns null when it could not be parsed.
    private static XDocument? LoadProjectFile(string file, string srcDir, List<UnanalyzableEntry> unanalyzable)
    {
        try
        {
            return XDocument.Load(file, LoadOptions.SetLineInfo);
        }
        catch (Exception ex)
        {
            unanalyzable.Add(new UnanalyzableEntry(
                RelativePath(srcDir, file), UnanalyzableEntry.KindFile, $"unparseable project file: {UnanalyzableEntry.Describe(ex)}"));
            return null;
        }
    }

    /// Explicit `<IsTestProject>` wins (it is the property the .NET SDK itself
    /// honours, and lets a project opt out); otherwise infer from a test-framework
    /// reference, naming the reference that matched. Deliberately does NOT guess
    /// from the path — a directory called `tests/` proves nothing, and a project
    /// that ships from a folder named that way would be wrongly excused from a
    /// consumer's build gate.
    private static string? TestMarker(XDocument doc, List<PackageDeclaration> refs)
    {
        var declared = doc.Descendants()
            .FirstOrDefault(e => e.Name.LocalName.Equals("IsTestProject", StringComparison.OrdinalIgnoreCase));
        if (declared is not null && bool.TryParse(declared.Value.Trim(), out var isTest))
        {
            return isTest ? IsTestProjectMarker : null;
        }

        var match = refs.FirstOrDefault(r => TestPackageMarkers.Any(marker =>
            r.PackageId.Equals(marker, StringComparison.OrdinalIgnoreCase) ||
            r.PackageId.StartsWith(marker + ".", StringComparison.OrdinalIgnoreCase)));
        return match?.PackageId;
    }

    private static List<PackageDeclaration> DeclarationsIn(
        XDocument doc, string file, string srcDir, string elementName)
    {
        var result = new List<PackageDeclaration>();
        foreach (var element in doc.Descendants())
        {
            if (!element.Name.LocalName.Equals(elementName, StringComparison.OrdinalIgnoreCase)) continue;
            var id = element.Attribute("Include")?.Value ?? element.Attribute("Update")?.Value;
            if (string.IsNullOrWhiteSpace(id)) continue;
            var line = (element as System.Xml.IXmlLineInfo)?.LineNumber ?? 1;
            result.Add(new PackageDeclaration(id, RelativePath(srcDir, file), line));
        }
        return result;
    }

    /// A path known to be under `root`, relative to it with POSIX separators.
    public static string RelativePath(string root, string path) =>
        Path.GetRelativePath(root, path).Replace('\\', '/');

    /// A path that may lie outside `root` (a package-cache assembly or nuspec):
    /// relative with POSIX separators when it is under the root, else the
    /// absolute path with POSIX separators — never a `../..` chain.
    public static string DisplayPath(string root, string path)
    {
        var rel = Path.GetRelativePath(root, path);
        var outside = Path.IsPathRooted(rel)
            || rel == ".."
            || rel.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal);
        return (outside ? Path.GetFullPath(path) : rel).Replace('\\', '/');
    }
}
