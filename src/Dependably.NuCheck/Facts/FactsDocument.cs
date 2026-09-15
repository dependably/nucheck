using System.Text.Json.Serialization;

namespace Dependably.NuCheck.Facts;

/// <summary>
/// The <c>--facts</c> document: .NET language and packaging FACTS about a source
/// tree, published as data for another tool. Same envelope identity as the
/// findings document (<c>tool</c>/<c>toolVersion</c>/<c>schemaVersion</c>/
/// <c>target</c>/<c>summary</c>) with <c>findings</c> replaced by the fact
/// sections and an explicit <c>documentType</c> discriminator, following
/// pycheck's <c>--imports</c> precedent.
///
/// <para><b>Facts are not findings, and nothing here is a verdict.</b> This
/// document says which namespaces a file imports, which assemblies a package
/// ships, which members an output assembly references — never whether a package
/// is reachable, whether it ships, what confidence to attach, or which package a
/// <c>using</c> belongs to. Those are the consumer's conclusions.</para>
///
/// <para><b>Null discipline.</b> A property annotated <c>WhenWritingNull</c> is
/// OMITTED when the tool could not determine it — "cannot tell", never "none".
/// A property written as an explicit <c>null</c> states a fact of absence (a
/// project with no test marker, a <c>using</c> with no alias). A present-and-empty
/// list is likewise a fact: "enumerated, found none".</para>
///
/// <para><b>The <c>schemaVersion</c> contract</b> (published in README.md, because a
/// contract only a consumer can read is a policy the consumer invented): a newer
/// MINOR is ADDITIVE — keys were added, every key a previous 1.x document carried
/// still exists and still means the same thing, so a consumer written against an
/// older minor proceeds unchanged. A newer MAJOR means a key was RENAMED, REMOVED,
/// or had its meaning changed, and a consumer written against the older major must
/// refuse the document. The version describes the document's SHAPE and nothing
/// else.</para>
///
/// <para><b>Why <see cref="Capabilities"/> exists beside it.</b> A shape version
/// cannot express a change in how an EXISTING field is filled: nucheck 2.3.0's IL
/// normalizations added no key — they changed which spellings appear inside
/// <c>il[].references[]</c> — so a 2.2.0 and a 2.3.0 build emit the same schema and
/// a consumer that needs the normalized spellings cannot tell them apart from the
/// document. Answering that with a version bump would also force every consumer to
/// learn, out of band, which minor meant which behaviour. The document therefore
/// NAMES its behaviours, which is the same reasoning that makes probing a tool by
/// running it better than parsing its <c>--version</c>: a fork, a dev build or a
/// backport can state truthfully what it does.</para>
/// </summary>
public sealed record FactsDocument
{
    public const string ToolName = "nucheck";

    /// <summary>
    /// The facts document's own schema version — independent of the findings
    /// document's (they are separate documents with separate shapes) and of the
    /// tool version. 1.0 → 1.1: <c>capabilities</c> was ADDED; nothing was
    /// renamed, removed or redefined.
    /// </summary>
    public const string SchemaVersion = "1.1";
    public const string DocumentTypeName = "facts";

    [JsonPropertyName("tool")] public string Tool { get; init; } = ToolName;
    [JsonPropertyName("toolVersion")] public string ToolVersion { get; init; } = "";
    [JsonPropertyName("schemaVersion")] public string Schema { get; init; } = SchemaVersion;
    [JsonPropertyName("documentType")] public string DocumentType { get; init; } = DocumentTypeName;
    /// <summary>
    /// The behaviours THIS BUILD has, named rather than versioned — see
    /// <see cref="FactsCapabilities"/> for what belongs here and what does not.
    /// Written always (an emitting build always knows its own), so a consumer
    /// negotiates from the document it has already parsed instead of launching the
    /// tool a second time to parse a version string. An ABSENT <c>capabilities</c>
    /// is a schemaVersion 1.0 document, i.e. a build that predates the field: that
    /// is "cannot tell", never "declares none" — the same distinction
    /// <c>WhenWritingNull</c> draws everywhere else in this document.
    /// </summary>
    [JsonPropertyName("capabilities")] public List<string> Capabilities { get; init; } = [.. FactsCapabilities.All];
    /// <summary>The target path exactly as given on the command line; every path inside the document is relative to it.</summary>
    [JsonPropertyName("target")] public string Target { get; init; } = "";
    [JsonPropertyName("summary")] public FactsSummary Summary { get; init; } = new();
    [JsonPropertyName("projects")] public List<ProjectFacts> Projects { get; init; } = [];
    [JsonPropertyName("centralPackageVersions")] public List<DeclarationFacts> CentralPackageVersions { get; init; } = [];
    [JsonPropertyName("packages")] public List<PackageFacts> Packages { get; init; } = [];
    [JsonPropertyName("packageFolders")] public List<PackageFolderFacts> PackageFolders { get; init; } = [];
    [JsonPropertyName("source")] public SourceFacts Source { get; init; } = new();
    [JsonPropertyName("il")] public List<IlFacts> Il { get; init; } = [];
    /// <summary>
    /// Every path the scan could not read, with a kind and a reason. LOAD-BEARING:
    /// "nothing references X" is only evidence when the search actually ran over
    /// every file, and a consumer must weaken every negative it draws from a
    /// document whose <c>unanalyzable</c> is non-empty.
    /// </summary>
    [JsonPropertyName("unanalyzable")] public List<UnanalyzableEntry> Unanalyzable { get; init; } = [];
}

/// <summary>
/// The capability ids the facts document declares. A capability names a
/// BEHAVIOUR a consumer would otherwise have to infer from the tool version —
/// i.e. one the document's own shape cannot reveal. A newly ADDED FIELD is not a
/// capability: <c>schemaVersion</c>'s minor already announces it and the key is
/// either there or it is not. Keeping that line means this list stays a short
/// negotiation surface rather than a second changelog.
///
/// <para>Adding one: define the constant, add it to <see cref="All"/> (every
/// emitted document then declares it), document it in README.md, and update the
/// pinned literal in the contract tests — which fail until you do.</para>
/// </summary>
public static class FactsCapabilities
{
    /// <summary>
    /// <c>il[].references[]</c> records a compiled property/indexer/event accessor
    /// (<c>get_Foo</c>) ADDITIONALLY under its natural source-level name
    /// (<c>Foo</c>). Shipped in nucheck 2.3.0; a 2.2.0 build emits the same schema
    /// with only the raw accessor spelling.
    /// </summary>
    public const string IlAccessorNames = "il-accessor-names";

    /// <summary>
    /// <c>il[].references[]</c> records a generic type ADDITIONALLY with its
    /// metadata arity suffix stripped (<c>List`1</c> → <c>List</c>), for
    /// <c>il-type-ref</c> entries and the type half of <c>il-member-ref</c>
    /// entries. Shipped in nucheck 2.3.0.
    /// </summary>
    public const string IlGenericArity = "il-generic-arity";

    /// <summary>Every capability this build declares, ordinal-sorted for a deterministic document.</summary>
    public static IReadOnlyList<string> All { get; } = [IlAccessorNames, IlGenericArity];
}

public sealed record FactsSummary
{
    [JsonPropertyName("projects")] public int Projects { get; init; }
    [JsonPropertyName("filesScanned")] public int FilesScanned { get; init; }
    /// <summary>Assemblies whose metadata was read: package DLLs (for <c>namespaces</c>) plus first-party output assemblies (for <c>il</c>).</summary>
    [JsonPropertyName("assembliesRead")] public int AssembliesRead { get; init; }
    /// <summary>Entries in <c>packages</c> — one per id + version.</summary>
    [JsonPropertyName("packages")] public int Packages { get; init; }
    /// <summary>Packages whose <c>namespaces</c> is present AND non-empty: read from assemblies and found at least one public namespace. A provably assembly-less package (<c>[]</c>) does not count.</summary>
    [JsonPropertyName("packagesWithNamespaces")] public int PackagesWithNamespaces { get; init; }
    [JsonPropertyName("unanalyzable")] public int Unanalyzable { get; init; }
    [JsonPropertyName("exitCode")] public int ExitCode { get; init; }
}

public sealed record ProjectFacts
{
    [JsonPropertyName("path")] public string Path { get; init; } = "";
    [JsonPropertyName("isTestProject")] public bool IsTestProject { get; init; }
    /// <summary>
    /// What made this a test project: <c>"&lt;IsTestProject&gt;"</c> for the explicit
    /// MSBuild property, else the id of the test-framework package it references.
    /// NEVER a directory name. An explicit <c>null</c> when it is not a test project.
    /// </summary>
    [JsonPropertyName("testMarker")] public string? TestMarker { get; init; }
    [JsonPropertyName("directReferences")] public List<DeclarationFacts> DirectReferences { get; init; } = [];
    /// <summary>The restore artefact read for this project, or an explicit <c>null</c> when neither exists.</summary>
    [JsonPropertyName("assets")] public AssetsSourceFacts? Assets { get; init; }
    /// <summary>
    /// Every package (id + version) the project's restore artefact resolved
    /// (transitive closure). Versioned because one tree can resolve two versions of
    /// one id in different projects, and each is a distinct entry in <c>packages</c>.
    /// OMITTED when there was no readable artefact: a project whose closure was never
    /// enumerated must not read as a project that resolved nothing.
    /// </summary>
    [JsonPropertyName("closure")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<PackageIdentity>? Closure { get; init; }
    /// <summary>The project's own built assembly under <c>bin/</c>, or an explicit <c>null</c> when none was found.</summary>
    [JsonPropertyName("outputAssembly")] public string? OutputAssembly { get; init; }
    /// <summary>
    /// One entry per readable <c>*.deps.json</c> under the project's <c>bin/</c>.
    /// OMITTED when nothing was built, or when every deps file present is
    /// unparseable (those are in <c>unanalyzable</c>) — never guess what an
    /// artefact nobody produced, or nobody could read, contains.
    /// </summary>
    [JsonPropertyName("runtimeOutput")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<RuntimeOutputFacts>? RuntimeOutput { get; init; }
}

public sealed record AssetsSourceFacts(
    [property: JsonPropertyName("file")] string File,
    /// <summary><c>"assets"</c> for <c>obj/project.assets.json</c>, <c>"lock"</c> for <c>packages.lock.json</c>.</summary>
    [property: JsonPropertyName("kind")] string Kind);

public sealed record DeclarationFacts(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("file")] string File,
    [property: JsonPropertyName("line")] int Line);

public sealed record RuntimeOutputFacts(
    [property: JsonPropertyName("depsJson")] string DepsJson,
    /// <summary>Packages contributing at least one <c>runtime</c> assembly to this output — the ones on disk next to the binary.</summary>
    [property: JsonPropertyName("packages")] List<PackageIdentity> Packages);

public sealed record PackageIdentity(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("version")] string Version);

public sealed record PackageFacts
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("version")] public string Version { get; init; } = "";
    /// <summary>SPDX expression from the package's own .nuspec. OMITTED when unreadable, unrestored, or not an expression — never guessed.</summary>
    [JsonPropertyName("license")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? License { get; init; }
    /// <summary>
    /// Assembly simple names the package ships under <c>lib/</c> or <c>ref/</c>.
    /// Present-and-empty means the artefact enumerated the package's files and
    /// none is an assembly (analyzer-, targets-, content-only). OMITTED when the
    /// files were never enumerated (a lock file names the closure, not its files).
    /// </summary>
    [JsonPropertyName("assemblies")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? Assemblies { get; init; }
    /// <summary>
    /// Namespaces of the package's public types, READ FROM ITS ASSEMBLIES. Present-
    /// and-empty when the package's assemblies were read and expose no public
    /// namespace, or when it provably ships no assembly at all (see
    /// <see cref="Assemblies"/>). OMITTED when no assembly could be read — never
    /// inferred from the package id (the id is wrong for whole families of real
    /// packages: <c>AWSSDK.*</c> ships <c>Amazon.*</c>).
    /// </summary>
    [JsonPropertyName("namespaces")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? Namespaces { get; init; }
    /// <summary>Ids this package depends on, as the restore artefact records them. An id may name a package absent from <c>packages</c> (a TFM-conditional edge that did not resolve) — reported as written, not filtered.</summary>
    [JsonPropertyName("dependencies")] public List<string> Dependencies { get; init; } = [];
}

public sealed record PackageFolderFacts(
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("readable")] bool Readable);

public sealed record SourceFacts
{
    /// <summary>
    /// The top-level identifier segments qualified identifiers were kept for: first
    /// segments of every DLL-read namespace, of every closure or declared package
    /// id, and of every root passed with <c>--roots</c>. A qualified identifier whose
    /// root is not in this set was not recorded, so a consumer knows what the
    /// <c>qualified</c> lists could contain — and what it has to ask for via
    /// <c>--roots</c> when a package it cares about is in no readable artefact.
    /// </summary>
    [JsonPropertyName("qualifiedRoots")] public List<string> QualifiedRoots { get; init; } = [];
    /// <summary>Every C# file that was read, sorted by path — a file with no usings is still listed.</summary>
    [JsonPropertyName("files")] public List<SourceFileFacts> Files { get; init; } = [];
}

public sealed record SourceFileFacts
{
    [JsonPropertyName("file")] public string File { get; init; } = "";
    /// <summary>The innermost discovered project whose directory contains the file; an explicit <c>null</c> for a file under no project.</summary>
    [JsonPropertyName("project")] public string? Project { get; init; }
    [JsonPropertyName("usings")] public List<UsingFacts> Usings { get; init; } = [];
    [JsonPropertyName("qualified")] public List<QualifiedFacts> Qualified { get; init; } = [];
}

public sealed record UsingFacts
{
    [JsonPropertyName("namespace")] public string Namespace { get; init; } = "";
    [JsonPropertyName("line")] public int Line { get; init; }
    [JsonPropertyName("global")] public bool Global { get; init; }
    [JsonPropertyName("static")] public bool Static { get; init; }
    [JsonPropertyName("alias")] public string? Alias { get; init; }
    /// <summary>True when the directive sits inside an <c>#if</c> region the parser skipped (a TFM-conditional using).</summary>
    [JsonPropertyName("disabled")] public bool Disabled { get; init; }
}

public sealed record QualifiedFacts
{
    /// <summary>The dotted prefix as written (<c>Serilog.Log.Information</c>); the consumer decides which namespace it belongs to.</summary>
    [JsonPropertyName("namespace")] public string Namespace { get; init; } = "";
    [JsonPropertyName("line")] public int Line { get; init; }
    [JsonPropertyName("snippet")] public string Snippet { get; init; } = "";
}

public sealed record IlFacts
{
    [JsonPropertyName("project")] public string Project { get; init; } = "";
    [JsonPropertyName("assembly")] public string Assembly { get; init; } = "";
    /// <summary>Distinct external type and member references, sorted. Reference evidence, not a call graph.</summary>
    [JsonPropertyName("references")] public List<IlReferenceFacts> References { get; init; } = [];
}

public sealed record IlReferenceFacts(
    /// <summary><c>il-type-ref</c> or <c>il-member-ref</c>.</summary>
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("symbol")] string Symbol,
    /// <summary>Simple name of the assembly that defines the referenced type.</summary>
    [property: JsonPropertyName("assembly")] string Assembly);

public sealed record UnanalyzableEntry(
    /// <summary>Relative to the target when under it (POSIX separators); a package-cache assembly or nuspec outside the tree keeps its absolute path.</summary>
    [property: JsonPropertyName("file")] string File,
    /// <summary><c>file</c>, <c>directory</c>, <c>assembly</c>, <c>assets</c>, or <c>deps</c>.</summary>
    [property: JsonPropertyName("kind")] string Kind,
    /// <summary>How far the tool got, with nothing machine-specific in it: never an absolute path, never raw exception text that could carry one.</summary>
    [property: JsonPropertyName("reason")] string Reason)
{
    public const string KindFile = "file";
    public const string KindDirectory = "directory";
    public const string KindAssembly = "assembly";
    public const string KindAssets = "assets";
    public const string KindDeps = "deps";

    /// <summary>
    /// A path-free description of a read failure. Filesystem exceptions embed the
    /// offending absolute path in their message, so they are mapped to a fixed
    /// phrase; parser exceptions carry only a position inside the document and
    /// keep their message. Anything else is named by type, never by message.
    /// </summary>
    public static string Describe(Exception ex) => ex switch
    {
        UnauthorizedAccessException => "access denied",
        FileNotFoundException or DirectoryNotFoundException => "not found",
        PathTooLongException => "path too long",
        BadImageFormatException => "not a valid PE/metadata image",
        System.Text.Json.JsonException or System.Xml.XmlException => ex.Message,
        IOException => "I/O error",
        _ => ex.GetType().Name,
    };
}
