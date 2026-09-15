using System.Text.Json;
using Dependably.NuCheck.Facts;

namespace Dependably.NuCheck.Tests.Facts;

/// <summary>
/// The facts document's SELF-DESCRIPTION: its <c>schemaVersion</c> and the
/// <c>capabilities</c> it declares. Both exist so a consumer negotiates from the
/// document it has already parsed rather than from nucheck's release history, so
/// the values are pinned to LITERALS here — a change that adds a capability or
/// alters the schema has to come through this file, and through README.md, which
/// is where the contract is published.
/// </summary>
public class FactsContractTests
{
    /// Every capability this build declares, written out rather than read from the
    /// source's own list: comparing the document to the constant it was built from
    /// would pass no matter what either says.
    private static readonly string[] PinnedCapabilities = ["il-accessor-names", "il-generic-arity"];

    [Fact]
    public void SchemaVersionIsPinnedAndIndependentOfTheFindingsDocument()
    {
        // 1.0 -> 1.1 is the ADDITIVE step the README contract defines: `capabilities`
        // was added; nothing was renamed, removed or redefined. A rename or a removal is
        // a MAJOR, and this literal is where that decision gets made deliberately rather
        // than incidentally.
        Assert.Equal("1.1", FactsDocument.SchemaVersion);
        Assert.Equal("1.1", FactsCommand.Build(Fixtures.CsharpApp, "test").Schema);
    }

    [Fact]
    public void DeclaredCapabilitiesArePinned()
    {
        Assert.Equal(PinnedCapabilities, FactsCapabilities.All);
        Assert.Equal("il-accessor-names", FactsCapabilities.IlAccessorNames);
        Assert.Equal("il-generic-arity", FactsCapabilities.IlGenericArity);
    }

    /// The point of the field: adding a capability changes what EVERY emitted
    /// document declares, because the document is built from the one list rather
    /// than from a literal of its own. Asserted on the wire form — a consumer reads
    /// JSON, not a C# property.
    [Fact]
    public void AddingACapabilityChangesWhatTheDocumentDeclares()
    {
        using var json = JsonDocument.Parse(FactsCommand.Serialize(FactsCommand.Build(Fixtures.CsharpApp, "test")));
        var declared = json.RootElement.GetProperty("capabilities").EnumerateArray().Select(e => e.GetString()!).ToArray();

        Assert.Equal(PinnedCapabilities, declared);
        Assert.Equal(FactsCapabilities.All, declared);

        // The same document built with one more capability declares one more — i.e.
        // the value tracks the list, and a build that gained a behaviour cannot keep
        // quiet about it by accident.
        var extended = FactsCommand.Build(Fixtures.CsharpApp, "test") with
        {
            Capabilities = [.. FactsCapabilities.All, "il-something-new"],
        };
        using var extendedJson = JsonDocument.Parse(FactsCommand.Serialize(extended));
        Assert.Equal(
            [.. PinnedCapabilities, "il-something-new"],
            extendedJson.RootElement.GetProperty("capabilities").EnumerateArray().Select(e => e.GetString()));
    }

    /// A capability is a negotiation surface for consumers, so an undocumented one
    /// is useless: it tells a reader a name and nothing about what the build does.
    [Fact]
    public void EveryDeclaredCapabilityIsDocumentedInTheReadme()
    {
        var readme = File.ReadAllText(Path.Combine(RepoRoot(), "README.md"));
        Assert.All(FactsCapabilities.All, id => Assert.Contains($"`{id}`", readme));
        // And the contract the ids are negotiated under is published there too.
        Assert.Contains("### `schemaVersion` and `capabilities`", readme);
    }

    /// Walks up from the test assembly to the directory holding the solution file.
    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Dependably.NuCheck.slnx")))
        {
            dir = dir.Parent;
        }
        Assert.True(dir is not null, "could not locate the repository root (Dependably.NuCheck.slnx) above the test assembly");
        return dir!.FullName;
    }
}
