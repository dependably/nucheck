using System.Text.RegularExpressions;
using Dependably.NuCheck.Facts.Nuget;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

namespace Dependably.NuCheck.Facts.Scan;

/// <param name="Kind"><c>using-directive</c>, <c>global-using</c> or <c>qualified-identifier</c>.</param>
/// <param name="Static">A <c>using static</c> directive.</param>
/// <param name="Alias">The alias name of a <c>using X = A.B;</c> directive, else null.</param>
/// <param name="Disabled">The directive sits in an <c>#if</c>-disabled region (TFM-conditional).</param>
public sealed record NamespaceUse(
    string Namespace,
    string File,
    int Line,
    string Snippet,
    string Kind,
    bool Static = false,
    string? Alias = null,
    bool Disabled = false);

/// <summary>One C# file that was read, with everything the scan found in it — possibly nothing.</summary>
public sealed record ScannedFile(string File, List<NamespaceUse> Uses);

/// <summary>
/// Parse-only Roslyn scan over *.cs: using directives (incl. global/static/alias),
/// `#if`-disabled using lines, and fully-qualified identifier prefixes whose root
/// segment matches a namespace of interest.
/// </summary>
public static partial class UsingScanner
{
    [GeneratedRegex(@"(global\s+)?using\s+(static\s+)?(?:(\w+)\s*=\s*)?([A-Za-z_][\w.]*)\s*;")]
    private static partial Regex DisabledUsingRegex();

    /// <summary>
    /// Every scannable C# file under <paramref name="srcDir"/>, sorted by path,
    /// each with its uses. A file that could not be read is reported in
    /// <paramref name="unanalyzable"/> and is NOT in the result — the two lists
    /// together are the whole tree, so a consumer can tell "read, found nothing"
    /// from "never read".
    /// </summary>
    public static List<ScannedFile> ScanAll(
        string srcDir,
        IReadOnlySet<string> interestingRoots,
        List<UnanalyzableEntry> unanalyzable)
    {
        var result = new List<ScannedFile>();
        var files = ProjectDiscovery.EnumerateFiles(srcDir, unanalyzable)
            .Where(IsScannableSource)
            .OrderBy(f => f, StringComparer.Ordinal);

        foreach (var file in files)
        {
            var rel = ProjectDiscovery.RelativePath(srcDir, file);
            string content;
            try
            {
                content = File.ReadAllText(file);
            }
            catch (Exception ex)
            {
                unanalyzable.Add(new UnanalyzableEntry(rel, UnanalyzableEntry.KindFile, $"unreadable: {ex.Message}"));
                continue;
            }
            var uses = new List<NamespaceUse>();
            try
            {
                ScanFile(rel, content, interestingRoots, uses);
            }
            catch (Exception ex)
            {
                unanalyzable.Add(new UnanalyzableEntry(rel, UnanalyzableEntry.KindFile, $"analysis error: {ex.Message}"));
                continue;
            }
            result.Add(new ScannedFile(rel, uses));
        }
        return result;
    }

    private static bool IsScannableSource(string path)
    {
        if (!path.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)) return false;
        var name = Path.GetFileName(path);
        if (name.EndsWith(".g.cs", StringComparison.OrdinalIgnoreCase)) return false;
        if (name.EndsWith(".Designer.cs", StringComparison.OrdinalIgnoreCase)) return false;
        if (name.EndsWith(".generated.cs", StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    private static void ScanFile(
        string rel,
        string content,
        IReadOnlySet<string> interestingRoots,
        List<NamespaceUse> uses)
    {
        var tree = CSharpSyntaxTree.ParseText(content, new CSharpParseOptions(LanguageVersion.Latest));
        var root = tree.GetRoot();
        var text = tree.GetText();

        foreach (var node in root.DescendantNodes(descendIntoTrivia: false))
        {
            switch (node)
            {
                case UsingDirectiveSyntax u when u.Name is not null:
                    uses.Add(new NamespaceUse(
                        u.Name.ToString(),
                        rel,
                        LineOf(text, u.SpanStart),
                        Snip(u.ToString()),
                        u.GlobalKeyword.IsKind(SyntaxKind.GlobalKeyword) ? "global-using" : "using-directive",
                        Static: u.StaticKeyword.IsKind(SyntaxKind.StaticKeyword),
                        Alias: u.Alias?.Name.Identifier.Text));
                    break;

                case MemberAccessExpressionSyntax ma when ma.Parent is not MemberAccessExpressionSyntax:
                    AddQualified(uses, rel, ma.ToString(), LineOf(text, ma.SpanStart), interestingRoots);
                    break;

                case QualifiedNameSyntax qn when qn.Parent is not QualifiedNameSyntax and not UsingDirectiveSyntax
                    and not NamespaceDeclarationSyntax and not FileScopedNamespaceDeclarationSyntax:
                    AddQualified(uses, rel, qn.ToString(), LineOf(text, qn.SpanStart), interestingRoots);
                    break;
            }
        }

        CollectDisabledUsings(root, text, rel, uses);
    }

    private static int LineOf(SourceText text, int position) => text.Lines.GetLinePosition(position).Line + 1;

    private static string Snip(string s)
    {
        var one = Regex.Replace(s, @"\s+", " ").Trim();
        return one.Length > 200 ? one[..199] + "…" : one;
    }

    /// The dotted prefix of a qualified expression, kept only when its first
    /// segment is a root of interest (see `source.qualifiedRoots`).
    private static void AddQualified(
        List<NamespaceUse> uses,
        string rel,
        string expression,
        int line,
        IReadOnlySet<string> interestingRoots)
    {
        var m = Regex.Match(expression.Replace(" ", ""), @"^[A-Za-z_]\w*(\.[A-Za-z_]\w*)+");
        if (!m.Success) return;
        var dotted = m.Value;
        var firstSegment = dotted[..dotted.IndexOf('.')];
        if (!interestingRoots.Contains(firstSegment)) return;
        uses.Add(new NamespaceUse(dotted, rel, line, Snip(expression), "qualified-identifier"));
    }

    /// `#if`-disabled regions: TFM-conditional usings are still a fact about the
    /// file, reported with Disabled = true so the consumer can weigh them.
    private static void CollectDisabledUsings(SyntaxNode root, SourceText text, string rel, List<NamespaceUse> uses)
    {
        foreach (var trivia in root.DescendantTrivia(descendIntoTrivia: true))
        {
            if (!trivia.IsKind(SyntaxKind.DisabledTextTrivia)) continue;
            var disabledText = trivia.ToFullString();
            foreach (Match m in DisabledUsingRegex().Matches(disabledText))
            {
                var offset = trivia.FullSpan.Start + m.Index;
                uses.Add(new NamespaceUse(
                    m.Groups[4].Value,
                    rel,
                    LineOf(text, offset),
                    Snip(m.Value),
                    m.Groups[1].Success ? "global-using" : "using-directive",
                    Static: m.Groups[2].Success,
                    Alias: m.Groups[3].Success ? m.Groups[3].Value : null,
                    Disabled: true));
            }
        }
    }
}
