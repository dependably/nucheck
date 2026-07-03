using System.Text.Json;
using Dependably.NuCheck.Config;

namespace Dependably.NuCheck.Tests;

/// <summary>
/// Replays the shared cross-language <c>.dependably</c> conformance fixtures
/// (conformance/dependably/cases/*.json, vendored from the spec repo) through the C#
/// exception parser + matcher. This is what keeps nucheck's port behaviour-identical to
/// npm-check's reference implementation: same fixtures, same outcomes, three languages.
/// The exception-grammar cases are tool-agnostic; the npm-flavoured config-loader cases
/// (discovery/section-merge) are covered by nucheck-specific tests instead.
/// </summary>
public class ConformanceTests
{
    private static readonly string[] SectionKeys = ["common", "npm-check", "nucheck", "pycheck", "cslint", "codemetrics", "npm", "nuget", "python"];

    public static IEnumerable<object[]> ExceptionMatchingCases() => CaseFiles("exceptions-");

    public static IEnumerable<object[]> ExceptionValidationCases() => CaseFiles("validation-exception-");

    private static IEnumerable<object[]> CaseFiles(string prefix)
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "conformance", "dependably", "cases");
        foreach (var file in Directory.EnumerateFiles(dir, "*.json").Where(f => Path.GetFileName(f).StartsWith(prefix, StringComparison.Ordinal)))
        {
            yield return [Path.GetFileName(file)];
        }
    }

    [Theory]
    [MemberData(nameof(ExceptionMatchingCases))]
    public void Exception_matching_matches_the_shared_spec(string caseFile)
    {
        var root = LoadCase(caseFile);
        var dependably = root.GetProperty("files").GetProperty(".dependably");

        var exceptions = ParseAllExceptions(dependably);
        var today = root.TryGetProperty("today", out var t) && t.ValueKind == JsonValueKind.String
            ? DateOnly.Parse(t.GetString()!)
            : new DateOnly(2026, 7, 3);

        var live = exceptions.Where(e => !DependablyExceptions.IsExpired(e, today)).ToList();
        var expired = exceptions.Where(e => DependablyExceptions.IsExpired(e, today)).ToList();
        var used = new HashSet<DependablyException>();

        var findings = root.TryGetProperty("findings", out var f) && f.ValueKind == JsonValueKind.Array
            ? f.EnumerateArray().ToList()
            : [];

        var suppressed = new List<int>();
        for (var i = 0; i < findings.Count; i++)
        {
            var target = ToTarget(findings[i]);
            var hit = live.FirstOrDefault(e => DependablyExceptions.Matches(e, target));
            if (hit is not null)
            {
                used.Add(hit);
                suppressed.Add(i);
            }
        }

        var expect = root.GetProperty("expect");
        if (expect.TryGetProperty("suppressedFindings", out var sf))
        {
            Assert.Equal(sf.EnumerateArray().Select(x => x.GetInt32()).OrderBy(x => x), suppressed.OrderBy(x => x));
        }

        if (expect.TryGetProperty("unusedExceptions", out var ue))
        {
            Assert.Equal(ue.GetArrayLength(), live.Count(e => !used.Contains(e)));
        }

        if (expect.TryGetProperty("expiredExceptions", out var ee))
        {
            Assert.Equal(ee.GetArrayLength(), expired.Count);
        }
    }

    [Theory]
    [MemberData(nameof(ExceptionValidationCases))]
    public void Exception_validation_raises_the_shared_error_code(string caseFile)
    {
        var root = LoadCase(caseFile);
        var expectedCode = root.GetProperty("expect").GetProperty("error").GetString();
        var dependably = root.GetProperty("files").GetProperty(".dependably");

        var ex = Assert.Throws<DependablyConfigException>(() =>
        {
            foreach (var section in SectionKeys)
            {
                if (dependably.TryGetProperty(section, out var sectionEl)
                    && sectionEl.ValueKind == JsonValueKind.Object
                    && sectionEl.TryGetProperty("exceptions", out var exc))
                {
                    // Own-section strictness (applicable = package/id, shared by npm-check + nucheck).
                    DependablyExceptions.Parse(exc, "own", DependablyExceptions.NuCheckSelectors, null);
                }
            }
        });

        Assert.Equal(expectedCode, ex.Code);
    }

    private static List<DependablyException> ParseAllExceptions(JsonElement dependably)
    {
        var all = new List<DependablyException>();
        foreach (var section in SectionKeys)
        {
            if (dependably.TryGetProperty(section, out var sectionEl)
                && sectionEl.ValueKind == JsonValueKind.Object
                && sectionEl.TryGetProperty("exceptions", out var exc))
            {
                all.AddRange(DependablyExceptions.Parse(exc, "common", DependablyExceptions.Selectors, null));
            }
        }

        return all;
    }

    private static ExceptionTarget ToTarget(JsonElement finding)
    {
        string? Str(string key) => finding.TryGetProperty(key, out var el) && el.ValueKind == JsonValueKind.String ? el.GetString() : null;

        var rule = Str("rule") ?? Str("ruleId") ?? "";
        var pkg = Str("package");
        string? name = pkg;
        string? version = null;
        if (pkg is not null)
        {
            var at = pkg.LastIndexOf('@');
            if (at > 0)
            {
                name = pkg[..at];
                version = pkg[(at + 1)..];
            }
        }

        return new ExceptionTarget(rule, Package: name, Version: version, Path: Str("path"), Symbol: Str("symbol"), Id: Str("id"));
    }

    private static JsonElement LoadCase(string caseFile)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "conformance", "dependably", "cases", caseFile);
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        return doc.RootElement.Clone();
    }
}
