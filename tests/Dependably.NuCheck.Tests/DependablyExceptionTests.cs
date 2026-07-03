using System.Text.Json;
using Dependably.NuCheck.Config;

namespace Dependably.NuCheck.Tests;

public class DependablyExceptionTests
{
    private static readonly string[] NpmSelectors = ["package", "id"];

    private static IReadOnlyList<DependablyException> Parse(string json, string source = "own",
        IReadOnlyCollection<string>? applicable = null, IReadOnlyCollection<string>? knownRules = null)
    {
        using var doc = JsonDocument.Parse(json);
        return DependablyExceptions.Parse(doc.RootElement, source, applicable ?? DependablyExceptions.NuCheckSelectors, knownRules);
    }

    private static DependablyException One(string entryJson, string source = "common",
        IReadOnlyCollection<string>? applicable = null)
        => Parse($"[{entryJson}]", source, applicable ?? DependablyExceptions.Selectors)[0];

    // ---- glob ----

    [Theory]
    [InlineData("src/**", "src/a/b.cs", true)]
    [InlineData("src/**", "src", true)]
    [InlineData("src/**", "lib/a.cs", false)]
    [InlineData("src/*.cs", "src/a.cs", true)]
    [InlineData("src/*.cs", "src/a/b.cs", false)]
    [InlineData("a?.cs", "ab.cs", true)]
    [InlineData("a?.cs", "abc.cs", false)]
    public void MatchGlob_portable_subset(string glob, string value, bool expected)
        => Assert.Equal(expected, DependablyExceptions.MatchGlob(glob, value));

    [Fact]
    public void MatchGlob_normalizes_backslashes()
        => Assert.True(DependablyExceptions.MatchGlob("src/**", "src\\a\\b.cs"));

    // ---- parse validation ----

    [Fact]
    public void Parse_accepts_wellformed_entry()
    {
        var ex = Parse("""[{ "rule": "unused-packages", "package": "Foo", "reason": "build tool" }]""");
        Assert.Single(ex);
        Assert.Equal("unused-packages", ex[0].Rule);
        Assert.Equal("foo", ex[0].PackageName);
    }

    [Fact]
    public void Parse_undefined_is_empty()
    {
        using var doc = JsonDocument.Parse("null");
        Assert.Empty(DependablyExceptions.Parse(doc.RootElement, "own", NpmSelectors, null));
    }

    [Theory]
    [InlineData("""[{ "package": "x", "reason": "y" }]""", "EXCEPTION_MISSING_RULE")]
    [InlineData("""[{ "rule": "unused-packages", "package": "x" }]""", "EXCEPTION_MISSING_REASON")]
    [InlineData("""[{ "rule": "unused-packages", "reason": "y" }]""", "EXCEPTION_NO_SELECTOR")]
    [InlineData("""[{ "rule": "unused-packages", "package": "x", "reason": "y", "expires": "31-12-2026" }]""", "EXCEPTION_BAD_EXPIRES")]
    [InlineData("""[{ "rule": "unused-packages", "symbol": "T.M", "reason": "y" }]""", "EXCEPTION_BAD_SELECTOR")]
    public void Parse_own_section_rejects(string json, string expectedCode)
    {
        var ex = Assert.Throws<DependablyConfigException>(() => Parse(json, "own", NpmSelectors));
        Assert.Equal(expectedCode, ex.Code);
    }

    [Fact]
    public void Parse_common_tolerates_inapplicable_selector()
    {
        var ex = Parse("""[{ "rule": "cyclomatic", "symbol": "T.M", "reason": "y" }]""", "common", NpmSelectors);
        Assert.Single(ex);
    }

    [Fact]
    public void Parse_own_rejects_unknown_rule_when_known_given()
    {
        var ex = Assert.Throws<DependablyConfigException>(
            () => Parse("""[{ "rule": "no-such", "package": "x", "reason": "y" }]""", "own", NpmSelectors, DependablyExceptions.KnownRules));
        Assert.Equal("UNKNOWN_RULE", ex.Code);
    }

    // ---- matching ----

    [Fact]
    public void Matches_package_case_insensitive()
    {
        var ex = One("""{ "rule": "r", "package": "ESBuild", "reason": "x" }""");
        Assert.True(DependablyExceptions.Matches(ex, new ExceptionTarget("r", Package: "esbuild")));
    }

    [Fact]
    public void Matches_version_pin_exact_only()
    {
        var ex = One("""{ "rule": "vulnerable-package", "package": "log4net@2.0.8", "reason": "x" }""");
        Assert.True(DependablyExceptions.Matches(ex, new ExceptionTarget("vulnerable-package", Package: "log4net", Version: "2.0.8")));
        Assert.False(DependablyExceptions.Matches(ex, new ExceptionTarget("vulnerable-package", Package: "log4net", Version: "2.0.15")));
    }

    [Fact]
    public void Matches_selectors_are_and()
    {
        var ex = One("""{ "rule": "r", "path": "src/Parser/**", "symbol": "Parser.Parse", "reason": "x" }""");
        Assert.True(DependablyExceptions.Matches(ex, new ExceptionTarget("r", Path: "src/Parser/P.cs", Symbol: "Parser.Parse")));
        Assert.False(DependablyExceptions.Matches(ex, new ExceptionTarget("r", Path: "src/Parser/P.cs", Symbol: "Parser.Other")));
    }

    [Fact]
    public void Matches_symbol_type_matches_member()
    {
        var ex = One("""{ "rule": "r", "symbol": "Parser", "reason": "x" }""");
        Assert.True(DependablyExceptions.Matches(ex, new ExceptionTarget("r", Symbol: "Parser.Parse")));
        Assert.False(DependablyExceptions.Matches(ex, new ExceptionTarget("r", Symbol: "Other.Parse")));
    }

    [Fact]
    public void Matches_id_exact()
    {
        var ex = One("""{ "rule": "r", "id": "GHSA-x", "reason": "x" }""");
        Assert.True(DependablyExceptions.Matches(ex, new ExceptionTarget("r", Id: "GHSA-x")));
        Assert.False(DependablyExceptions.Matches(ex, new ExceptionTarget("r", Id: "GHSA-y")));
    }

    // ---- expiry ----

    [Fact]
    public void IsExpired_respects_date()
    {
        var ex = One("""{ "rule": "r", "package": "x", "reason": "x", "expires": "2026-01-01" }""");
        Assert.True(DependablyExceptions.IsExpired(ex, new DateOnly(2026, 7, 3)));
        Assert.False(DependablyExceptions.IsExpired(ex, new DateOnly(2025, 12, 1)));
    }

    [Fact]
    public void IsExpired_false_without_expires()
    {
        var ex = One("""{ "rule": "r", "package": "x", "reason": "x" }""");
        Assert.False(DependablyExceptions.IsExpired(ex, new DateOnly(2999, 1, 1)));
    }
}
