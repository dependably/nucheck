using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Dependably.NuCheck.Config;
using Dependably.NuCheck.Models;
using Dependably.NuCheck.Services;
using Xunit.Abstractions;

namespace Dependably.NuCheck.Tests;

/// <summary>
/// Replays the vendored cross-language <c>.dependably</c> conformance corpus
/// (conformance/dependably/cases/*.json) through nucheck's REAL config entry point,
/// <see cref="DependablyCheckConfig.Load"/>, and — for cases carrying findings — through the
/// real <see cref="ExceptionApplier"/> and the real <see cref="AuditResult.GateTrips"/>.
/// <para>
/// Driving the loader rather than the primitives it calls is the whole point: a suite that
/// reached past <c>Load</c> into <c>DependablyExceptions.Parse</c> would still pass with a
/// broken loader, which is the failure mode this suite exists to catch. Every case is
/// materialized into a throwaway repo (a <c>.git</c> marker bounds the walk-up) exactly as a
/// user's checkout would present it.
/// </para>
/// <para>
/// Cases written in the shared symbolic vocabulary (spec §12) are bound to nucheck's own
/// section keys and rule ids before they run; a placeholder that cannot be bound fails the
/// run rather than reaching the loader, because an unbound <c>$tool</c> would become an
/// unknown top-level section that §3.5 requires be ignored silently — the case would then
/// pass while asserting nothing.
/// </para>
/// </summary>
public sealed class ConformanceTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly string _root;

    public ConformanceTests(ITestOutputHelper output)
    {
        _output = output;
        _root = Path.Combine(Path.GetTempPath(), "nucheck-conformance-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(_root, ".git"));
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
            // A leftover temp directory is not worth failing an otherwise green run over.
        }
    }

    // ---------------------------------------------------------------- vocabulary binding

    /// <summary>
    /// nucheck's binding of the seven spec §12.2 placeholders. Whole-string replacement only:
    /// a placeholder is an entire object key or an entire string value, never a fragment.
    /// </summary>
    private static readonly Dictionary<string, string> Bindings = new(StringComparer.Ordinal)
    {
        // §3.3 registry entries for nucheck.
        ["$tool"] = DependablyCheckConfig.SectionKey,
        ["$alias"] = DependablyCheckConfig.DeprecatedSectionKey,

        // Two distinct ids from nucheck's own §4.4 registry.
        ["$rule1"] = DependablyExceptions.KnownRules[0],
        ["$rule2"] = DependablyExceptions.KnownRules[1],

        // In codemetrics' registry — it is the rule the `codemetrics` section of
        // exceptions-path-and-symbol-and configures — and in no nucheck registry.
        ["$foreignRule"] = "cyclomatic",

        // Deliberate nonsense: in no tool's registry, so it can only ever be UNKNOWN_RULE.
        ["$unknownRule"] = "no-such-rule-in-any-registry",

        // A key pdbcheck defines inside its own section; nucheck's §4 vocabulary has no such key.
        ["$foreignKey"] = "terms",
    };

    /// <summary>The subtrees binding applies to (spec §12.2). `tool`, `name` and `today` are not bound.</summary>
    private static readonly string[] BoundSubtrees = ["files", "cli", "findings", "expect"];

    /// <summary>
    /// The §12.5 capability tokens, answered from nucheck's real vocabulary rather than from a
    /// hand-maintained list — adding a selector to <see cref="DependablyExceptions.NuCheckSelectors"/>
    /// flips the matching capability on by itself.
    /// </summary>
    private static readonly Dictionary<string, bool> Capabilities = new(StringComparer.Ordinal)
    {
        ["alias"] = !string.IsNullOrEmpty(DependablyCheckConfig.DeprecatedSectionKey),
        ["packageSelector"] = DependablyExceptions.NuCheckSelectors.Contains("package"),
        ["pathSelector"] = DependablyExceptions.NuCheckSelectors.Contains("path"),
        ["symbolSelector"] = DependablyExceptions.NuCheckSelectors.Contains("symbol"),
        ["idSelector"] = DependablyExceptions.NuCheckSelectors.Contains("id"),
    };

    // ---------------------------------------------------------------- registries

    /// <summary>
    /// Cases nucheck cannot replay, each named and reasoned: filtering a corpus by filename
    /// prefix is how it grows cases nobody runs. A waiver may only cover a case authored in
    /// another tool's literal vocabulary (spec §12.1) — the coverage tests below enforce that,
    /// so a nucheck case can never be waived.
    /// </summary>
    private static readonly Dictionary<string, string> Waived = new(StringComparer.Ordinal)
    {
        ["exceptions-common-and-tool-union"] =
            "cslint vocabulary: the tool half of the union lives in the `cslint` section, which nucheck " +
            "never reads, and both halves select on `path`, which nucheck findings never carry.",
        ["exceptions-expired"] =
            "npm-check vocabulary: the exception lives in the `npm-check` section and names " +
            "`install-scripts`, so nucheck's loader resolves no exceptions at all and the case would " +
            "assert nothing. Expiry is pinned against nucheck's own section by DependablyExceptionTests.",
        ["exceptions-package-selector"] =
            "npm-check vocabulary: the exception lives in the `npm-check` section and names " +
            "`install-scripts`; nucheck's own package-selector behaviour is pinned by " +
            "exceptions-package-version-pin, which is authored for nucheck.",
        ["exceptions-path-and-symbol-and"] =
            "codemetrics vocabulary: the exception lives in the `codemetrics` section and ANDs `path` " +
            "with `symbol`, two selectors nucheck rejects in its own section by design.",
        ["exceptions-suppressed-still-counted"] =
            "npm-check vocabulary: the exception lives in the `npm-check` section and names " +
            "`unused-dependencies`, a rule id that is in no nucheck registry.",
        ["exceptions-unused-warns"] =
            "npm-check vocabulary: the exception lives in the `npm-check` section, so nucheck resolves " +
            "no exceptions and could never report one as unused.",
        ["validation-exception-bad-expires"] =
            "npm-check vocabulary: the malformed entry lives in the `npm-check` section, which nucheck " +
            "never reads, so the loader raises nothing. EXCEPTION_BAD_EXPIRES is pinned against " +
            "nucheck's own section by DependablyExceptionTests.",
        ["validation-exception-bad-selector-own-section"] =
            "npm-check vocabulary: the entry lives in the `npm-check` section and turns on npm-check's " +
            "own inapplicable selector; nucheck's own-section selector strictness is pinned by " +
            "DependablyExceptionTests.",
        ["validation-exception-missing-reason"] =
            "npm-check vocabulary: the entry lives in the `npm-check` section, which nucheck never reads. " +
            "EXCEPTION_MISSING_REASON is pinned against nucheck's own section by DependablyExceptionTests.",
        ["validation-exception-no-selector"] =
            "npm-check vocabulary: the entry lives in the `npm-check` section, which nucheck never reads. " +
            "EXCEPTION_NO_SELECTOR is pinned against nucheck's own section by DependablyExceptionTests.",
    };

    /// <summary>
    /// Cases nucheck replays but does not yet satisfy. Each entry is a bug with a test already
    /// written for it, not a waiver: the case is replayed and asserted to STILL fail, so the suite
    /// goes red the moment one starts passing and the entry cannot outlive the defect. Empty is
    /// the goal.
    /// </summary>
    private static readonly Dictionary<string, string> KnownDivergences = new(StringComparer.Ordinal)
    {
        ["discovery-walkup-finds-repo-root"] =
            "nucheck treats `exclude` as legal-and-inert: it is in KnownSectionKeys so it never warns, but " +
            "DependablyCheckConfig exposes no property carrying the merged list, so a case pinning " +
            "`resolved.exclude` has nothing to assert against. Closing it means either surfacing the merged " +
            "`exclude` off the config the way the other three §5 list keys are surfaced, or the corpus " +
            "growing an `exclude` capability token so §12.5 can skip the case honestly.",
        ["merge-lists-union-and-dedupe"] =
            "Two defects in one case. UnionStringArray dedupes allowedRegistryHosts case-insensitively but " +
            "stores the FIRST-seen spelling, where §5.1 requires lowercase as the canonical stored form — so " +
            "`Packages.Corp.Dev` from `common` survives verbatim instead of collapsing to `packages.corp.dev`, " +
            "and a config that spells a host two ways gets two allowlist entries downstream. The case then " +
            "also pins `exclude`, which nucheck does not surface (see discovery-walkup-finds-repo-root).",
    };

    // ---------------------------------------------------------------- corpus

    private static readonly IReadOnlyList<JsonObject> Corpus = LoadCorpus();

    private static IReadOnlyList<JsonObject> LoadCorpus()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "conformance", "dependably", "cases");
        return Directory.EnumerateFiles(dir, "*.json")
            .OrderBy(f => f, StringComparer.Ordinal)
            .Select(f => (JsonObject)JsonNode.Parse(File.ReadAllText(f))!)
            .ToList();
    }

    private static string Name(JsonObject caseDef) => (string)caseDef["name"]!;

    private static string Tool(JsonObject caseDef) => (string)caseDef["tool"]!;

    private static string[] Requires(JsonObject caseDef) =>
        caseDef["requires"] is JsonArray array ? array.Select(n => (string)n!).ToArray() : [];

    private static string[]? AppliesTo(JsonObject caseDef) =>
        caseDef["appliesTo"] is JsonArray array ? array.Select(n => (string)n!).ToArray() : null;

    /// <summary>The §12.5 / §12.6 skip decision: null to replay, else the reason the case cannot run here.</summary>
    private static string? SkipReason(JsonObject caseDef)
    {
        foreach (var capability in Requires(caseDef))
        {
            if (!Capabilities.TryGetValue(capability, out var have))
            {
                throw new InvalidOperationException(
                    $"case \"{Name(caseDef)}\" requires capability \"{capability}\", which this adapter does " +
                    "not know how to answer. Teach ConformanceTests.Capabilities about it — treating an " +
                    "unknown token as satisfied is exactly how a skipped case silently passes (spec §12.5).");
            }

            if (!have)
            {
                return $"requires capability \"{capability}\", which nucheck does not have";
            }
        }

        var appliesTo = AppliesTo(caseDef);
        return appliesTo is not null && !appliesTo.Contains(DependablyCheckConfig.SectionKey)
            ? $"appliesTo [{string.Join(", ", appliesTo)}] does not name {DependablyCheckConfig.SectionKey}"
            : null;
    }

    private static bool IsRegistered(JsonObject caseDef) =>
        Waived.ContainsKey(Name(caseDef)) || KnownDivergences.ContainsKey(Name(caseDef));

    private static IEnumerable<JsonObject> Skipped => Corpus.Where(c => SkipReason(c) is not null);

    private static IEnumerable<JsonObject> Replayed =>
        Corpus.Where(c => !IsRegistered(c) && SkipReason(c) is null);

    private static IEnumerable<JsonObject> Divergent => Corpus.Where(c => KnownDivergences.ContainsKey(Name(c)));

    public static IEnumerable<object[]> ReplayedCases() => Replayed.Select(c => new object[] { Name(c) });

    public static IEnumerable<object[]> DivergentCases() => Divergent.Select(c => new object[] { Name(c) });

    public static IEnumerable<object[]> WaivedEntries() => Waived.Select(e => new object[] { e.Key, e.Value });

    public static IEnumerable<object[]> DivergenceEntries() =>
        KnownDivergences.Select(e => new object[] { e.Key, e.Value });

    public static IEnumerable<object[]> AllCases() => Corpus.Select(c => new object[] { Name(c) });

    /// <summary>A private copy of a case, so binding never mutates the shared corpus.</summary>
    private static JsonObject Case(string name) =>
        (JsonObject)JsonNode.Parse(Corpus.Single(c => Name(c) == name).ToJsonString())!;

    // ---------------------------------------------------------------- the suite

    [Theory]
    [MemberData(nameof(ReplayedCases))]
    public void Conforms_to_the_shared_corpus(string name) => Replay(Bind(Case(name)));

    /// <summary>
    /// A recorded divergence must STILL fail. When one starts passing the fix has landed and the
    /// <see cref="KnownDivergences"/> entry has to go, or the case would sit unreplayed forever.
    /// </summary>
    [Theory]
    [MemberData(nameof(DivergentCases))]
    public void Known_divergence_still_fails(string name)
    {
        var conforms = true;
        try
        {
            Replay(Bind(Case(name)));
        }
        catch (Exception ex)
        {
            conforms = false;
            _output.WriteLine($"{name} diverges as recorded: {ex.Message}");
        }

        Assert.False(conforms,
            $"{name} now conforms — delete its KnownDivergences entry so the case is replayed for real.");
    }

    // ---------------------------------------------------------------- coverage

    [Fact]
    public void Accounts_for_every_vendored_case()
    {
        var accounted = new HashSet<string>(
            Replayed.Concat(Skipped).Select(Name).Concat(Waived.Keys).Concat(KnownDivergences.Keys),
            StringComparer.Ordinal);

        var unaccounted = Corpus.Select(Name).Where(n => !accounted.Contains(n)).ToList();
        Assert.Empty(unaccounted);
    }

    /// <summary>
    /// Cases authored FOR nucheck carry nucheck's literal vocabulary and are the whole reason the
    /// tool sits in the §3.3 registry. Waiving one, or writing it off as a divergence, would leave
    /// nucheck's own contract untested — so both are refused here.
    /// </summary>
    [Fact]
    public void Replays_every_case_authored_in_nucheck_vocabulary()
    {
        var own = Corpus.Where(c => Tool(c) == DependablyCheckConfig.SectionKey).Select(Name).ToList();
        Assert.NotEmpty(own);

        var unreplayed = own.Where(n => Waived.ContainsKey(n) || KnownDivergences.ContainsKey(n)).ToList();
        Assert.Empty(unreplayed);
    }

    /// <summary>nucheck HAS a §3.3 alias section key, so the alias cases must run rather than skip.</summary>
    [Fact]
    public void Replays_the_alias_cases_because_nucheck_has_an_alias()
    {
        Assert.True(Capabilities["alias"]);
        var replayed = Replayed.Select(Name).ToList();
        Assert.Contains("sections-alias-read", replayed);
        Assert.Contains("sections-canonical-beats-alias", replayed);
    }

    /// <summary>
    /// Every skip is reported by name and by the capability that forced it (spec §12.5) — a
    /// silently skipped case is the failure that field exists to prevent. A skip naming a
    /// capability nucheck actually has is an adapter bug, not a legitimate skip.
    /// </summary>
    [Fact]
    public void Reports_every_capability_skip()
    {
        var skipped = Skipped.ToList();
        _output.WriteLine(skipped.Count == 0
            ? "no case skipped: nucheck satisfies every capability the corpus requires."
            : $"{skipped.Count} case(s) skipped by capability:");

        foreach (var caseDef in skipped)
        {
            _output.WriteLine($"  {Name(caseDef)} — {SkipReason(caseDef)}");

            var satisfied = Requires(caseDef).Where(r => Capabilities[r]).ToList();
            Assert.Empty(satisfied);
        }
    }

    [Theory]
    [MemberData(nameof(WaivedEntries))]
    public void Waives_a_vendored_case_for_a_stated_reason(string name, string reason)
    {
        Assert.Contains(name, Corpus.Select(Name));
        Assert.True(reason.Length > 20, $"{name} needs a reason a reader can act on");

        // §12.1: a vocabulary-bound case is replayable by every tool, so it can never be waived.
        Assert.NotEqual("$any", Tool(Case(name)));
    }

    [Theory]
    [MemberData(nameof(DivergenceEntries))]
    public void Records_a_divergence_for_a_stated_reason(string name, string reason)
    {
        Assert.Contains(name, Corpus.Select(Name));
        Assert.True(reason.Length > 20, $"{name} needs a reason a reader can act on");
    }

    // ---------------------------------------------------------------- binding contract

    /// <summary>
    /// Binding must leave no placeholder behind, in ANY vendored case — waived and divergent ones
    /// included, because a corpus that grows an eighth placeholder has to fail loudly here rather
    /// than reach a loader that would ignore it as an unknown section (spec §12.7).
    /// </summary>
    [Theory]
    [MemberData(nameof(AllCases))]
    public void Binds_every_placeholder_in_the_case(string name) => Bind(Case(name));

    [Fact]
    public void Bindings_satisfy_the_spec_vocabulary_contract()
    {
        Assert.NotEqual(Bindings["$tool"], Bindings["$alias"]);
        Assert.NotEqual(Bindings["$rule1"], Bindings["$rule2"]);
        Assert.Contains(Bindings["$rule1"], DependablyExceptions.KnownRules);
        Assert.Contains(Bindings["$rule2"], DependablyExceptions.KnownRules);
        Assert.DoesNotContain(Bindings["$foreignRule"], DependablyExceptions.KnownRules);
        Assert.DoesNotContain(Bindings["$unknownRule"], DependablyExceptions.KnownRules);

        // §4 universal vocabulary plus nucheck's own keys: $foreignKey must be none of them.
        string[] nucheckKeys =
        [
            "rules", "exceptions", "exclude", "failOn",
            "allowedRegistryHosts", "allowedLocalFeeds", "ignoreUnusedPackages",
        ];
        Assert.DoesNotContain(Bindings["$foreignKey"], nucheckKeys);
    }

    // ---------------------------------------------------------------- binding

    /// <summary>
    /// Bind a vocabulary-bound case to nucheck's names, then prove nothing was left unbound. A
    /// tool-specific case (§12.1) carries literal vocabulary and is not substituted, but is still
    /// checked — a placeholder in one would be a corpus defect.
    /// </summary>
    private static JsonObject Bind(JsonObject caseDef)
    {
        var bindable = Tool(caseDef) == "$any";

        foreach (var subtree in BoundSubtrees)
        {
            if (caseDef[subtree] is not { } node)
            {
                continue;
            }

            if (bindable)
            {
                caseDef[subtree] = Substitute(node.DeepClone());
            }

            AssertFullyBound(Name(caseDef), subtree, caseDef[subtree]!);
        }

        return caseDef;
    }

    /// <summary>Whole-string replacement over both object keys and string values (spec §12.2).</summary>
    private static JsonNode? Substitute(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject obj:
                var bound = new JsonObject();
                foreach (var (key, value) in obj.ToList())
                {
                    obj.Remove(key);
                    bound[Bindings.TryGetValue(key, out var boundKey) ? boundKey : key] = Substitute(value);
                }

                return bound;

            case JsonArray array:
                var items = array.ToList();
                array.Clear();
                return new JsonArray(items.Select(Substitute).ToArray());

            case JsonValue value when value.TryGetValue<string>(out var text):
                return JsonValue.Create(Bindings.TryGetValue(text, out var boundValue) ? boundValue : text);

            default:
                return node;
        }
    }

    private static void AssertFullyBound(string caseName, string subtree, JsonNode node)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var (key, value) in obj)
                {
                    Reject(caseName, subtree, key);
                    if (value is not null)
                    {
                        AssertFullyBound(caseName, subtree, value);
                    }
                }

                break;

            case JsonArray array:
                foreach (var item in array)
                {
                    if (item is not null)
                    {
                        AssertFullyBound(caseName, subtree, item);
                    }
                }

                break;

            case JsonValue value when value.TryGetValue<string>(out var text):
                Reject(caseName, subtree, text);
                break;

            default:
                break;
        }
    }

    private static void Reject(string caseName, string subtree, string text)
    {
        // §12.3: `$schema` is a configuration key, not a placeholder, and is never bound.
        if (text.StartsWith('$') && text != "$schema")
        {
            throw new InvalidOperationException(
                $"case \"{caseName}\" still carries the unbound placeholder \"{text}\" in `{subtree}`. Bind it " +
                "in ConformanceTests.Bindings — an unbound $tool becomes an unknown top-level section that " +
                "§3.5 requires be ignored silently, so the case would pass while asserting nothing.");
        }
    }

    // ---------------------------------------------------------------- replay

    private void Replay(JsonObject caseDef)
    {
        Materialize(caseDef);

        var startDir = _root;
        if (caseDef["startDir"] is JsonValue sd && sd.TryGetValue<string>(out var relativeStart))
        {
            startDir = Path.Combine(_root, relativeStart.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(startDir);
        }

        string? explicitPath = null;
        if (caseDef["cli"]?["config"] is JsonValue cfg && cfg.TryGetValue<string>(out var relativeConfig))
        {
            explicitPath = Path.Combine(_root, relativeConfig.Replace('/', Path.DirectorySeparatorChar));
        }

        DependablyCheckConfig? config = null;
        DependablyConfigException? error = null;
        try
        {
            config = DependablyCheckConfig.Load(explicitPath, startDir);
        }
        catch (DependablyConfigException ex)
        {
            error = ex;
        }

        var expect = caseDef["expect"] as JsonObject ?? [];

        if (expect.TryGetPropertyValue("error", out var expectedError))
        {
            if (expectedError is JsonValue e && e.TryGetValue<string>(out var code))
            {
                Assert.NotNull(error);
                Assert.Equal(code, error.Code);
                return;
            }

            Assert.Null(error);
        }

        if (error is not null)
        {
            throw error;    // an unexpected throw is the case failing, reported as itself
        }

        Assert.NotNull(config);
        AssertSelectedFile(expect, startDir);

        var run = ApplyFindings(caseDef, config);
        AssertWarnings(expect, config, run);

        if (expect["resolved"] is JsonObject resolved)
        {
            AssertResolved(resolved, config);
        }

        AssertFindingAxes(expect, run);
    }

    /// <summary>Write the case's <c>files</c> into the throwaway repo, verbatim.</summary>
    private void Materialize(JsonObject caseDef)
    {
        var files = caseDef["files"] as JsonObject ?? [];
        foreach (var (relative, content) in files)
        {
            var target = Path.Combine(_root, relative.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.WriteAllText(
                target, content?.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) ?? "null");
        }
    }

    private void AssertSelectedFile(JsonObject expect, string startDir)
    {
        if (expect["selectedFile"] is not JsonValue sf || !sf.TryGetValue<string>(out var expected))
        {
            return;
        }

        // Load does not surface the file it picked, so the assertion goes through the same
        // Discover() the loader itself calls rather than re-deriving the walk-up here.
        var discovered = DependablyCheckConfig.Discover(startDir);
        Assert.NotNull(discovered);
        Assert.Equal(expected, Path.GetRelativePath(_root, discovered).Replace('\\', '/'));
    }

    private static void AssertWarnings(JsonObject expect, DependablyCheckConfig config, FindingRun? run)
    {
        if (expect["warnings"] is not JsonArray expected)
        {
            return;
        }

        var codes = config.Warnings.Select(w => w.Code).ToList();
        if (run is not null)
        {
            codes.AddRange(Enumerable.Repeat("UNUSED_EXCEPTION", run.UnusedIndexes.Count));
            codes.AddRange(Enumerable.Repeat("EXPIRED_EXCEPTION", run.ExpiredIndexes.Count));
        }

        Assert.Equal(
            expected.Select(n => (string)n!).Distinct().OrderBy(x => x, StringComparer.Ordinal),
            codes.Distinct().OrderBy(x => x, StringComparer.Ordinal));
    }

    private static void AssertResolved(JsonObject resolved, DependablyCheckConfig config)
    {
        if (resolved["rules"] is JsonObject rules)
        {
            foreach (var (ruleId, entry) in rules)
            {
                var (severity, options) = SplitRuleEntry(entry!);
                Assert.True(config.RuleSeverities.TryGetValue(ruleId, out var actual),
                    $"rule \"{ruleId}\" was not resolved");
                Assert.Equal(severity, actual);
                Assert.True(options.Count == 0,
                    $"case pins rule options for \"{ruleId}\"; nucheck accepts a rules options object but " +
                    "stores nothing from it, so the assertion cannot be made honestly.");
            }
        }

        if (resolved["allowedRegistryHosts"] is JsonArray hosts)
        {
            Assert.Equal(hosts.Select(n => (string)n!), config.AllowedRegistryHosts);
        }

        // Last, so a case pinning several list keys reports the one nucheck CAN express first.
        if (resolved["exclude"] is not null)
        {
            Assert.Fail("case pins `exclude`, which DependablyCheckConfig does not surface at all.");
        }

        if (resolved["failOn"] is JsonObject failOn)
        {
            if (failOn["severity"] is JsonValue sev && sev.TryGetValue<string>(out var level))
            {
                // §4.2: a ladder word and its aliases denote the same gate level, and nucheck stores
                // the canonical ladder word — so compare levels, not spellings.
                Assert.Equal(LadderLevel(level), config.FailOnSeverity);
            }

            if (failOn["count"] is JsonValue count && count.TryGetValue<int>(out var expected))
            {
                Assert.Equal(expected, config.FailOnCount);
            }
        }
    }

    private static void AssertFindingAxes(JsonObject expect, FindingRun? run)
    {
        if (expect["suppressedFindings"] is JsonArray suppressed)
        {
            Assert.NotNull(run);
            Assert.Equal(suppressed.Select(n => (int)n!).Order(), run.SuppressedIndexes.Order());
        }

        if (expect["unusedExceptions"] is JsonArray unused)
        {
            Assert.NotNull(run);
            Assert.Equal(unused.Select(n => (int)n!).Order(), run.UnusedIndexes.Order());
        }

        if (expect["expiredExceptions"] is JsonArray expired)
        {
            Assert.NotNull(run);
            Assert.Equal(expired.Select(n => (int)n!).Order(), run.ExpiredIndexes.Order());
        }

        if (expect["gated"] is JsonValue gated && gated.TryGetValue<bool>(out var expectedGate))
        {
            Assert.NotNull(run);
            Assert.Equal(expectedGate, run.Gated);
        }
    }

    /// <summary>The spec §4.2 finding-severity ladder, including the two mandatory aliases.</summary>
    private static string LadderLevel(string raw) => raw switch
    {
        "error" => Severity.High,
        "warning" or "warn" => Severity.Moderate,
        _ => Severity.ParseLevel(raw)
             ?? throw new InvalidOperationException(
                 $"case pins failOn.severity \"{raw}\", which is not on the §4.2 ladder"),
    };

    private static (string Severity, JsonObject Options) SplitRuleEntry(JsonNode entry) =>
        entry is JsonArray array
            ? (array[0]!.GetValue<string>(), array.Count > 1 ? (JsonObject)array[1]!.DeepClone() : [])
            : (entry.GetValue<string>(), []);

    // ---------------------------------------------------------------- findings

    private sealed record FindingRun(
        IReadOnlyList<int> SuppressedIndexes,
        IReadOnlyList<int> UnusedIndexes,
        IReadOnlyList<int> ExpiredIndexes,
        bool Gated);

    /// <summary>
    /// Feed the case's synthetic findings to the REAL <see cref="ExceptionApplier"/> using the
    /// exceptions the loader resolved and the case's fixed clock, then ask the REAL
    /// <see cref="AuditResult.GateTrips"/> whether the run would fail.
    /// </summary>
    private static FindingRun? ApplyFindings(JsonObject caseDef, DependablyCheckConfig config)
    {
        if (caseDef["findings"] is not JsonArray findings)
        {
            return null;
        }

        var mapped = findings.Select(f => Map((JsonObject)f!)).ToList();
        Assert.Equal(mapped.Count, mapped.Select(m => m.Identity).Distinct(StringComparer.Ordinal).Count());

        DateOnly? today = caseDef["today"] is JsonValue t && t.TryGetValue<string>(out var raw)
            ? DateOnly.ParseExact(raw, "yyyy-MM-dd", CultureInfo.InvariantCulture)
            : null;

        var result = ExceptionApplier.Apply(
            mapped.Where(m => m.Vulnerability is not null).Select(m => m.Vulnerability!).ToList(),
            mapped.Where(m => m.Unused is not null).Select(m => m.Unused!).ToList(),
            mapped.Where(m => m.Unverifiable is not null).Select(m => m.Unverifiable!).ToList(),
            config.Exceptions,
            today,
            mapped.Where(m => m.Pinned is not null).Select(m => m.Pinned!).ToList());

        var survivors = new HashSet<string>(
            result.Vulnerabilities
                .SelectMany(v => v.Advisories.Select(a => Identity(v.Id, v.Version, a.AdvisoryId)))
                .Concat(result.UnusedPackages.Select(u => Identity(u.Id, null, null)))
                .Concat(result.UnverifiableAdvisories.Select(u => Identity(u.PackageId, null, u.AdvisoryId)))
                .Concat(result.PinnedVersionFindings.Select(p => Identity(p.Id, p.RawVersion, null))),
            StringComparer.Ordinal);

        var suppressed = mapped
            .Select((m, index) => (m.Identity, index))
            .Where(x => !survivors.Contains(x.Identity))
            .Select(x => x.index)
            .ToList();

        var gated = new AuditResult
        {
            Vulnerabilities = result.Vulnerabilities,
            UnusedPackages = result.UnusedPackages,
            UnverifiableAdvisories = result.UnverifiableAdvisories,
            PinnedVersionFindings = result.PinnedVersionFindings,
        }.GateTrips(config.FailOnSeverity, config.FailOnCount);

        return new FindingRun(
            suppressed,
            NoticeIndexes(config, result, unused: true),
            NoticeIndexes(config, result, unused: false),
            gated);
    }

    /// <summary>
    /// Recover which resolved exceptions the applier reported as unused / expired. The applier
    /// surfaces them as operator-facing notices rather than as lists, so match the exact text it
    /// emits for a given entry.
    /// </summary>
    private static IReadOnlyList<int> NoticeIndexes(
        DependablyCheckConfig config, ExceptionApplier.Result result, bool unused)
    {
        var notices = new HashSet<string>(result.Notices, StringComparer.Ordinal);
        return config.Exceptions
            .Select((ex, index) => (ex, index))
            .Where(x => notices.Contains(unused
                ? $"unused exception for rule \"{x.ex.Rule}\" — {x.ex.Reason}"
                : $"exception expired {x.ex.Expires:yyyy-MM-dd} for rule \"{x.ex.Rule}\" — {x.ex.Reason}"))
            .Select(x => x.index)
            .ToList();
    }

    private sealed record MappedFinding(
        string Identity,
        PackageVulnerability? Vulnerability = null,
        UnusedPackageFinding? Unused = null,
        UnverifiableAdvisoryFinding? Unverifiable = null,
        PinnedVersionFinding? Pinned = null);

    private static string Identity(string package, string? version, string? id) => $"{package}|{version}|{id}";

    /// <summary>
    /// Turn a corpus finding into the nucheck model its rule id produces. Synthetic advisories carry
    /// <c>critical</c> severity so any survivor trips any <c>failOn.severity</c>: the corpus puts no
    /// severity on a finding, and the axis these cases pin is whether an exception suppressed it,
    /// not how a severity word maps onto the ladder.
    /// </summary>
    private static MappedFinding Map(JsonObject finding)
    {
        string? Str(string key) => finding[key] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

        foreach (var unsupported in new[] { "path", "symbol" })
        {
            Assert.True(Str(unsupported) is null,
                $"corpus finding carries a `{unsupported}` selector, which no nucheck finding does — " +
                "replaying it would silently assert nothing.");
        }

        var (package, version) = SplitPackage(Str("package"));
        var id = Str("id");

        return Str("rule") switch
        {
            "vulnerable-package" => new MappedFinding(
                Identity(package, version, id),
                Vulnerability: new PackageVulnerability(
                    package, version ?? "0.0.0", [new Advisory("synthetic", Severity.Critical, "*", [], AdvisoryId: id)])),
            "unused-packages" => new MappedFinding(
                Identity(package, null, null), Unused: new UnusedPackageFinding(package, "synthetic")),
            "unverifiable-advisory" => new MappedFinding(
                Identity(package, null, id), Unverifiable: new UnverifiableAdvisoryFinding(package, "*", id)),
            "pinned-versions" => new MappedFinding(
                Identity(package, version, null), Pinned: new PinnedVersionFinding(package, version, "synthetic", "synthetic")),
            _ => throw new InvalidOperationException(
                $"corpus finding for package \"{package}\" names rule \"{Str("rule")}\", which nucheck neither " +
                "emits nor suppresses; map it in ConformanceTests.Map or waive the case."),
        };
    }

    private static (string Name, string? Version) SplitPackage(string? package)
    {
        if (package is null)
        {
            return (string.Empty, null);
        }

        var at = package.LastIndexOf('@');
        return at > 0 ? (package[..at], package[(at + 1)..]) : (package, null);
    }
}
