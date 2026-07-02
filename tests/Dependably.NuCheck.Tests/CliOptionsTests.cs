using Dependably.NuCheck.Cli;

namespace Dependably.NuCheck.Tests;

public class CliOptionsTests
{
    [Fact]
    public void Parse_reads_path_and_defaults()
    {
        var options = CliOptions.Parse(["./packages.config"]);

        Assert.Equal("./packages.config", options.FilePath);
        Assert.Equal("human", options.Format);
        Assert.Null(options.Severity);
        Assert.False(options.UseRest);
        Assert.False(options.Verbose);
        Assert.False(options.ShowHelp);
    }

    [Fact]
    public void Parse_reads_value_and_bool_flags()
    {
        var options = CliOptions.Parse(
            ["./p.config", "--format", "json", "--severity", "high", "--rest", "--verbose"]);

        Assert.Equal("./p.config", options.FilePath);
        Assert.Equal("json", options.Format);
        Assert.Equal("high", options.Severity);
        Assert.True(options.UseRest);
        Assert.True(options.Verbose);
    }

    [Theory]
    [InlineData("--help")]
    [InlineData("-h")]
    public void Parse_recognises_help(string flag)
    {
        Assert.True(CliOptions.Parse([flag]).ShowHelp);
    }

    [Fact]
    public void Parse_recognises_version()
    {
        var options = CliOptions.Parse(["--version"]);
        Assert.True(options.ShowVersion);
        Assert.False(options.ShowHelp);
        Assert.Null(options.Error);
    }

    [Fact]
    public void Parse_value_flag_at_end_of_list_is_usage_error()
    {
        // A value flag at the end of the argument list has no following value: this is a
        // usage error, not a silent no-op (the flag keeps its default, but Error is set).
        var options = CliOptions.Parse(["--format"]);

        Assert.NotNull(options.Error);
        Assert.Contains("--format", options.Error);
        Assert.Equal("human", options.Format); // default unchanged
    }

    [Theory]
    [InlineData("--severity")]
    [InlineData("--source")]
    [InlineData("--config")]
    [InlineData("--fail-on")]
    public void Parse_every_value_flag_at_end_of_list_is_usage_error(string flag)
    {
        var options = CliOptions.Parse([flag]);

        Assert.NotNull(options.Error);
        Assert.Contains(flag, options.Error);
    }

    [Fact]
    public void Parse_keeps_only_first_positional_as_path()
    {
        var options = CliOptions.Parse(["first.config", "second.config"]);
        Assert.Equal("first.config", options.FilePath);
    }

    [Fact]
    public void Parse_reads_config_path()
    {
        var options = CliOptions.Parse(["./p.config", "--config", "./.dependably-check"]);

        Assert.Equal("./.dependably-check", options.ConfigPath);
    }

    [Fact]
    public void Parse_config_defaults_to_null()
    {
        Assert.Null(CliOptions.Parse(["./p.config"]).ConfigPath);
    }

    [Fact]
    public void Parse_clean_args_have_no_error()
    {
        Assert.Null(CliOptions.Parse(["./p.config", "--format", "json", "--verbose"]).Error);
    }

    [Theory]
    [InlineData("--bogus")]
    [InlineData("-x")]
    [InlineData("--formatt")] // typo of --format
    public void Parse_rejects_unknown_flag(string flag)
    {
        // Previously an unrecognized -/-- token was silently ignored. It is now a usage
        // error so a typo cannot pass unnoticed and exit 0.
        var options = CliOptions.Parse(["./p.config", flag]);

        Assert.NotNull(options.Error);
        Assert.Contains(flag, options.Error);
        Assert.Equal("./p.config", options.FilePath); // positional path is still captured
    }

    [Fact]
    public void Parse_unknown_flag_does_not_consume_following_value()
    {
        // A bogus flag must not swallow the manifest path that follows it.
        var options = CliOptions.Parse(["--bogus", "./p.config"]);

        Assert.NotNull(options.Error);
        Assert.Equal("./p.config", options.FilePath);
    }

    [Fact]
    public void Parse_reports_first_unknown_flag()
    {
        var options = CliOptions.Parse(["./p.config", "--first-bad", "--second-bad"]);

        Assert.Contains("--first-bad", options.Error);
    }

    [Fact]
    public void Parse_fail_on_defaults_to_null()
    {
        var options = CliOptions.Parse(["./p.config"]);

        Assert.Null(options.FailOnSeverity);
        Assert.Null(options.FailOnCount);
        Assert.Null(options.Error);
    }

    [Theory]
    [InlineData("critical", "critical")]
    [InlineData("high", "high")]
    [InlineData("moderate", "moderate")]
    [InlineData("medium", "moderate")]  // alias normalised onto the ladder
    [InlineData("low", "low")]
    [InlineData("info", "info")]
    [InlineData("HIGH", "high")]        // case-insensitive
    public void Parse_fail_on_severity_sets_gate_level(string value, string expected)
    {
        var options = CliOptions.Parse(["./p.config", "--fail-on", $"severity={value}"]);

        Assert.Null(options.Error);
        Assert.Equal(expected, options.FailOnSeverity);
        Assert.Null(options.FailOnCount);
    }

    [Theory]
    [InlineData("0", 0)]
    [InlineData("5", 5)]
    public void Parse_fail_on_count_sets_gate_count(string value, int expected)
    {
        var options = CliOptions.Parse(["./p.config", "--fail-on", $"count={value}"]);

        Assert.Null(options.Error);
        Assert.Equal(expected, options.FailOnCount);
        Assert.Null(options.FailOnSeverity);
    }

    [Fact]
    public void Parse_fail_on_is_repeatable()
    {
        var options = CliOptions.Parse(
            ["./p.config", "--fail-on", "severity=high", "--fail-on", "count=3"]);

        Assert.Null(options.Error);
        Assert.Equal("high", options.FailOnSeverity);
        Assert.Equal(3, options.FailOnCount);
    }

    [Theory]
    [InlineData("severity=bogus")]   // not a ladder word
    [InlineData("severity=")]        // missing value
    [InlineData("count=-1")]         // negative
    [InlineData("count=abc")]        // not a number
    [InlineData("count=")]           // missing value
    [InlineData("warnings=5")]       // unknown key
    [InlineData("nokey")]            // no '='
    public void Parse_fail_on_bad_value_is_usage_error(string spec)
    {
        var options = CliOptions.Parse(["./p.config", "--fail-on", spec]);

        Assert.NotNull(options.Error);
        Assert.Contains("--fail-on", options.Error);
    }
}
