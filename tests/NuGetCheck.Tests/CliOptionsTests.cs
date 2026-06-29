using NuGetCheck.Cli;

namespace NuGetCheck.Tests;

public class CliOptionsTests
{
    [Fact]
    public void Parse_reads_path_and_defaults()
    {
        var options = CliOptions.Parse(["./packages.config"]);

        Assert.Equal("./packages.config", options.FilePath);
        Assert.Equal("summary", options.Format);
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
    public void Parse_ignores_value_flag_without_argument()
    {
        var options = CliOptions.Parse(["--format"]);
        Assert.Equal("summary", options.Format);
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
}
