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
}
