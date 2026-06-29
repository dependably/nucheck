using NuGetCheck.Services;

namespace NuGetCheck.Tests;

public class UnusedPackageServiceTests
{
    // -----------------------------------------------------------------
    // Core overload (pure, no disk access)
    // -----------------------------------------------------------------

    [Fact]
    public void Core_flags_package_with_no_namespace_usage()
    {
        var findings = UnusedPackageService.Check(
            directPackageIds: ["Newtonsoft.Json"],
            namespaceUsages: new HashSet<string>(),
            ignoredPackages: []);

        var finding = Assert.Single(findings);
        Assert.Equal("Newtonsoft.Json", finding.Id);
        Assert.Contains("heuristic", finding.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Core_does_not_flag_package_whose_namespace_is_used_exactly()
    {
        var findings = UnusedPackageService.Check(
            directPackageIds: ["Newtonsoft.Json"],
            namespaceUsages: new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Newtonsoft.Json" },
            ignoredPackages: []);

        Assert.Empty(findings);
    }

    [Fact]
    public void Core_does_not_flag_package_whose_sub_namespace_is_used()
    {
        // A `using Newtonsoft.Json.Linq;` line should satisfy the check for `Newtonsoft.Json`.
        var findings = UnusedPackageService.Check(
            directPackageIds: ["Newtonsoft.Json"],
            namespaceUsages: new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Newtonsoft.Json.Linq" },
            ignoredPackages: []);

        Assert.Empty(findings);
    }

    [Fact]
    public void Core_ignore_list_suppresses_finding()
    {
        var findings = UnusedPackageService.Check(
            directPackageIds: ["StyleCop.Analyzers"],
            namespaceUsages: new HashSet<string>(),
            ignoredPackages: ["StyleCop.Analyzers"]);

        Assert.Empty(findings);
    }

    [Fact]
    public void Core_ignore_list_is_case_insensitive()
    {
        var findings = UnusedPackageService.Check(
            directPackageIds: ["StyleCop.Analyzers"],
            namespaceUsages: new HashSet<string>(),
            ignoredPackages: ["stylecop.analyzers"]);

        Assert.Empty(findings);
    }

    [Fact]
    public void Core_flags_only_packages_missing_from_usages()
    {
        // Mixed: one used, one not.
        var findings = UnusedPackageService.Check(
            directPackageIds: ["Newtonsoft.Json", "Serilog"],
            namespaceUsages: new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Newtonsoft.Json" },
            ignoredPackages: []);

        var finding = Assert.Single(findings);
        Assert.Equal("Serilog", finding.Id);
    }

    [Fact]
    public void Core_empty_package_list_produces_no_findings()
    {
        var findings = UnusedPackageService.Check(
            directPackageIds: [],
            namespaceUsages: new HashSet<string>(),
            ignoredPackages: []);

        Assert.Empty(findings);
    }

    [Fact]
    public void Core_partial_failure_scenario_mixed_used_unused_ignored()
    {
        // Three packages: one used, one unused, one suppressed.
        var findings = UnusedPackageService.Check(
            directPackageIds: ["Used.Pkg", "Unused.Pkg", "Ignored.Pkg"],
            namespaceUsages: new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Used.Pkg" },
            ignoredPackages: ["Ignored.Pkg"]);

        // Only the unused, non-ignored package should be reported.
        var finding = Assert.Single(findings);
        Assert.Equal("Unused.Pkg", finding.Id);
    }

    // -----------------------------------------------------------------
    // Disk-based overload (temp directories)
    // -----------------------------------------------------------------

    private static string NewTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"unused-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Fact]
    public void Disk_no_csproj_produces_no_findings()
    {
        var dir = NewTempDir();
        try
        {
            // No .csproj → nothing to check.
            var findings = UnusedPackageService.Check(dir, []);
            Assert.Empty(findings);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_detects_package_referenced_via_using_directive()
    {
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
                    <PackageReference Include="Serilog" Version="3.0.0" />
                  </ItemGroup>
                </Project>
                """);

            // Source file uses Newtonsoft.Json but NOT Serilog.
            File.WriteAllText(Path.Combine(dir, "Program.cs"), """
                using Newtonsoft.Json;
                var x = JsonConvert.SerializeObject(new { });
                """);

            var findings = UnusedPackageService.Check(dir, []);

            var finding = Assert.Single(findings);
            Assert.Equal("Serilog", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_suppression_via_ignore_list()
    {
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="StyleCop.Analyzers" Version="1.2.0" />
                  </ItemGroup>
                </Project>
                """);

            File.WriteAllText(Path.Combine(dir, "Class.cs"), "public class C { }");

            var findings = UnusedPackageService.Check(dir, ["StyleCop.Analyzers"]);
            Assert.Empty(findings);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_bin_and_obj_cs_files_are_excluded()
    {
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.Bar" Version="1.0.0" />
                  </ItemGroup>
                </Project>
                """);

            // Place a .cs file with the using in obj/ — must be excluded.
            var objDir = Path.Combine(dir, "obj");
            Directory.CreateDirectory(objDir);
            File.WriteAllText(Path.Combine(objDir, "Generated.cs"), "using Foo.Bar;");

            var findings = UnusedPackageService.Check(dir, []);

            // The obj/ file must not count; package should still be flagged.
            var finding = Assert.Single(findings);
            Assert.Equal("Foo.Bar", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_reads_Directory_Packages_props()
    {
        var dir = NewTempDir();
        try
        {
            // Central package management: versions in Directory.Packages.props,
            // but no *.csproj present in this temp tree.
            File.WriteAllText(Path.Combine(dir, "Directory.Packages.props"), """
                <Project>
                  <ItemGroup>
                    <PackageReference Include="Central.Pkg" />
                  </ItemGroup>
                </Project>
                """);

            // No .cs files → package should be flagged as unused.
            var findings = UnusedPackageService.Check(dir, []);

            var finding = Assert.Single(findings);
            Assert.Equal("Central.Pkg", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
