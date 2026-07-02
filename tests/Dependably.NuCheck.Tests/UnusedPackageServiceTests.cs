using Dependably.NuCheck.Services;

namespace Dependably.NuCheck.Tests;

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
    public void Disk_PrivateAssets_all_reference_is_not_flagged()
    {
        // A PrivateAssets="all" reference does not flow to consumers and has no runtime
        // namespace — flagging it as unused is a false positive, so it must be excluded.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.BuildTool" Version="1.0.0" PrivateAssets="all" />
                  </ItemGroup>
                </Project>
                """);

            File.WriteAllText(Path.Combine(dir, "Class.cs"), "public class C { }");

            var findings = UnusedPackageService.Check(dir, []);
            Assert.Empty(findings);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_PrivateAssets_all_child_element_is_not_flagged()
    {
        // Same exclusion, but expressed as a child <PrivateAssets> element.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.BuildTool" Version="1.0.0">
                      <PrivateAssets>all</PrivateAssets>
                    </PackageReference>
                  </ItemGroup>
                </Project>
                """);

            File.WriteAllText(Path.Combine(dir, "Class.cs"), "public class C { }");

            var findings = UnusedPackageService.Check(dir, []);
            Assert.Empty(findings);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_analyzer_only_IncludeAssets_reference_is_not_flagged()
    {
        // IncludeAssets limited to analyzer/build assets (no runtime/compile) — no namespace.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Some.Tooling" Version="1.0.0"
                      IncludeAssets="analyzers; build; buildtransitive" />
                  </ItemGroup>
                </Project>
                """);

            File.WriteAllText(Path.Combine(dir, "Class.cs"), "public class C { }");

            var findings = UnusedPackageService.Check(dir, []);
            Assert.Empty(findings);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_known_analyzer_id_without_PrivateAssets_is_not_flagged()
    {
        // StyleCop.Analyzers is on the built-in allowlist; an author may add it WITHOUT
        // PrivateAssets metadata, and it still must not be flagged (no ignore list needed).
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

            var findings = UnusedPackageService.Check(dir, []);
            Assert.Empty(findings);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_known_analyzer_suffix_without_PrivateAssets_is_not_flagged()
    {
        // Any id ending in `.Analyzers` / `.SourceGenerators` is treated as build/analyzer.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Contoso.SourceGenerators" Version="2.0.0" />
                  </ItemGroup>
                </Project>
                """);

            File.WriteAllText(Path.Combine(dir, "Class.cs"), "public class C { }");

            var findings = UnusedPackageService.Check(dir, []);
            Assert.Empty(findings);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_normal_unused_package_is_still_flagged()
    {
        // A genuine runtime package with no namespace usage and no dev/build markers must
        // STILL be flagged — the exclusions must not silence real findings.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
                  </ItemGroup>
                </Project>
                """);

            File.WriteAllText(Path.Combine(dir, "Class.cs"), "public class C { }");

            var findings = UnusedPackageService.Check(dir, []);

            var finding = Assert.Single(findings);
            Assert.Equal("Newtonsoft.Json", finding.Id);
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

    // ---- #14: ExcludeAssets exclusion paths -------------------------------------

    [Fact]
    public void Disk_ExcludeAssets_runtime_reference_is_not_flagged()
    {
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.RuntimeExcluded" Version="1.0.0" ExcludeAssets="runtime" />
                  </ItemGroup>
                </Project>
                """);

            File.WriteAllText(Path.Combine(dir, "Class.cs"), "public class C { }");

            var findings = UnusedPackageService.Check(dir, []);
            Assert.Empty(findings);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_ExcludeAssets_compile_reference_is_not_flagged()
    {
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.CompileExcluded" Version="1.0.0" ExcludeAssets="compile" />
                  </ItemGroup>
                </Project>
                """);

            File.WriteAllText(Path.Combine(dir, "Class.cs"), "public class C { }");

            var findings = UnusedPackageService.Check(dir, []);
            Assert.Empty(findings);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_ExcludeAssets_all_reference_is_not_flagged()
    {
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.AllExcluded" Version="1.0.0" ExcludeAssets="all" />
                  </ItemGroup>
                </Project>
                """);

            File.WriteAllText(Path.Combine(dir, "Class.cs"), "public class C { }");

            var findings = UnusedPackageService.Check(dir, []);
            Assert.Empty(findings);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // ---- #19 / #52 (consolidated): global using, using static, qualified name --

    [Fact]
    public void Disk_global_using_directive_marks_package_as_used()
    {
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
                  </ItemGroup>
                </Project>
                """);

            // 'global using' form (C# 10+) — the UsingDirectivePattern optional group.
            File.WriteAllText(Path.Combine(dir, "GlobalUsings.cs"), "global using Newtonsoft.Json;");

            var findings = UnusedPackageService.Check(dir, []);
            Assert.Empty(findings);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_using_static_directive_marks_package_as_used()
    {
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
                  </ItemGroup>
                </Project>
                """);

            // 'using static' form — the UsingDirectivePattern optional group.
            File.WriteAllText(Path.Combine(dir, "Program.cs"), "using static Newtonsoft.Json.JsonConvert;");

            var findings = UnusedPackageService.Check(dir, []);
            Assert.Empty(findings);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_qualified_name_reference_marks_package_as_used()
    {
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
                  </ItemGroup>
                </Project>
                """);

            // No 'using' directive — only a fully-qualified reference.
            // QualifiedNamePattern must pick up "Newtonsoft.Json" from the dotted expression.
            File.WriteAllText(Path.Combine(dir, "Program.cs"), "var s = Newtonsoft.Json.JsonConvert.SerializeObject(new { });");

            var findings = UnusedPackageService.Check(dir, []);
            Assert.Empty(findings);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
