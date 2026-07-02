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

    // --- Ticket #9: ExcludeAssets="runtime" must not suppress compile-available packages ---

    [Fact]
    public void Disk_ExcludeAssets_runtime_only_package_is_still_scanned_and_flagged()
    {
        // ExcludeAssets="runtime" keeps the compile-time reference assembly: the package's
        // types are fully available via `using` directives. If no usage exists it IS unused.
        // Before the fix, this package was silently dropped from the scan (false negative).
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.Abstractions" Version="2.0.0"
                      ExcludeAssets="runtime" />
                  </ItemGroup>
                </Project>
                """);

            File.WriteAllText(Path.Combine(dir, "Class.cs"), "public class C { }");

            var findings = UnusedPackageService.Check(dir, []);

            var finding = Assert.Single(findings);
            Assert.Equal("Foo.Abstractions", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_ExcludeAssets_runtime_mixed_packages_partial_failure()
    {
        // Mixed batch: runtime-excluded unused, compile-excluded (suppressed), and normal used.
        // Only the runtime-excluded package with no usage should be flagged.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.Abstractions" Version="2.0.0"
                      ExcludeAssets="runtime" />
                    <PackageReference Include="Bar.BuildOnly" Version="1.0.0"
                      ExcludeAssets="compile" />
                    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
                  </ItemGroup>
                </Project>
                """);

            // Only Newtonsoft.Json is actually used in source.
            File.WriteAllText(Path.Combine(dir, "Class.cs"), "using Newtonsoft.Json;");

            var findings = UnusedPackageService.Check(dir, []);

            // Foo.Abstractions: runtime-excluded, but compile is available and not used → flagged.
            // Bar.BuildOnly: compile-excluded, no namespace flows in → suppressed.
            // Newtonsoft.Json: used via `using` → not flagged.
            var finding = Assert.Single(findings);
            Assert.Equal("Foo.Abstractions", finding.Id);
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

    // --- Ticket #24: Directory.Packages.props PackageVersion (CPM) detection ----------

    [Fact]
    public void Disk_CPM_PackageVersion_orphan_is_detected()
    {
        // Standard CPM: Directory.Packages.props uses <PackageVersion>, projects use
        // <PackageReference> without a version. A PackageVersion with no matching
        // PackageReference anywhere is an orphaned central declaration.
        // Before the fix, PackageVersion was invisible to the scan (false negative).
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "Directory.Packages.props"), """
                <Project>
                  <ItemGroup>
                    <PackageVersion Include="Orphaned.Pkg" Version="1.0.0" />
                  </ItemGroup>
                </Project>
                """);

            // No .csproj uses Orphaned.Pkg and no .cs file references it.
            var findings = UnusedPackageService.Check(dir, []);

            var finding = Assert.Single(findings);
            Assert.Equal("Orphaned.Pkg", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_CPM_PackageVersion_used_is_not_flagged()
    {
        // A CPM PackageVersion entry whose namespace appears in source must not be flagged.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "Directory.Packages.props"), """
                <Project>
                  <ItemGroup>
                    <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
                  </ItemGroup>
                </Project>
                """);

            File.WriteAllText(Path.Combine(dir, "Program.cs"), "using Newtonsoft.Json;");

            var findings = UnusedPackageService.Check(dir, []);
            Assert.Empty(findings);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_CPM_partial_failure_mixed_PackageVersion_orphaned_and_used()
    {
        // Mixed CPM batch: one orphaned PackageVersion, one used. Only the orphan fires.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "Directory.Packages.props"), """
                <Project>
                  <ItemGroup>
                    <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
                    <PackageVersion Include="Orphaned.Pkg" Version="1.0.0" />
                  </ItemGroup>
                </Project>
                """);

            File.WriteAllText(Path.Combine(dir, "Program.cs"), "using Newtonsoft.Json;");

            var findings = UnusedPackageService.Check(dir, []);

            var finding = Assert.Single(findings);
            Assert.Equal("Orphaned.Pkg", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // --- Ticket #46: comments, string literals, and namespace declarations must not
    //     count as package usage in the qualified-name secondary scan -------------------

    [Fact]
    public void Disk_package_id_only_in_line_comment_is_still_flagged()
    {
        // Before the fix: QualifiedNamePattern ran on raw content and matched
        // "Newtonsoft.Json" inside the comment, producing a false negative (no finding).
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

            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                "// TODO: replace Newtonsoft.Json with System.Text.Json\npublic class C { }");

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
    public void Disk_package_id_only_in_block_comment_is_still_flagged()
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

            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                "/* Newtonsoft.Json formerly used here */\npublic class C { }");

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
    public void Disk_package_id_only_in_string_literal_is_still_flagged()
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

            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                "public class C { string s = \"Newtonsoft.Json\"; }");

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
    public void Disk_package_id_only_in_namespace_declaration_is_still_flagged()
    {
        // A file declaring `namespace Foo.Bar;` must not mark package `Foo.Bar` as used.
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

            File.WriteAllText(Path.Combine(dir, "Ext.cs"), "namespace Foo.Bar;\npublic class Ext { }");

            var findings = UnusedPackageService.Check(dir, []);

            var finding = Assert.Single(findings);
            Assert.Equal("Foo.Bar", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_qualified_name_scan_partial_failure_real_usage_vs_comment_only()
    {
        // Mixed: one package used via a genuine qualified reference (no using directive),
        // one mentioned only in a comment. Only the comment-only package should be flagged.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Acme.Widgets" Version="1.0.0" />
                    <PackageReference Include="Acme.Gadgets" Version="1.0.0" />
                  </ItemGroup>
                </Project>
                """);

            // Acme.Widgets used via qualified name; Acme.Gadgets only in a comment.
            File.WriteAllText(Path.Combine(dir, "Class.cs"), """
                // We used to use Acme.Gadgets but switched.
                public class C
                {
                    Acme.Widgets.Widget w = new Acme.Widgets.Widget();
                }
                """);

            var findings = UnusedPackageService.Check(dir, []);

            var finding = Assert.Single(findings);
            Assert.Equal("Acme.Gadgets", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // --- Ticket #46: interpolated strings — code in {holes} must not be stripped ----------

    [Fact]
    public void Disk_package_used_only_in_interpolation_hole_is_not_flagged()
    {
        // Before the fix: $"...{Pkg.X()}..." was treated like a regular string and the
        // entire content (including the hole) was stripped, so Pkg was wrongly flagged unused.
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

            // The ONLY reference is inside an interpolation hole — must count as usage.
            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                "public class C { string s = $\"{Newtonsoft.Json.JsonConvert.SerializeObject(this)}\"; }");

            var findings = UnusedPackageService.Check(dir, []);

            // The package IS used (qualified reference in hole) — must not be flagged.
            Assert.Empty(findings);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_interpolation_hole_partial_failure_used_vs_unused()
    {
        // Mixed: one package used inside an interpolation hole, one genuinely unused.
        // Only the genuinely unused package should fire.
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

            // Newtonsoft.Json referenced in hole; Serilog not referenced at all.
            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                "public class C { string s = $\"{Newtonsoft.Json.JsonConvert.SerializeObject(this)}\"; }");

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
    public void Disk_raw_string_literal_trailing_code_is_not_stripped()
    {
        // Before the fix: the old SkipRegularString called on each individual '"' of the
        // """...""" delimiter misidentified the raw-string boundary when the content
        // contained a bare '"'. The extra SkipRegularString call then consumed the trailing
        // code on the same line, making Foo.Bar invisible and wrongly flagging it as unused.
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

            // Raw string literal with a bare " in the content, followed immediately by
            // code on the same line. The bare " caused the old code to consume the trailing
            // Foo.Bar.Helper.Run() call as part of the (phantom) string literal.
            // Outer delimiter is """" (4 quotes) so the inner """ is unambiguous.
            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                """"public class C { void M() { var r = """a " b"""; Foo.Bar.Helper.Run(r); } }"""");

            var findings = UnusedPackageService.Check(dir, []);

            // Foo.Bar IS used (qualified reference after the raw string) — must not be flagged.
            Assert.Empty(findings);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_verbatim_interpolated_string_hole_usage_is_not_flagged()
    {
        // @$"..." / $@"..." verbatim interpolated strings must also preserve hole content.
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

            // Package referenced ONLY inside a verbatim-interpolated string hole.
            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                @"public class C { string s = @$""{Newtonsoft.Json.JsonConvert.SerializeObject(this)}""; }");

            var findings = UnusedPackageService.Check(dir, []);

            Assert.Empty(findings);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // --- Ticket #24: CPM dev-only packages (PackageVersion) must not be reported ----------

    [Fact]
    public void Disk_CPM_PackageVersion_with_devonly_PackageReference_is_not_flagged()
    {
        // Probe from finding #24: a <PackageVersion> in Directory.Packages.props + a
        // <PackageReference PrivateAssets="all" ExcludeAssets="compile"> in the .csproj
        // must NOT be reported as unused — the dev-only csproj entry suppresses the CPM entry.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "Directory.Packages.props"), """
                <Project>
                  <ItemGroup>
                    <PackageVersion Include="Some.BuildTool" Version="2.0.0" />
                  </ItemGroup>
                </Project>
                """);

            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Some.BuildTool"
                      PrivateAssets="all" ExcludeAssets="compile" />
                  </ItemGroup>
                </Project>
                """);

            File.WriteAllText(Path.Combine(dir, "Class.cs"), "public class C { }");

            var findings = UnusedPackageService.Check(dir, []);

            // Some.BuildTool is dev-only — must not be flagged as unused.
            Assert.Empty(findings);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_CPM_devonly_partial_failure_suppressed_vs_genuinely_unused()
    {
        // Mixed CPM batch: one PackageVersion whose csproj PackageReference is dev-only
        // (suppressed), one PackageVersion with no csproj entry at all (genuinely unused).
        // Only the genuinely unused one should fire.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "Directory.Packages.props"), """
                <Project>
                  <ItemGroup>
                    <PackageVersion Include="Some.BuildTool" Version="2.0.0" />
                    <PackageVersion Include="Orphaned.Pkg" Version="1.0.0" />
                  </ItemGroup>
                </Project>
                """);

            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Some.BuildTool" PrivateAssets="all" />
                  </ItemGroup>
                </Project>
                """);

            File.WriteAllText(Path.Combine(dir, "Class.cs"), "public class C { }");

            var findings = UnusedPackageService.Check(dir, []);

            // Some.BuildTool is dev-only → suppressed. Orphaned.Pkg is genuinely unused → flagged.
            var finding = Assert.Single(findings);
            Assert.Equal("Orphaned.Pkg", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // --- Fix #46 follow-up: over-strip bugs in StripCommentsAndLiterals ----------------

    // Finding 1: $"" (empty interpolated string) was misidentified as a raw interpolated
    // string ($"""), causing SkipRawStringLiteral to eat all code that follows.

    [Fact]
    public void Disk_empty_interpolated_string_does_not_consume_trailing_code()
    {
        // Before the fix: $"" triggered the $"""...""" branch (only 2 quotes checked),
        // and SkipRawStringLiteral swallowed everything after it until the next "" run,
        // making Foo.Bar invisible and wrongly flagging it as unused.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.Bar" Version="1.0.0" />
                    <PackageReference Include="Serilog" Version="3.0.0" />
                  </ItemGroup>
                </Project>
                """);

            // $"" is an empty interpolated string; Foo.Bar is used in the code that follows.
            // Serilog is genuinely unused — only it should be flagged.
            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                "public class C { void M() { var s = $\"\"; Foo.Bar.Helper.Run(); } }");

            var findings = UnusedPackageService.Check(dir, []);

            // Foo.Bar IS used after $"" — must not be flagged; only Serilog is unused.
            var finding = Assert.Single(findings);
            Assert.Equal("Serilog", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // Finding 2: $"""…{hole}…""" — the hole code was discarded by the conservative skip,
    // so a package used only in a hole of an interpolated raw string was wrongly flagged.

    [Fact]
    public void Disk_interpolated_raw_string_hole_usage_is_not_flagged()
    {
        // Before the fix: SkipRawStringLiteral consumed $"""...""" wholesale (no hole
        // preservation), so a qualified name inside the hole was invisible to the scanner.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.Bar" Version="1.0.0" />
                    <PackageReference Include="Serilog" Version="3.0.0" />
                  </ItemGroup>
                </Project>
                """);

            // Foo.Bar used ONLY inside an interpolated raw string hole; Serilog not used.
            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                """"public class C { void M() { var s = $"""{Foo.Bar.Helper.Run()}"""; } }"""");

            var findings = UnusedPackageService.Check(dir, []);

            // Foo.Bar IS used (inside the raw string hole) — only Serilog should be flagged.
            var finding = Assert.Single(findings);
            Assert.Equal("Serilog", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // Finding 3: $"{$"{Foo.Bar()}"}" — nested interpolation loses the inner hole.
    // EmitInterpolatedHoleChar treated the inner $" as plain $ + regular string,
    // so the inner {Foo.Bar()} was stripped by SkipRegularString.

    [Fact]
    public void Disk_nested_interpolated_string_hole_usage_is_not_flagged()
    {
        // Before the fix: inside an outer hole, $"..." was processed as bare $ (emitted)
        // followed by SkipRegularString, discarding the inner hole's code entirely.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.Bar" Version="1.0.0" />
                    <PackageReference Include="Serilog" Version="3.0.0" />
                  </ItemGroup>
                </Project>
                """);

            // Foo.Bar used ONLY inside a nested interpolation hole; Serilog not used.
            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                """"public class C { void M() { var s = $"{$"{Foo.Bar.Run()}"}"; } }"""");

            var findings = UnusedPackageService.Check(dir, []);

            // Foo.Bar IS used (inside the nested hole) — only Serilog should be flagged.
            var finding = Assert.Single(findings);
            Assert.Equal("Serilog", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // --- Review findings: additional over-strip bugs in StripCommentsAndLiterals ----------

    // Finding 1: char literals inside interpolation holes are unhandled.
    // EmitInterpolatedHoleChar did not route '\'' to SkipCharLiteral, so a char literal
    // such as '}' or '"' inside a hole desync'd hole depth or invoked SkipRegularString.

    [Fact]
    public void Disk_char_literal_closing_brace_in_hole_does_not_strip_usage()
    {
        // Before the fix: $"{ p.TrimEnd('}') + Foo.Bar.X.Run() }" caused the stripper
        // to emit the bare ' and then treat the } inside the char literal as the
        // hole-closing brace, stripping everything after it including Foo.Bar.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.Bar" Version="1.0.0" />
                    <PackageReference Include="Serilog" Version="3.0.0" />
                  </ItemGroup>
                </Project>
                """);

            // Foo.Bar used ONLY inside a hole that also contains a char literal with '}'.
            // The stripper must not treat that '}' as the hole-closing brace.
            // Serilog is genuinely unused — it must still be flagged.
            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                """public class C { void M(string p) { var s = $"{ p.TrimEnd('}') + Foo.Bar.X.Run() }"; } }""");

            var findings = UnusedPackageService.Check(dir, []);

            // Foo.Bar IS used (in the hole) — only Serilog should be flagged.
            var finding = Assert.Single(findings);
            Assert.Equal("Serilog", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // Finding 2: {{ inside an interpolation hole was misread as a literal-brace escape,
    // desyncing hole depth. The {{ / }} escape must only be applied at holeDepth == 0.

    [Fact]
    public void Disk_double_brace_in_hole_code_does_not_strip_usage()
    {
        // Before the fix: $"{ new int[,]{{1,2}}[0,0] + Foo.Bar.X.Run() }" caused
        // AdvanceInterpolatedOpenBrace to skip {{ unconditionally (even at holeDepth > 0),
        // which closed the hole early and stripped Foo.Bar as literal text.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.Bar" Version="1.0.0" />
                    <PackageReference Include="Serilog" Version="3.0.0" />
                  </ItemGroup>
                </Project>
                """);

            // Foo.Bar used ONLY in a hole whose code contains a 2D array initialiser
            // ({{...}}) — the inner {{ are real code braces, not literal-brace escapes.
            // Serilog is genuinely unused — it must still be flagged.
            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                """public class C { void M() { var s = $"{ new int[,]{{1,2}}[0,0] + Foo.Bar.X.Run() }"; } }""");

            var findings = UnusedPackageService.Check(dir, []);

            // Foo.Bar IS used (in the hole) — only Serilog should be flagged.
            var finding = Assert.Single(findings);
            Assert.Equal("Serilog", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // Finding 2 (regression guard): {{ at holeDepth == 0 (the literal-text portion) must
    // still be treated as a literal-brace escape so content inside it is NOT emitted as code.

    [Fact]
    public void Disk_double_brace_in_literal_portion_does_not_count_as_usage()
    {
        // After the finding-2 fix, {{ at holeDepth == 0 must still suppress content.
        // If the depth guard regressed, {{Foo.Bar.X.Run()}} would be emitted as hole
        // code and Foo.Bar would wrongly appear used.
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

            // The entire content of $"..." is in the literal-text portion ({{...}} escape,
            // no real interpolation hole), so Foo.Bar must NOT count as used.
            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                """public class C { void M() { var s = $"{{Foo.Bar.X.Run()}}"; } }""");

            var findings = UnusedPackageService.Check(dir, []);

            // Foo.Bar is NOT used (only in literal-text escape, not in a hole).
            var finding = Assert.Single(findings);
            Assert.Equal("Foo.Bar", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // --- Follow-up review findings: two remaining over-strips in EmitInterpolatedHoleChar ------

    // Review finding 1: EmitNestedInterpolatedString lacked a $$-branch. For a hole containing
    // $$"""{{Foo.Bar.X.Run()}}""" the first $ was emitted as bare code; the second $ dispatched
    // to SkipInterpolatedRawString as a single-dollar string, which treated {{ as a literal-brace
    // escape and stripped the hole content, wrongly flagging Foo.Bar as unused.

    [Fact]
    public void Disk_nested_multi_dollar_raw_string_in_outer_hole_usage_is_not_flagged()
    {
        // Before the fix: $"{ $$"""{{Foo.Bar.X.Run()}}""" }" — first $ emitted as plain code;
        // second $ routed to SkipInterpolatedRawString (single-dollar path), which treated {{ as
        // a literal-brace escape (holeDepth 0) and stripped all hole content. Foo.Bar wrongly
        // flagged unused.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.Bar" Version="1.0.0" />
                    <PackageReference Include="Serilog" Version="3.0.0" />
                  </ItemGroup>
                </Project>
                """);

            // Foo.Bar used ONLY inside $$"""{{…}}""" nested in a $"" hole; Serilog is unused.
            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                """"public class C { void M() { var s = $"{ $$"""{{Foo.Bar.X.Run()}}""" }"; } }"""");

            var findings = UnusedPackageService.Check(dir, []);

            // Foo.Bar IS used (inside the nested multi-dollar hole) — only Serilog is flagged.
            var finding = Assert.Single(findings);
            Assert.Equal("Serilog", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // Review finding 2: comments (// and /* */) inside an interpolation hole were not handled.
    // A } (or { or ") inside a comment reached AdvanceInterpolatedCloseBrace and closed the hole
    // early, stripping the remaining hole code including the real usage.

    [Fact]
    public void Disk_block_comment_with_closing_brace_in_hole_does_not_strip_usage()
    {
        // Before the fix: $"{ x /* } */ + Foo.Bar.X.Run() }" — the } inside /* } */ was
        // treated as a hole-closing brace (holeDepth decremented to 0), so everything after the
        // comment was processed as literal string text and Foo.Bar was wrongly flagged unused.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.Bar" Version="1.0.0" />
                    <PackageReference Include="Serilog" Version="3.0.0" />
                  </ItemGroup>
                </Project>
                """);

            // Foo.Bar used ONLY after a block comment inside the hole; Serilog is unused.
            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                """public class C { void M(string x) { var s = $"{ x /* } */ + Foo.Bar.X.Run() }"; } }""");

            var findings = UnusedPackageService.Check(dir, []);

            // Foo.Bar IS used (in the hole after the block comment) — only Serilog is flagged.
            var finding = Assert.Single(findings);
            Assert.Equal("Serilog", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // --- Existing finding 3 (kept for context) --------------------------------------------------

    // Finding 3: multi-dollar raw interpolated strings ($$"""...""", $$$"""...""") were not
    // recognised by the top-level dispatch; the trailing single-$ branch mis-parsed their
    // holes, stripping qualified names inside.  Fix: detect a $$+ run and emit the entire
    // literal content as code (fail-safe: over-preserving is harmless, over-stripping is not).

    [Fact]
    public void Disk_multi_dollar_raw_interpolated_string_hole_usage_is_not_flagged()
    {
        // Before the fix: $$"""{ "n": "{{Foo.Bar.X.Run()}}" }""" — the leading $ was
        // emitted as plain code; the remaining $"""...""" dispatched to SkipInterpolatedRawString
        // which (before finding-2 fix) treated {{ as a literal-brace escape and discarded
        // the hole, wrongly flagging Foo.Bar as unused.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.Bar" Version="1.0.0" />
                    <PackageReference Include="Serilog" Version="3.0.0" />
                  </ItemGroup>
                </Project>
                """);

            // Foo.Bar used ONLY inside the $$"""...""" hole; Serilog is genuinely unused.
            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                """"public class C { void M() { var j = $$"""{ "n": "{{Foo.Bar.X.Run()}}" }"""; } }"""");

            var findings = UnusedPackageService.Check(dir, []);

            // Foo.Bar IS used (inside the multi-dollar raw string hole) — only Serilog flagged.
            var finding = Assert.Single(findings);
            Assert.Equal("Serilog", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // --- Remaining over-strip: EmitRawMultiDollarContent lacked hole tracking (#46) ------------

    // The scanner terminated $$"""...""" at the FIRST quote run of length >= quoteCount regardless
    // of whether that run was inside an interpolation hole.  A nested raw string literal
    // ("""q""") inside the hole looks like the closing delimiter and caused the scanner to exit
    // early, treating the real usage (Foo.Bar.X.Run()) as post-literal code-then-string and
    // over-stripping it.  Fix: EmitRawMultiDollarContent now tracks brace-run hole depth (a run
    // of dollarCount '{' enters a hole; a run of dollarCount '}' exits) and only matches the
    // closing delimiter at hole depth 0.

    [Fact]
    public void Disk_raw_multi_dollar_nested_raw_string_in_hole_usage_is_not_flagged()
    {
        // Before the fix: $$"""{{ """q""" + Foo.Bar.X.Run() }}""" — the nested """q"""
        // inside the {{ }} hole looked like the closing delimiter, so EmitRawMultiDollarContent
        // exited there and Foo.Bar.X.Run() was never scanned as code. Foo.Bar was wrongly
        // flagged unused.  Serilog is genuinely unused and must still be flagged (partial-failure
        // scenario: one used, one unused — only the unused one must appear in findings).
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.Bar" Version="1.0.0" />
                    <PackageReference Include="Serilog" Version="3.0.0" />
                  </ItemGroup>
                </Project>
                """);

            // Foo.Bar used ONLY inside the $$"""...""" hole that also contains a nested raw
            // string literal """q"""; Serilog is genuinely unused.
            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                """""public class C { static void M() { var s = $$"""{{ """q""" + Foo.Bar.X.Run() }}"""; } }""""");

            var findings = UnusedPackageService.Check(dir, []);

            // Foo.Bar IS used (in the hole) — only Serilog should be flagged.
            var finding = Assert.Single(findings);
            Assert.Equal("Serilog", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_raw_multi_dollar_nested_raw_string_in_outer_hole_usage_is_not_flagged()
    {
        // Variant: the $$"""...""" literal is itself nested inside an outer $"{ ... }" hole.
        // Before the fix: the nested """q""" inside the inner $$"""...""" hole closed the
        // inner literal early, stripping Foo.Bar.X.Run() from the inner hole, so Foo.Bar was
        // wrongly flagged unused.
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.Bar" Version="1.0.0" />
                    <PackageReference Include="Serilog" Version="3.0.0" />
                  </ItemGroup>
                </Project>
                """);

            // Foo.Bar used ONLY inside $$"""{{ """q""" + Foo.Bar.X.Run() }}""" which is
            // itself inside a $"{ ... }" hole; Serilog is genuinely unused.
            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                """""public class C { static void M() { var s = $"{ $$"""{{ """q""" + Foo.Bar.X.Run() }}""" }"; } }""""");

            var findings = UnusedPackageService.Check(dir, []);

            // Foo.Bar IS used (in the nested hole) — only Serilog should be flagged.
            var finding = Assert.Single(findings);
            Assert.Equal("Serilog", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // --- Structural fix: EmitRawMultiDollarContent hole-content must be nested-token-aware ----
    //
    // Root cause: when holeDepth > 0 the scanner used a naive brace-run counter with NO
    // awareness of nested strings/comments inside the hole.  A }} that appears inside a
    // nested "..." string or /* */ comment wrongly decremented holeDepth to 0, after which
    // a subsequent """…""" run closed the literal early and the real usage after it was
    // stripped.  Fix: route hole content through EmitRawMultiDollarHoleChar which mirrors
    // the nested-token-aware EmitInterpolatedHoleChar dispatch, adapted for dollarCount-wide
    // brace runs.

    [Fact]
    public void Disk_raw_multi_dollar_closing_braces_in_nested_string_do_not_strip_usage()
    {
        // Before the fix: $$"""{{ "}}" + """q""" + Foo.Bar.X.Run() }}""" — the }} inside
        // the nested "..." string wrongly decremented holeDepth to 0, so EmitRawMultiDollarContent
        // closed the literal early at """q""" and Foo.Bar.X.Run() was stripped as phantom
        // raw-string content, wrongly flagging Foo.Bar as unused.
        // Serilog is genuinely unused and must still be flagged (partial-failure control).
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.Bar" Version="1.0.0" />
                    <PackageReference Include="Serilog" Version="3.0.0" />
                  </ItemGroup>
                </Project>
                """);

            // Foo.Bar used ONLY inside the $$"""...""" hole; the hole also contains a
            // nested regular string whose content includes }}, which must NOT affect
            // hole depth.  Serilog is genuinely unused.
            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                """""public class C { static void M() { var s = $$"""{{ "}}" + """q""" + Foo.Bar.X.Run() }}"""; } }""""");

            var findings = UnusedPackageService.Check(dir, []);

            // Foo.Bar IS used (in the hole) — only Serilog should be flagged.
            var finding = Assert.Single(findings);
            Assert.Equal("Serilog", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_raw_multi_dollar_closing_braces_in_block_comment_do_not_strip_usage()
    {
        // Before the fix: $$"""{{ /* }} */ """q""" + Foo.Bar.X.Run() }}""" — the }} inside
        // the /* */ comment wrongly decremented holeDepth to 0, same failure mode as above.
        // Serilog is genuinely unused and must still be flagged (partial-failure control).
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.Bar" Version="1.0.0" />
                    <PackageReference Include="Serilog" Version="3.0.0" />
                  </ItemGroup>
                </Project>
                """);

            // Foo.Bar used ONLY inside the $$"""...""" hole; the hole also contains a
            // block comment whose content includes }}, which must NOT affect hole depth.
            // Serilog is genuinely unused.
            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                """""public class C { static void M() { var s = $$"""{{ /* }} */ """q""" + Foo.Bar.X.Run() }}"""; } }""""");

            var findings = UnusedPackageService.Check(dir, []);

            // Foo.Bar IS used (in the hole) — only Serilog should be flagged.
            var finding = Assert.Single(findings);
            Assert.Equal("Serilog", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // --- Brace-depth arithmetic fix: per-token codeDepth model (#46) ------------------------
    //
    // Root cause: AdvanceRawMultiDollarBraceRun used a single holeDepth counter for both
    // the "are we in a hole?" state and code-brace balancing inside the hole.  A consecutive
    // run of } characters whose length >= dollarCount was treated as a hole-close even when
    // those braces were plain code (e.g. closing nested initializer levels), causing two
    // failure modes:
    //
    //   R1 (false close): the run desynchronised holeDepth to 0 mid-hole, causing the next
    //      closing-delimiter search to trigger on a nested """…""" inside the hole and strip
    //      the real usage that followed.
    //
    //   R2 (phantom depth): {{…}} inside the hole (codeDepth levels) pushed holeDepth to 2,
    //      so the real hole-close }} only decremented it to 1, the closing """ was then
    //      consumed as a nested raw-string inside the still-open phantom hole, and all code
    //      that followed the literal (including real usage) was stripped.
    //
    // Fix: introduce a separate codeDepth counter for plain code braces inside the hole.
    // Each plain { in code increments codeDepth; each } decrements codeDepth when positive
    // (code block close) or, when codeDepth == 0, counts toward the N-consecutive-} hole-close
    // sequence.  This makes the two counters orthogonal and matches Roslyn's token model.

    [Fact]
    public void Disk_raw_multi_dollar_code_initialiser_brace_run_false_close_usage_is_not_flagged()
    {
        // R1: $$"""{{ (new List<int[]>{new[]{1}}).Count + """q""".Length + Foo.Bar.X.Run().Length }}"""
        // The brace run }}} (closing inner array, then outer list) had length 2 == dollarCount,
        // which the old code misread as a hole-close.  After that false close the nested """q"""
        // was treated as the literal's closing delimiter, stripping Foo.Bar.X.Run().Length.
        // Serilog is genuinely unused and must still be flagged (partial-failure control).
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.Bar" Version="1.0.0" />
                    <PackageReference Include="Serilog" Version="3.0.0" />
                  </ItemGroup>
                </Project>
                """);

            // Exact reproducer: Foo.Bar used ONLY inside the $$"""...""" hole whose code
            // contains a collection initialiser with a consecutive brace run matching dollarCount.
            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                """""public class C { static void M() { var n = $$"""{{ (new System.Collections.Generic.List<int[]>{new[]{1}}).Count + """q""".Length + Foo.Bar.X.Run().Length }}"""; } }""""");

            var findings = UnusedPackageService.Check(dir, []);

            // Foo.Bar IS used (inside the hole) — only Serilog should be flagged.
            var finding = Assert.Single(findings);
            Assert.Equal("Serilog", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Disk_raw_multi_dollar_phantom_depth_does_not_strip_post_literal_usage()
    {
        // R2: $$"""{{ (new int[1,1]{{1} }).Length }}"""; var b = Foo.Bar.X.Run(); …
        // The old code treated {{ inside the hole as a nested hole-open (holeDepth→2).
        // The real }} then only decremented to 1, the closing """ was consumed as a nested
        // raw-string inside the phantom hole, and everything after the literal — including
        // Foo.Bar.X.Run() — was silently stripped.
        // Serilog is genuinely unused and must still be flagged (partial-failure control).
        var dir = NewTempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "MyApp.csproj"), """
                <Project Sdk="Microsoft.NET.Sdk">
                  <ItemGroup>
                    <PackageReference Include="Foo.Bar" Version="1.0.0" />
                    <PackageReference Include="Serilog" Version="3.0.0" />
                  </ItemGroup>
                </Project>
                """);

            // Exact reproducer: Foo.Bar used ONLY after the $$"""...""" literal; the hole
            // contains a 2-D array initialiser with a {{ run that the old code misread as a
            // nested hole-open, leaving the outer hole unclosed and consuming the real usage.
            File.WriteAllText(Path.Combine(dir, "Class.cs"),
                """""public class C { static int M() { var n = $$"""{{ (new int[1,1]{{1} }).Length }}"""; var b = Foo.Bar.X.Run(); return n.Length + b.Length; } }""""");

            var findings = UnusedPackageService.Check(dir, []);

            // Foo.Bar IS used (after the literal) — only Serilog should be flagged.
            var finding = Assert.Single(findings);
            Assert.Equal("Serilog", finding.Id);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
