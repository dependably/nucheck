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
}
