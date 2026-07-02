using Dependably.NuCheck.Services;

namespace Dependably.NuCheck.Tests;

public class PackageFileReaderTests : IDisposable
{
    private readonly List<string> _tempFiles = [];
    private readonly List<string> _tempDirs = [];

    [Fact]
    public void Read_parses_packages_config_including_four_part_versions()
    {
        var path = WriteTemp(".config", """
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="11.0.2" targetFramework="net462" />
  <package id="Bouncy.Castle" version="1.8.3.1" targetFramework="net462" />
</packages>
""");

        var packages = PackageFileReader.Read(path);

        Assert.Equal(2, packages.Count);
        Assert.Contains(packages, p => p.Id == "Newtonsoft.Json" && p.Version.ToString() == "11.0.2");
        // The four-part version that npm semver could not handle.
        Assert.Contains(packages, p => p.Id == "Bouncy.Castle" && p.Version.ToString() == "1.8.3.1");
    }

    [Fact]
    public void Read_parses_packages_lock_json()
    {
        var path = WriteTemp(".json", """
{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Newtonsoft.Json": { "type": "Direct", "requested": "[11.0.2, )", "resolved": "11.0.2", "contentHash": "abc" }
    }
  }
}
""");

        var packages = PackageFileReader.Read(path);

        var package = Assert.Single(packages);
        Assert.Equal("Newtonsoft.Json", package.Id);
        Assert.Equal("11.0.2", package.Version.ToString());
    }

    [Fact]
    public void Read_throws_for_missing_file()
    {
        Assert.Throws<FileNotFoundException>(() => PackageFileReader.Read("/no/such/file.config"));
    }

    [Fact]
    public void Read_throws_invalid_data_for_malformed_config()
    {
        var path = WriteTemp(".config", "<packages><unclosed>");
        Assert.Throws<InvalidDataException>(() => PackageFileReader.Read(path));
    }

    [Fact]
    public void Read_reports_zero_for_valid_but_empty_packages_config()
    {
        // A real, recognised packages.config with no entries must still be treated as
        // an empty audit (0 packages) — only UNRECOGNISED formats error.
        var path = WriteTemp(".config", """
<?xml version="1.0" encoding="utf-8"?>
<packages>
</packages>
""");

        var packages = PackageFileReader.Read(path);

        Assert.Empty(packages);
    }

    [Fact]
    public void Read_recognises_packages_config_by_root_not_extension()
    {
        // Content-based recognition: a <packages> root parses even with an odd name.
        var path = WriteTemp(".xml", """
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="11.0.2" targetFramework="net462" />
</packages>
""");

        var packages = PackageFileReader.Read(path);

        var package = Assert.Single(packages);
        Assert.Equal("Newtonsoft.Json", package.Id);
    }

    // Wave 2 change: Central Package Management and bare <PackageReference> are now
    // SUPPORTED. The two tests below previously asserted these formats THREW
    // "Unsupported manifest" (Wave 1, fail-closed). They are now positive tests proving
    // the formats parse.
    [Fact]
    public void Read_parses_directory_packages_props_as_central_versions()
    {
        // Central Package Management file: a <Project> root whose <PackageVersion>
        // entries ARE the package set to audit.
        var path = WriteTemp(".props", """
<?xml version="1.0" encoding="utf-8"?>
<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="11.0.2" />
  </ItemGroup>
</Project>
""");

        var packages = PackageFileReader.Read(path);

        var package = Assert.Single(packages);
        Assert.Equal("Newtonsoft.Json", package.Id);
        Assert.Equal("11.0.2", package.Version.ToString());
    }

    [Fact]
    public void Read_parses_csproj_packagereference()
    {
        // A <Project>-rooted .csproj with a bare <PackageReference> is now audited.
        var path = WriteTemp(".csproj", """
<?xml version="1.0" encoding="utf-8"?>
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="11.0.2" />
  </ItemGroup>
</Project>
""");

        var packages = PackageFileReader.Read(path);

        var package = Assert.Single(packages);
        Assert.Equal("Newtonsoft.Json", package.Id);
        Assert.Equal("11.0.2", package.Version.ToString());
    }

    [Fact]
    public void Read_fails_closed_on_unknown_non_xml_file()
    {
        var path = WriteTemp(".txt", "this is not a manifest");

        var ex = Assert.Throws<InvalidDataException>(() => PackageFileReader.Read(path));
        Assert.Contains("Unsupported manifest", ex.Message);
    }

    [Fact]
    public void Read_throws_for_malformed_json()
    {
        var path = WriteTemp(".json", "{ not valid json");

        Assert.Throws<InvalidDataException>(() => PackageFileReader.Read(path));
    }

    [Fact]
    public void Read_throws_for_json_that_is_not_a_lock_file()
    {
        // Valid JSON, but not a lock file — must NOT silently report 0 packages.
        var path = WriteTemp(".json", """{ "foo": "bar" }""");

        Assert.Throws<InvalidDataException>(() => PackageFileReader.Read(path));
    }

    [Fact]
    public void Read_reports_zero_for_valid_but_empty_lock_file()
    {
        var path = WriteTemp(".json", """{ "version": 1, "dependencies": {} }""");

        var packages = PackageFileReader.Read(path);

        Assert.Empty(packages);
    }

    // --- Wave 2: <PackageReference> + Central Package Management (.csproj / .props) ---

    [Fact]
    public void Read_parses_packagereference_version_attribute()
    {
        var path = WriteTemp(".csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X" Version="1.2.3" />
  </ItemGroup>
</Project>
""");

        var package = Assert.Single(PackageFileReader.Read(path));
        Assert.Equal("X", package.Id);
        Assert.Equal("1.2.3", package.Version.ToString());
    }

    [Fact]
    public void Read_parses_packagereference_version_child_element()
    {
        // The <Version> child-element form instead of the attribute.
        var path = WriteTemp(".csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X">
      <Version>1.2.3</Version>
    </PackageReference>
  </ItemGroup>
</Project>
""");

        var package = Assert.Single(PackageFileReader.Read(path));
        Assert.Equal("X", package.Id);
        Assert.Equal("1.2.3", package.Version.ToString());
    }

    [Fact]
    public void Read_resolves_cpm_version_from_directory_packages_props()
    {
        // Central Package Management: csproj has a versionless <PackageReference>; the
        // version comes from a Directory.Packages.props beside it (walked up the tree).
        var dir = NewTempDir();
        File.WriteAllText(Path.Combine(dir, "Directory.Packages.props"), """
<Project>
  <ItemGroup>
    <PackageVersion Include="X" Version="1.2.3" />
  </ItemGroup>
</Project>
""");
        var csproj = Path.Combine(dir, "foo.csproj");
        File.WriteAllText(csproj, """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X" />
  </ItemGroup>
</Project>
""");

        var package = Assert.Single(PackageFileReader.Read(csproj));
        Assert.Equal("X", package.Id);
        Assert.Equal("1.2.3", package.Version.ToString());
    }

    [Fact]
    public void Read_directory_packages_props_directly_returns_its_version_set()
    {
        var path = WriteTemp(".props", """
<Project>
  <ItemGroup>
    <PackageVersion Include="X" Version="1.0.0" />
    <PackageVersion Include="Y" Version="2.0.0" />
  </ItemGroup>
</Project>
""");

        var packages = PackageFileReader.Read(path);

        Assert.Equal(2, packages.Count);
        Assert.Contains(packages, p => p.Id == "X" && p.Version.ToString() == "1.0.0");
        Assert.Contains(packages, p => p.Id == "Y" && p.Version.ToString() == "2.0.0");
    }

    [Fact]
    public void Read_audits_version_range_at_lower_bound()
    {
        // A version range is audited at its declared LOWER BOUND (conservative).
        var path = WriteTemp(".csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X" Version="[1.0.0,2.0.0)" />
  </ItemGroup>
</Project>
""");

        var package = Assert.Single(PackageFileReader.Read(path));
        Assert.Equal("X", package.Id);
        Assert.Equal("1.0.0", package.Version.ToString());
    }

    [Fact]
    public void Read_project_with_no_packagereferences_returns_empty_not_error()
    {
        // A clean <Project> with zero packages is an empty audit, NOT an error.
        var path = WriteTemp(".csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
</Project>
""");

        Assert.Empty(PackageFileReader.Read(path));
    }

    [Fact]
    public void Read_skips_unresolvable_version_but_returns_siblings()
    {
        // A reference whose version cannot be determined is skipped; siblings remain.
        var path = WriteTemp(".csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Good" Version="1.2.3" />
    <PackageReference Include="Unversioned" />
  </ItemGroup>
</Project>
""");

        var package = Assert.Single(PackageFileReader.Read(path));
        Assert.Equal("Good", package.Id);
        Assert.Equal("1.2.3", package.Version.ToString());
    }

    [Fact]
    public void Read_uses_version_override_attribute()
    {
        var path = WriteTemp(".csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X" VersionOverride="3.1.0" />
  </ItemGroup>
</Project>
""");

        var package = Assert.Single(PackageFileReader.Read(path));
        Assert.Equal("X", package.Id);
        Assert.Equal("3.1.0", package.Version.ToString());
    }

    // ---- #13 / #50 (consolidated): lock-file multi-target deduplication ---------

    [Fact]
    public void Read_deduplicates_same_package_version_across_lock_file_targets()
    {
        // Same id + same resolved version in net6.0 and net8.0 → exactly 1 PackageRef.
        var path = WriteTemp(".json", """
{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Newtonsoft.Json": { "type": "Direct", "requested": "[13.0.1, )", "resolved": "13.0.1", "contentHash": "abc" }
    },
    "net8.0": {
      "Newtonsoft.Json": { "type": "Direct", "requested": "[13.0.1, )", "resolved": "13.0.1", "contentHash": "abc" }
    }
  }
}
""");

        var packages = PackageFileReader.Read(path);

        Assert.Single(packages);
        Assert.Equal("Newtonsoft.Json", packages[0].Id);
        Assert.Equal("13.0.1", packages[0].Version.ToString());
    }

    [Fact]
    public void Read_retains_both_entries_when_resolved_versions_differ_across_targets()
    {
        // Same id but different resolved versions across targets → 2 PackageRefs (both auditable).
        var path = WriteTemp(".json", """
{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Serilog": { "type": "Direct", "requested": "[3.0.0, )", "resolved": "3.0.0", "contentHash": "x1" }
    },
    "net8.0": {
      "Serilog": { "type": "Direct", "requested": "[4.0.0, )", "resolved": "4.0.0", "contentHash": "x2" }
    }
  }
}
""");

        var packages = PackageFileReader.Read(path);

        Assert.Equal(2, packages.Count);
        Assert.Contains(packages, p => p.Id == "Serilog" && p.Version.ToString() == "3.0.0");
        Assert.Contains(packages, p => p.Id == "Serilog" && p.Version.ToString() == "4.0.0");
    }

    // ---- #49 × #26: duplicate-id with a range + an exact version audits BOTH -----
    // Pre-#26 these collapsed to the exact version (range's lower bound dropped). #26
    // deliberately audits every DISTINCT resolved version so a vulnerable lower bound is
    // never masked by an exact pin — the range "[1.0.0,)" and the exact "1.2.3" resolve to
    // different versions (1.0.0 vs 1.2.3), so both are now audited. (An exact and a range
    // that resolve to the SAME version still collapse — see
    // Read_collapses_exact_and_range_that_resolve_to_the_same_version.)

    [Fact]
    public void Read_audits_both_range_lower_bound_and_exact_when_range_declared_first()
    {
        var path = WriteTemp(".csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X" Version="[1.0.0,)" />
    <PackageReference Include="x" Version="1.2.3" />
  </ItemGroup>
</Project>
""");

        var packages = PackageFileReader.Read(path);

        Assert.Equal(2, packages.Count);
        Assert.Contains(packages, p => p.Version.ToString() == "1.0.0");
        Assert.Contains(packages, p => p.Version.ToString() == "1.2.3");
    }

    [Fact]
    public void Read_audits_both_range_lower_bound_and_exact_when_exact_declared_first()
    {
        var path = WriteTemp(".csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X" Version="1.2.3" />
    <PackageReference Include="x" Version="[1.0.0,)" />
  </ItemGroup>
</Project>
""");

        var packages = PackageFileReader.Read(path);

        Assert.Equal(2, packages.Count);
        Assert.Contains(packages, p => p.Version.ToString() == "1.0.0");
        Assert.Contains(packages, p => p.Version.ToString() == "1.2.3");
    }

    // ---- #51 × #26: file-local <PackageVersion> is UNIONED with Directory.Packages.props -----

    [Fact]
    public void Read_audits_both_file_local_and_central_package_version()
    {
        // Directory.Packages.props declares X at 1.0.0; the csproj declares a file-local
        // <PackageVersion Include="X" Version="2.0.0" /> plus a versionless
        // <PackageReference Include="X" />. Pre-#26 the file-local declaration OVERRODE the
        // central one (single 2.0.0). #26 does not evaluate MSBuild override precedence, so
        // it audits BOTH declared versions — a vulnerable central pin (1.0.0) must not be
        // silently masked by a file-local override. Auditing the superset is fail-safe.
        var dir = NewTempDir();
        File.WriteAllText(Path.Combine(dir, "Directory.Packages.props"), """
<Project>
  <ItemGroup>
    <PackageVersion Include="X" Version="1.0.0" />
  </ItemGroup>
</Project>
""");
        var csproj = Path.Combine(dir, "app.csproj");
        File.WriteAllText(csproj, """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageVersion Include="X" Version="2.0.0" />
    <PackageReference Include="X" />
  </ItemGroup>
</Project>
""");

        var packages = PackageFileReader.Read(csproj);

        Assert.Equal(2, packages.Count);
        Assert.Contains(packages, p => p.Id == "X" && p.Version.ToString() == "1.0.0");
        Assert.Contains(packages, p => p.Id == "X" && p.Version.ToString() == "2.0.0");
    }

    [Fact]
    public void Read_explicit_version_attribute_beats_central_package_version()
    {
        // Directory.Packages.props declares X at 1.0.0.
        // The csproj PackageReference has an explicit Version="3.0.0" attribute (VersionOverride style).
        // The explicit attribute must win → resolved version is 3.0.0.
        var dir = NewTempDir();
        File.WriteAllText(Path.Combine(dir, "Directory.Packages.props"), """
<Project>
  <ItemGroup>
    <PackageVersion Include="X" Version="1.0.0" />
  </ItemGroup>
</Project>
""");
        var csproj = Path.Combine(dir, "app.csproj");
        File.WriteAllText(csproj, """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X" Version="3.0.0" />
  </ItemGroup>
</Project>
""");

        var package = Assert.Single(PackageFileReader.Read(csproj));
        Assert.Equal("X", package.Id);
        Assert.Equal("3.0.0", package.Version.ToString());
    }

    [Fact]
    public void Read_audits_every_distinct_version_of_a_duplicated_packagereference()
    {
        // The same package pinned to two different exact versions for two TargetFrameworks
        // (Condition-gated, common multi-TFM pattern). Conditions are deliberately NOT
        // evaluated, so BOTH declared versions must be audited — a vulnerable legacy pin
        // must not be masked by a clean newer one.
        var path = WriteTemp(".csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup Condition="'$(TargetFramework)'=='net48'">
    <PackageReference Include="X" Version="1.0.0" />
  </ItemGroup>
  <ItemGroup Condition="'$(TargetFramework)'=='net8.0'">
    <PackageReference Include="X" Version="2.0.0" />
  </ItemGroup>
</Project>
""");

        var packages = PackageFileReader.Read(path);

        Assert.Equal(2, packages.Count);
        Assert.Contains(packages, p => p.Id == "X" && p.Version.ToString() == "1.0.0");
        Assert.Contains(packages, p => p.Id == "X" && p.Version.ToString() == "2.0.0");
    }

    [Fact]
    public void Read_audits_every_distinct_version_of_a_duplicated_packageversion()
    {
        // Central Package Management with the same id declared at two versions (per-TFM
        // Condition). Both distinct versions must survive — no last-wins collapse.
        var path = WriteTemp(".props", """
<Project>
  <ItemGroup Condition="'$(TargetFramework)'=='net48'">
    <PackageVersion Include="X" Version="1.0.0" />
  </ItemGroup>
  <ItemGroup Condition="'$(TargetFramework)'=='net8.0'">
    <PackageVersion Include="X" Version="2.0.0" />
  </ItemGroup>
</Project>
""");

        var packages = PackageFileReader.Read(path);

        Assert.Equal(2, packages.Count);
        Assert.Contains(packages, p => p.Id == "X" && p.Version.ToString() == "1.0.0");
        Assert.Contains(packages, p => p.Id == "X" && p.Version.ToString() == "2.0.0");
    }

    [Fact]
    public void Read_collapses_exact_and_range_that_resolve_to_the_same_version()
    {
        // An exact "1.0.0" and a range "[1.0.0,2.0.0)" both resolve to 1.0.0 — the same
        // audited version. They collapse to a single entry (exact preferred over range).
        var path = WriteTemp(".csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X" Version="[1.0.0,2.0.0)" />
    <PackageReference Include="X" Version="1.0.0" />
  </ItemGroup>
</Project>
""");

        var package = Assert.Single(PackageFileReader.Read(path));
        Assert.Equal("X", package.Id);
        Assert.Equal("1.0.0", package.Version.ToString());
    }

    // --- Ticket #36: floating-version lower-bound behaviour (documented at PackageFileReader.cs:224-227) ---

    [Fact]
    public void Read_audits_floating_major_wildcard_at_lower_bound()
    {
        // "6.*" is a floating version. TryResolveVersion falls through to VersionRange and
        // resolves to MinVersion. NuGet.Versioning places the wildcard at the minor position,
        // so MinVersion = 6.0 (two-part; no patch component). The documented lower-bound
        // contract must hold: the audit uses 6.0, not some higher resolved version.
        var path = WriteTemp(".csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X" Version="6.*" />
  </ItemGroup>
</Project>
""");

        var package = Assert.Single(PackageFileReader.Read(path));
        Assert.Equal("X", package.Id);
        Assert.Equal("6.0", package.Version.ToString());
    }

    [Fact]
    public void Read_audits_floating_minor_wildcard_at_lower_bound()
    {
        // "1.2.*" is a floating version; MinVersion = 1.2.0.
        var path = WriteTemp(".csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X" Version="1.2.*" />
  </ItemGroup>
</Project>
""");

        var package = Assert.Single(PackageFileReader.Read(path));
        Assert.Equal("X", package.Id);
        Assert.Equal("1.2.0", package.Version.ToString());
    }

    [Fact]
    public void Read_skips_range_with_no_lower_bound()
    {
        // "(,2.0]" has no lower bound (MinVersion is null). TryResolveVersion returns false
        // and the package is skipped — it cannot be audited at a conservative version.
        // Siblings with resolvable versions are still returned.
        var path = WriteTemp(".csproj", """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="NoLower" Version="(,2.0]" />
    <PackageReference Include="Good" Version="3.0.0" />
  </ItemGroup>
</Project>
""");

        var packages = PackageFileReader.Read(path);

        var package = Assert.Single(packages);
        Assert.Equal("Good", package.Id);
        Assert.Equal("3.0.0", package.Version.ToString());
    }

    [Fact]
    public void Read_resolves_versionless_reference_against_every_central_version_of_the_id()
    {
        // Central Package Management, cross-file: a version-LESS <PackageReference Include="X" />
        // in the csproj, with an up-tree Directory.Packages.props declaring X TWICE at different
        // versions (per-TargetFramework Condition). Conditions are not evaluated, so the reference
        // can statically resolve to EITHER central version — both must be audited. A last-wins
        // collapse here would silently mask the vulnerable legacy pin (1.0.0).
        var dir = NewTempDir();
        File.WriteAllText(Path.Combine(dir, "Directory.Packages.props"), """
<Project>
  <ItemGroup Condition="'$(TargetFramework)'=='net48'">
    <PackageVersion Include="X" Version="1.0.0" />
  </ItemGroup>
  <ItemGroup Condition="'$(TargetFramework)'=='net8.0'">
    <PackageVersion Include="X" Version="2.0.0" />
  </ItemGroup>
</Project>
""");
        var csproj = Path.Combine(dir, "foo.csproj");
        File.WriteAllText(csproj, """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X" />
  </ItemGroup>
</Project>
""");

        var packages = PackageFileReader.Read(csproj);

        Assert.Equal(2, packages.Count);
        Assert.Contains(packages, p => p.Id == "X" && p.Version.ToString() == "1.0.0");
        Assert.Contains(packages, p => p.Id == "X" && p.Version.ToString() == "2.0.0");
    }

    // --- Ticket #3: malformed Directory.Packages.props must surface, not silently fall back ---

    [Fact]
    public void Read_throws_when_nearest_directory_packages_props_is_malformed_xml()
    {
        // MSBuild stops at the first Directory.Packages.props; if it is malformed, the
        // build fails. nucheck must do the same — fail closed, not fall back silently.
        var dir = NewTempDir();
        File.WriteAllText(Path.Combine(dir, "Directory.Packages.props"), "<Project><unclosed>");
        var csproj = Path.Combine(dir, "foo.csproj");
        File.WriteAllText(csproj, """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X" />
  </ItemGroup>
</Project>
""");

        var ex = Assert.Throws<InvalidDataException>(() => PackageFileReader.Read(csproj));
        Assert.Contains("Directory.Packages.props", ex.Message);
    }

    [Fact]
    public void Read_does_not_silently_fall_back_to_ancestor_props_when_nearest_is_malformed()
    {
        // Mixed partial-failure: a malformed nearest props sits between the csproj and a
        // valid ancestor props. The tool must NOT skip the malformed file and use the
        // ancestor — that would resolve wrong versions and produce a false-negative audit.
        var ancestor = NewTempDir();
        File.WriteAllText(Path.Combine(ancestor, "Directory.Packages.props"), """
<Project>
  <ItemGroup>
    <PackageVersion Include="X" Version="99.0.0" />
  </ItemGroup>
</Project>
""");

        var subdir = Path.Combine(ancestor, $"sub-{Guid.NewGuid():N}");
        Directory.CreateDirectory(subdir);
        _tempDirs.Add(subdir);
        File.WriteAllText(Path.Combine(subdir, "Directory.Packages.props"), "<Project><broken>");

        var csproj = Path.Combine(subdir, "foo.csproj");
        File.WriteAllText(csproj, """
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="X" />
  </ItemGroup>
</Project>
""");

        // Must throw — not silently return the ancestor's 99.0.0.
        Assert.Throws<InvalidDataException>(() => PackageFileReader.Read(csproj));
    }

    private string WriteTemp(string extension, string content)
    {
        var path = Path.Combine(Path.GetTempPath(), $"nugetcheck-{Guid.NewGuid():N}{extension}");
        File.WriteAllText(path, content);
        _tempFiles.Add(path);
        return path;
    }

    private string NewTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"nugetcheck-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);
        return dir;
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
        foreach (var file in _tempFiles)
        {
            if (File.Exists(file))
            {
                File.Delete(file);
            }
        }

        foreach (var dir in _tempDirs)
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }
}
