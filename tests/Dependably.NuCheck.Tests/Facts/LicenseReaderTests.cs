using Dependably.NuCheck.Facts;
using Dependably.NuCheck.Facts.Nuget;

namespace Dependably.NuCheck.Tests.Facts;

public class LicenseReaderTests
{
    private static string WriteNuspec(string packageFoldersRoot, string id, string version, string nuspecXml)
    {
        var pkgDir = Path.Combine(packageFoldersRoot, id.ToLowerInvariant(), version);
        Directory.CreateDirectory(pkgDir);
        var path = Path.Combine(pkgDir, $"{id.ToLowerInvariant()}.nuspec");
        File.WriteAllText(path, nuspecXml);
        return path;
    }

    [Fact]
    public void ReadsAModernExpressionLicense()
    {
        var root = Fixtures.NewScratch("license");
        try
        {
            WriteNuspec(root, "Acme.Widgets", "1.2.3", """
                <?xml version="1.0" encoding="utf-8"?>
                <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
                  <metadata>
                    <id>Acme.Widgets</id>
                    <version>1.2.3</version>
                    <license type="expression">MIT</license>
                    <licenseUrl>https://licenses.nuget.org/MIT</licenseUrl>
                  </metadata>
                </package>
                """);

            var license = LicenseReader.Read([root], "Acme.Widgets", "1.2.3");
            Assert.Equal("MIT", license);
        }
        finally
        {
            Fixtures.DeleteScratch(root);
        }
    }

    [Fact]
    public void ReadsACompoundSpdxExpression()
    {
        var root = Fixtures.NewScratch("license");
        try
        {
            WriteNuspec(root, "Acme.Widgets", "1.2.3", """
                <?xml version="1.0" encoding="utf-8"?>
                <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
                  <metadata>
                    <id>Acme.Widgets</id>
                    <version>1.2.3</version>
                    <license type="expression">(MIT OR Apache-2.0)</license>
                  </metadata>
                </package>
                """);

            var license = LicenseReader.Read([root], "Acme.Widgets", "1.2.3");
            Assert.Equal("(MIT OR Apache-2.0)", license);
        }
        finally
        {
            Fixtures.DeleteScratch(root);
        }
    }

    [Fact]
    public void AnOlderNuspecWithOnlyLicenseUrlIsAbsentNotGuessed()
    {
        var root = Fixtures.NewScratch("license");
        try
        {
            WriteNuspec(root, "Acme.Widgets", "1.2.3", """
                <?xml version="1.0" encoding="utf-8"?>
                <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
                  <metadata>
                    <id>Acme.Widgets</id>
                    <version>1.2.3</version>
                    <licenseUrl>https://example.com/license</licenseUrl>
                  </metadata>
                </package>
                """);

            var license = LicenseReader.Read([root], "Acme.Widgets", "1.2.3");
            Assert.Null(license);
        }
        finally
        {
            Fixtures.DeleteScratch(root);
        }
    }

    [Fact]
    public void ALicenseTypeFileReferenceIsAbsentNotTheFilePath()
    {
        var root = Fixtures.NewScratch("license");
        try
        {
            WriteNuspec(root, "Acme.Widgets", "1.2.3", """
                <?xml version="1.0" encoding="utf-8"?>
                <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
                  <metadata>
                    <id>Acme.Widgets</id>
                    <version>1.2.3</version>
                    <license type="file">LICENSE.txt</license>
                  </metadata>
                </package>
                """);

            var license = LicenseReader.Read([root], "Acme.Widgets", "1.2.3");
            Assert.Null(license);
        }
        finally
        {
            Fixtures.DeleteScratch(root);
        }
    }

    [Fact]
    public void MissingNuspecReturnsNullNeverThrows()
    {
        var root = Fixtures.NewScratch("license");
        try
        {
            var unanalyzable = new List<UnanalyzableEntry>();
            Assert.Null(LicenseReader.Read([root], "Never.Restored", "1.0.0", unanalyzable));
            // A packageFolders entry that doesn't exist at all must not throw either.
            Assert.Null(LicenseReader.Read(["/definitely/not/a/dir"], "Never.Restored", "1.0.0", unanalyzable));
            // Absence of the file is not a read failure — nothing to report.
            Assert.Empty(unanalyzable);
        }
        finally
        {
            Fixtures.DeleteScratch(root);
        }
    }

    [Fact]
    public void MalformedNuspecReturnsNullAndIsReported()
    {
        var root = Fixtures.NewScratch("license");
        try
        {
            var path = WriteNuspec(root, "Acme.Widgets", "1.2.3", "not valid xml <<<");
            var unanalyzable = new List<UnanalyzableEntry>();

            Assert.Null(LicenseReader.Read([root], "Acme.Widgets", "1.2.3", unanalyzable));

            var gap = Assert.Single(unanalyzable);
            Assert.Equal(UnanalyzableEntry.KindFile, gap.Kind);
            Assert.Equal(path.Replace('\\', '/'), gap.File);
            Assert.StartsWith("unparseable nuspec", gap.Reason);
        }
        finally
        {
            Fixtures.DeleteScratch(root);
        }
    }
}
