using Dependably.NuCheck.Facts;
using Dependably.NuCheck.Facts.Nuget;

namespace Dependably.NuCheck.Tests.Facts;

public class NuspecReaderTests
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

            var license = NuspecReader.Read([root], "Acme.Widgets", "1.2.3")?.License;
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

            var license = NuspecReader.Read([root], "Acme.Widgets", "1.2.3")?.License;
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

            var license = NuspecReader.Read([root], "Acme.Widgets", "1.2.3")?.License;
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

            var license = NuspecReader.Read([root], "Acme.Widgets", "1.2.3")?.License;
            Assert.Null(license);
        }
        finally
        {
            Fixtures.DeleteScratch(root);
        }
    }

    [Fact]
    public void MissingNuspecReadsNothingAndNeverThrows()
    {
        var root = Fixtures.NewScratch("license");
        try
        {
            var unanalyzable = new List<UnanalyzableEntry>();
            Assert.Null(NuspecReader.Read([root], "Never.Restored", "1.0.0", unanalyzable: unanalyzable));
            // A packageFolders entry that doesn't exist at all must not throw either.
            Assert.Null(NuspecReader.Read(["/definitely/not/a/dir"], "Never.Restored", "1.0.0", unanalyzable: unanalyzable));
            // Absence of the file is not a read failure — nothing to report.
            Assert.Empty(unanalyzable);
        }
        finally
        {
            Fixtures.DeleteScratch(root);
        }
    }

    [Fact]
    public void MalformedNuspecReadsNothingAndIsReported()
    {
        var root = Fixtures.NewScratch("license");
        try
        {
            var path = WriteNuspec(root, "Acme.Widgets", "1.2.3", "not valid xml <<<");
            var unanalyzable = new List<UnanalyzableEntry>();

            // Under the scanned tree: relative path. The reason carries the XML
            // parser's position, never a filesystem path.
            Assert.Null(NuspecReader.Read([root], "Acme.Widgets", "1.2.3", srcDir: root, unanalyzable));

            var gap = Assert.Single(unanalyzable);
            Assert.Equal(UnanalyzableEntry.KindFile, gap.Kind);
            Assert.Equal("acme.widgets/1.2.3/acme.widgets.nuspec", gap.File);
            Assert.StartsWith("unparseable nuspec: ", gap.Reason);
            Assert.DoesNotContain(root, gap.Reason);
            Assert.DoesNotContain("/", gap.Reason);

            // Outside any scanned tree: the absolute path, POSIX separators.
            unanalyzable.Clear();
            Assert.Null(NuspecReader.Read([root], "Acme.Widgets", "1.2.3", srcDir: Path.Combine(root, "elsewhere"), unanalyzable));
            Assert.Equal(Path.GetFullPath(path).Replace('\\', '/'), Assert.Single(unanalyzable).File);
        }
        finally
        {
            Fixtures.DeleteScratch(root);
        }
    }

    /// `authors`/`owners` are comma-separated free text, and free text is what
    /// gets published: no split, no trim of the interior, no attribution.
    [Fact]
    public void ProducerStringsAreVerbatim()
    {
        var root = Fixtures.NewScratch("nuspec");
        try
        {
            WriteNuspec(root, "Acme.Widgets", "1.2.3", """
                <?xml version="1.0" encoding="utf-8"?>
                <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
                  <metadata>
                    <id>Acme.Widgets</id>
                    <version>1.2.3</version>
                    <authors>Acme Corp,  J. Random Hacker &amp; friends</authors>
                    <owners>acme-bot, acme</owners>
                  </metadata>
                </package>
                """);

            var producer = NuspecReader.Read([root], "Acme.Widgets", "1.2.3")!.Producer;
            Assert.Equal("Acme Corp,  J. Random Hacker & friends", producer.Authors);
            Assert.Equal("acme-bot, acme", producer.Owners);
        }
        finally
        {
            Fixtures.DeleteScratch(root);
        }
    }

    /// The file was read and says nothing: an explicit null, which the document
    /// writes as `"authors": null` — a fact of absence, not the omission that
    /// means "no nuspec was read at all".
    [Fact]
    public void AnAbsentOrEmptyProducerElementIsNullNotGuessed()
    {
        var root = Fixtures.NewScratch("nuspec");
        try
        {
            WriteNuspec(root, "Acme.Widgets", "1.2.3", """
                <?xml version="1.0" encoding="utf-8"?>
                <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
                  <metadata>
                    <id>Acme.Widgets</id>
                    <version>1.2.3</version>
                    <owners>   </owners>
                    <license type="expression">MIT</license>
                  </metadata>
                </package>
                """);

            var nuspec = NuspecReader.Read([root], "Acme.Widgets", "1.2.3");
            Assert.NotNull(nuspec);
            Assert.Equal("MIT", nuspec.License);
            Assert.Null(nuspec.Producer.Authors);   // element absent
            Assert.Null(nuspec.Producer.Owners);    // element present but empty
        }
        finally
        {
            Fixtures.DeleteScratch(root);
        }
    }

    /// The package id is not a producer: a nuspec with no `authors` yields null,
    /// never "Acme.Widgets" — the same rule that keeps a namespace from being
    /// guessed off a package id.
    [Fact]
    public void ProducerIsNeverInferredFromTheId()
    {
        var root = Fixtures.NewScratch("nuspec");
        try
        {
            WriteNuspec(root, "Acme.Widgets", "1.2.3", """
                <?xml version="1.0" encoding="utf-8"?>
                <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
                  <metadata><id>Acme.Widgets</id><version>1.2.3</version></metadata>
                </package>
                """);

            var producer = NuspecReader.Read([root], "Acme.Widgets", "1.2.3")!.Producer;
            Assert.Null(producer.Authors);
            Assert.Null(producer.Owners);
        }
        finally
        {
            Fixtures.DeleteScratch(root);
        }
    }
}
