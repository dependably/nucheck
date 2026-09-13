using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Dependably.NuCheck.Tests.Facts;

internal static class Fixtures
{
    /// <summary>
    /// The committed sample app (copied from sbom-reach's fixtures/csharp-app). Its
    /// <c>App/obj/project.assets.json</c> deliberately points <c>packageFolders</c> at a
    /// path that does not exist: that is the permanently UN-restored case, and the
    /// facts document for it must carry no <c>namespaces</c> for any package — never a
    /// guess from the id.
    /// </summary>
    public static string CsharpApp => Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "fixtures", "csharp-app"));

    /// <summary>
    /// Copies fixtures/csharp-app (excluding any `bin/`) into a fresh temp
    /// directory. Every test that needs a real `dotnet build` MUST build this
    /// copy, never the committed tree in place — `dotnet build` implicitly
    /// restores, which rewrites the deliberately-committed, machine-independent
    /// `App/obj/project.assets.json` with real (and machine-specific) restore
    /// output, and races with tests reading that same tracked file concurrently.
    /// </summary>
    public static string CopyToScratch(string label)
    {
        var scratch = NewScratch(label);
        CopyExcludingBin(CsharpApp, scratch);
        return scratch;
    }

    public static string NewScratch(string label) =>
        Directory.CreateTempSubdirectory($"nucheck-facts-{label}-").FullName;

    public static void CopyExcludingBin(string sourceDir, string destDir)
    {
        bool UnderBin(string relativePath) =>
            relativePath.Split(Path.DirectorySeparatorChar).Any(p => p.Equals("bin", StringComparison.OrdinalIgnoreCase));

        Directory.CreateDirectory(destDir);
        foreach (var dir in Directory.GetDirectories(sourceDir, "*", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(sourceDir, dir);
            if (UnderBin(rel)) continue;
            Directory.CreateDirectory(Path.Combine(destDir, rel));
        }
        foreach (var file in Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(sourceDir, file);
            if (UnderBin(rel)) continue;
            var destFile = Path.Combine(destDir, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(destFile)!);
            File.Copy(file, destFile);
        }
    }

    public static void DeleteScratch(string scratch)
    {
        try
        {
            Directory.Delete(scratch, recursive: true);
        }
        catch
        {
            // Best-effort cleanup; a leftover temp dir isn't worth failing the run over.
        }
    }

    /// <summary>
    /// Emits a real assembly with Roslyn so the metadata readers are exercised
    /// against genuine PE files without committing any binary fixture.
    /// </summary>
    public static void EmitAssembly(string assemblyName, string source, string path)
    {
        var compilation = CSharpCompilation.Create(
            assemblyName,
            [CSharpSyntaxTree.ParseText(source)],
            [MetadataReference.CreateFromFile(typeof(object).Assembly.Location)],
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var result = compilation.Emit(path);
        Assert.True(result.Success, string.Join("\n", result.Diagnostics));
    }
}
