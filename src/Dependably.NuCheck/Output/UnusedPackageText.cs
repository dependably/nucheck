using System.Text;
using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Output;

/// <summary>
/// Renders the variable label for one unused-package finding shared by the text formatters:
/// the package id, its installed version when known, and the declaring project file when known
/// (e.g. <c>AWSSDK.S3 3.7.301 (src/Api/Api.csproj)</c>). Every component is passed through
/// <see cref="TextSanitizer"/> so control characters from a manifest cannot corrupt the output.
/// </summary>
internal static class UnusedPackageText
{
    public static string Label(UnusedPackageFinding finding)
    {
        var builder = new StringBuilder(TextSanitizer.Sanitize(finding.Id));

        if (!string.IsNullOrEmpty(finding.Version))
        {
            builder.Append(' ').Append(TextSanitizer.Sanitize(finding.Version));
        }

        if (!string.IsNullOrEmpty(finding.DeclaringProject))
        {
            builder.Append(" (").Append(TextSanitizer.Sanitize(finding.DeclaringProject)).Append(')');
        }

        return builder.ToString();
    }
}
