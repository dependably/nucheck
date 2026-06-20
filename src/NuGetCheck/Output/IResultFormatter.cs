using NuGetCheck.Models;

namespace NuGetCheck.Output;

/// <summary>Renders an <see cref="AuditResult"/> as text for the console.</summary>
public interface IResultFormatter
{
    string Format(AuditResult result);
}
