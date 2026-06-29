using Dependably.NuCheck.Models;

namespace Dependably.NuCheck.Output;

/// <summary>Renders an <see cref="AuditResult"/> as text for the console.</summary>
public interface IResultFormatter
{
    string Format(AuditResult result);
}
