namespace Dependably.NuCheck.Facts.Il;

/// <summary>
/// Compiled property/indexer/event accessors are emitted to metadata under a
/// synthetic <c>get_</c>/<c>set_</c>/<c>add_</c>/<c>remove_</c> name — the
/// source-level name a consumer actually searches for (a property <c>Foo</c>,
/// an event <c>Changed</c>) never appears in a MemberReference at all. This is
/// a pure name transform only: it does not know whether <paramref
/// name="memberName"/> genuinely names an accessor or an ordinary method that
/// happens to start with one of these prefixes (e.g. a hand-written
/// <c>get_Foo()</c> method) — callers use it to additionally record the
/// natural spelling alongside the raw one, never to replace it.
/// </summary>
public static class AccessorNaming
{
    private static readonly string[] AccessorPrefixes = ["get_", "set_", "add_", "remove_"];

    /// <summary>
    /// True when <paramref name="memberName"/> carries one of the four
    /// accessor prefixes followed by a non-empty remainder, with <paramref
    /// name="naturalName"/> set to that remainder (e.g. <c>get_Foo</c> →
    /// <c>Foo</c>). False — with <paramref name="naturalName"/> unset — for
    /// anything else, including a bare prefix with nothing after it
    /// (<c>"get_"</c>), which is not a valid natural name.
    /// </summary>
    public static bool TryGetNaturalName(string memberName, out string naturalName)
    {
        foreach (var prefix in AccessorPrefixes)
        {
            if (memberName.Length > prefix.Length && memberName.StartsWith(prefix, StringComparison.Ordinal))
            {
                naturalName = memberName[prefix.Length..];
                return true;
            }
        }
        naturalName = "";
        return false;
    }
}
