namespace Dependably.NuCheck.Facts.Il;

/// <summary>
/// A generic type's metadata name carries a backtick-arity suffix (ECMA-335
/// §I.10.7.2) — <c>List</c>&lt;T&gt; is <c>List`1</c>, <c>Dictionary</c>&lt;TKey,
/// TValue&gt; is <c>Dictionary`2</c> — a spelling that never appears in source.
/// A consumer correlating IL evidence against source-level identifiers needs
/// the arity-stripped form; callers use this to additionally record it
/// alongside the raw metadata name, never to replace it.
/// </summary>
public static class GenericTypeNaming
{
    /// <summary>
    /// Strips a trailing backtick-arity suffix (<c>`</c> followed by one or
    /// more ASCII digits) from <paramref name="typeName"/>. Returns <paramref
    /// name="typeName"/> unchanged when there is no backtick, the backtick is
    /// the last character (nothing to strip a digit run from), or what
    /// follows it isn't all digits — a name that merely contains a backtick
    /// is never guessed at.
    /// </summary>
    public static string StripArity(string typeName)
    {
        var backtick = typeName.LastIndexOf('`');
        if (backtick < 0 || backtick == typeName.Length - 1) return typeName;

        for (var i = backtick + 1; i < typeName.Length; i++)
        {
            if (typeName[i] is < '0' or > '9') return typeName;
        }

        return typeName[..backtick];
    }
}
