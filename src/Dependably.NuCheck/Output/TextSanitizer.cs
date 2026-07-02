namespace Dependably.NuCheck.Output;

/// <summary>
/// Strips terminal-injection hazards from remote-sourced text before it is embedded
/// in table or summary output. Replaces C0 control characters (U+0000–U+001F, which
/// includes ESC/U+001B, CR, LF, and TAB), C1 control characters (U+0080–U+009F), and
/// the lone DEL (U+007F) with a space so the surrounding line stays legible. The JSON
/// formatter is unaffected — System.Text.Json escapes control characters automatically.
/// </summary>
public static class TextSanitizer
{
    /// <summary>
    /// Return <paramref name="text"/> with every control character replaced by a space.
    /// Returns an empty string for null input.
    /// </summary>
    public static string Sanitize(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        var chars = text.ToCharArray();
        for (var i = 0; i < chars.Length; i++)
        {
            if (IsControlCharacter(chars[i]))
            {
                chars[i] = ' ';
            }
        }

        return new string(chars);
    }

    internal static bool IsControlCharacter(char c) =>
        c <= '\x1F' || (c >= '\x7F' && c <= '\x9F');
}
