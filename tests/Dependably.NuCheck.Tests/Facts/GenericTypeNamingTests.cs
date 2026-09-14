using Dependably.NuCheck.Facts.Il;

namespace Dependably.NuCheck.Tests.Facts;

public class GenericTypeNamingTests
{
    [Theory]
    [InlineData("List`1", "List")]
    [InlineData("Dictionary`2", "Dictionary")]
    [InlineData("Func`17", "Func")] // multi-digit arity
    public void StripsTheBacktickAritySuffix(string typeName, string expected)
    {
        Assert.Equal(expected, GenericTypeNaming.StripArity(typeName));
    }

    [Theory]
    [InlineData("JsonConvert")] // no backtick at all
    [InlineData("Weird`Name")] // backtick present but not followed by digits
    [InlineData("Trailing`")] // backtick is the last character — nothing to strip
    [InlineData("")]
    public void LeavesNonGenericOrUnrecognizedNamesUnchanged(string typeName)
    {
        Assert.Equal(typeName, GenericTypeNaming.StripArity(typeName));
    }
}
