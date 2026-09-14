using Dependably.NuCheck.Facts.Il;

namespace Dependably.NuCheck.Tests.Facts;

public class AccessorNamingTests
{
    [Theory]
    [InlineData("get_Name", "Name")]
    [InlineData("set_Name", "Name")]
    [InlineData("add_Changed", "Changed")]
    [InlineData("remove_Changed", "Changed")]
    [InlineData("get_Item", "Item")] // indexer accessor
    public void RecognizesAllFourAccessorPrefixes(string memberName, string expectedNatural)
    {
        Assert.True(AccessorNaming.TryGetNaturalName(memberName, out var natural));
        Assert.Equal(expectedNatural, natural);
    }

    [Theory]
    [InlineData("Name")] // no prefix at all
    [InlineData("GetName")] // no underscore — not the accessor shape
    [InlineData("get_")] // prefix with nothing after it: not a valid natural name
    [InlineData("")]
    public void LeavesNonAccessorNamesAlone(string memberName)
    {
        Assert.False(AccessorNaming.TryGetNaturalName(memberName, out _));
    }
}
