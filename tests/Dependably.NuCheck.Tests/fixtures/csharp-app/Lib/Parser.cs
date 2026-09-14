namespace FixtureLib;

public static class Parser
{
    public static string? ReadName(string json) => JObject.Parse(json)["name"]?.ToString();
}
