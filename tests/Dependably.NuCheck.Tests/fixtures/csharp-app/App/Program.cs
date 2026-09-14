using Newtonsoft.Json;

#if NET472
using CsvHelper;
#endif

namespace FixtureApp;

public static class Program
{
    public static void Main(string[] args)
    {
        var payload = JsonConvert.SerializeObject(new { args });
        // Fully-qualified use, no using directive:
        Serilog.Log.Information("payload: {Payload}", payload);
    }
}
