using System;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.DSL;

public static class JsonToVerify
{
    private static readonly Assembly SelfAssembly = typeof(JsonToVerify).Assembly;
    private static readonly string[] ResourceNames = SelfAssembly.GetManifestResourceNames();

    public static string GetResourceByMethodName<T>(this T caller, [CallerMemberName] string jsonFileName = "")
    {
        var @namespace = caller!.GetType().Namespace;
        var resourceName = $"{@namespace}.{jsonFileName}.json";
        if (!ResourceNames.Contains(resourceName))
        {
            throw new ArgumentException($"Can't locate json resource file: {resourceName}");
        }

        using var resourceStream = SelfAssembly.GetManifestResourceStream(resourceName);
        if (resourceStream is null)
        {
            throw new ArgumentException($"Can't read json resource file: {resourceName}");
        }

        var jsonDocument = JsonSerializer.Deserialize<JsonDocument>(resourceStream);
        var unindentedValue = JsonSerializer.Serialize(jsonDocument, new JsonSerializerOptions(JsonSerializerDefaults.General)
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never,
            WriteIndented = false
        });
        return unindentedValue;
    }
}
