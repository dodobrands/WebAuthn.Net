using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

namespace WebAuthn.Net.DSL;

public static class EmbeddedResourceProvider
{
    private static readonly Assembly SelfAssembly = typeof(EmbeddedResourceProvider).Assembly;
    private static readonly string[] ResourceNames = SelfAssembly.GetManifestResourceNames();

    public static string GetString(string resourceName)
    {
        if (!ResourceNames.Contains(resourceName))
        {
            throw new ArgumentException($"The assembly is missing an embedded resource: '{resourceName}'");
        }

        using var resourceStream = SelfAssembly.GetManifestResourceStream(resourceName);
        if (resourceStream is null)
        {
            throw new ArgumentException($"Failed to read the embedded resource: '{resourceName}' from the assembly");
        }

        using var memoryStream = new MemoryStream();
        resourceStream.CopyTo(memoryStream);
        memoryStream.Seek(0L, SeekOrigin.Begin);
        var resourceBytes = memoryStream.ToArray();
        return Encoding.UTF8.GetString(resourceBytes);
    }
}
