using System.Net;
using System.Security.Cryptography;
using System.Text;
using WebAuthn.Net.FidoConformance.Constants;

namespace WebAuthn.Net.FidoConformance.Services.ConformanceMetadata;

public class LocalFilesFidoMetadataHttpClientDelegatingHandler : DelegatingHandler
{
    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var jwtBlobs = GetJwtBlobsContents();
        if (jwtBlobs.Length > 0)
        {
            var index = RandomNumberGenerator.GetInt32(0, jwtBlobs.Length);
            var result = jwtBlobs[index];
            return new(HttpStatusCode.OK)
            {
                Content = new StringContent(result, Encoding.UTF8)
            };
        }

        return new(HttpStatusCode.NotFound);
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        return Task.FromResult(Send(request, cancellationToken));
    }

    private static DirectoryInfo? GetConformanceMetadataDirectory()
    {
        var assemblyDirectory = new FileInfo(typeof(LocalFilesFidoMetadataProviderForMdsTests).Assembly.Location).Directory;
        if (assemblyDirectory is null || !assemblyDirectory.Exists)
        {
            throw new InvalidOperationException("Failed to retrieve the path to the current assembly on disk");
        }

        return assemblyDirectory
            .GetDirectories()
            .FirstOrDefault(static x => string.Equals(x.Name, FidoConformanceMetadata.RootDirectory, StringComparison.OrdinalIgnoreCase));
    }

    private static string[] GetJwtBlobsContents()
    {
        var conformanceMetadata = GetConformanceMetadataDirectory();
        var jwtDirectory = conformanceMetadata?
            .GetDirectories()
            .FirstOrDefault(static x => string.Equals(x.Name, FidoConformanceMetadata.JwtBlobsSubdirectory, StringComparison.OrdinalIgnoreCase));
        var jwtBlobs = jwtDirectory?
            .GetFiles()
            .Where(static x => !string.Equals(x.Extension, ".gitkeep", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (jwtBlobs is not null)
        {
            var result = new string[jwtBlobs.Length];
            for (var i = 0; i < jwtBlobs.Length; i++)
            {
                result[i] = File.ReadAllText(jwtBlobs[i].FullName).Trim();
            }

            return result;
        }

        return Array.Empty<string>();
    }
}
