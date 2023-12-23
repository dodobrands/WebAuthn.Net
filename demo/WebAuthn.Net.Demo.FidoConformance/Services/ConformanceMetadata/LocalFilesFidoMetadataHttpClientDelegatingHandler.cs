using System.Net;
using System.Text;
using WebAuthn.Net.Demo.FidoConformance.Constants;

namespace WebAuthn.Net.Demo.FidoConformance.Services.ConformanceMetadata;

public class LocalFilesFidoMetadataHttpClientDelegatingHandler : DelegatingHandler
{
    private readonly string[] _jwtBlobContents = GetJwtBlobsContents();
    private int _calls = -1;

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (_jwtBlobContents.Length > 0)
        {
            var calls = Interlocked.Increment(ref _calls);
            var index = calls % _jwtBlobContents.Length;
            var result = _jwtBlobContents[index];
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
