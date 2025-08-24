using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;
using WebAuthn.Net.Demo.FidoConformance.Constants;
using WebAuthn.Net.Demo.FidoConformance.Services.ConformanceMetadata.Models;

namespace WebAuthn.Net.Demo.FidoConformance.Services.ConformanceMetadata;

public class LocalFilesFidoMetadataHttpClientDelegatingHandler : DelegatingHandler
{
    private readonly LocalFileBlobInfo[] _jwtBlobContents = GetJwtBlobsContents();
    private readonly object _lock = new();

    private readonly ILogger<LocalFilesFidoMetadataHttpClientDelegatingHandler> _logger;
    private int _index;

    public LocalFilesFidoMetadataHttpClientDelegatingHandler(ILogger<LocalFilesFidoMetadataHttpClientDelegatingHandler> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
    }

    [SuppressMessage("Performance", "CA1848:Use the LoggerMessage delegates")]
    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        HttpResponseMessage? result = null;
        if (_jwtBlobContents.Length > 0)
        {
            lock (_lock)
            {
                if (_index < _jwtBlobContents.Length)
                {
                    var jwtBlob = _jwtBlobContents[_index];
                    _index++;
                    result = new(HttpStatusCode.OK)
                    {
                        Content = new StringContent(jwtBlob.Content, Encoding.UTF8)
                    };
                    _logger.LogInformation("Provide {BlobIndex} / {TotalBlobs} blob {FilePath}", _index, _jwtBlobContents.Length, jwtBlob.FileName);
                }
            }
        }

        return result ?? new(HttpStatusCode.NotFound);
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

    private static LocalFileBlobInfo[] GetJwtBlobsContents()
    {
        var conformanceMetadata = GetConformanceMetadataDirectory();
        var jwtDirectory = conformanceMetadata?
            .GetDirectories()
            .FirstOrDefault(static x => string.Equals(x.Name, FidoConformanceMetadata.JwtBlobsSubdirectory, StringComparison.OrdinalIgnoreCase));
        var jwtBlobs = jwtDirectory?
            .GetFiles()
            .Where(static x => !string.Equals(x.Extension, ".gitkeep", StringComparison.OrdinalIgnoreCase))
            .OrderBy(x => x.Name)
            .ToArray();
        if (jwtBlobs is not null)
        {
            var result = new LocalFileBlobInfo[jwtBlobs.Length];
            for (var i = 0; i < jwtBlobs.Length; i++)
            {
                var content = File.ReadAllText(jwtBlobs[i].FullName, Encoding.UTF8).Trim();
                result[i] = new(jwtBlobs[i].Name, content);
            }

            return result;
        }

        return [];
    }
}
