using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using WebAuthn.Net.FidoConformance.Constants;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

namespace WebAuthn.Net.FidoConformance.Services;

public class LocalFilesFidoMetadataProvider : IFidoMetadataProvider
{
    public Task<Result<MetadataBLOBPayloadJSON>> DownloadMetadataAsync(CancellationToken cancellationToken)
    {
        var metadataDirectory = GetMetadataDirectory();
        var blob = BuildMetadataBlobPayload(metadataDirectory);
        var result = Result<MetadataBLOBPayloadJSON>.Success(blob);
        return Task.FromResult(result);
    }

    [SuppressMessage("Globalization", "CA1309:Use ordinal string comparison")]
    private static DirectoryInfo GetMetadataDirectory()
    {
        var location = new FileInfo(typeof(LocalFilesFidoMetadataProvider).Assembly.Location).Directory;
        if (location is null)
        {
            throw new InvalidOperationException("Failed to retrieve the path to the current assembly on disk");
        }

        var metadataDirectory = location
            .GetDirectories()
            .FirstOrDefault(static x => string.Equals(x.Name, FidoConformanceMetadata.DirectoryName, StringComparison.InvariantCultureIgnoreCase));
        if (metadataDirectory is null)
        {
            throw new InvalidOperationException($"The metadata directory \"{FidoConformanceMetadata.DirectoryName}\" does not exist in the folder \"{location.FullName}\"");
        }

        return metadataDirectory;
    }

    [SuppressMessage("Globalization", "CA1309:Use ordinal string comparison")]
    private static MetadataBLOBPayloadJSON BuildMetadataBlobPayload(DirectoryInfo metadataDirectory)
    {
        var entries = new List<MetadataBLOBPayloadEntryJSON>();
        var jsons = metadataDirectory
            .GetFiles()
            .Where(static x => string.Equals(x.Extension, ".json", StringComparison.InvariantCultureIgnoreCase))
            .ToArray();
        foreach (var json in jsons)
        {
            var fileContent = File.ReadAllText(json.FullName);
            var metadataStatement = JsonSerializer.Deserialize<MetadataStatementJSON>(fileContent);
            if (metadataStatement is null)
            {
                throw new InvalidOperationException($"The JSON file \"{json.FullName}\" does not contain a valid set of metadata ({nameof(MetadataStatementJSON)})");
            }

            var entry = new MetadataBLOBPayloadEntryJSON(
                metadataStatement.Aaid,
                metadataStatement.Aaguid,
                metadataStatement.AttestationCertificateKeyIdentifiers,
                metadataStatement,
                null,
                new StatusReportJSON[]
                {
                    new(
                        "FIDO_CERTIFIED",
                        "2023-11-15",
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null)
                },
                "2023-11-15",
                null,
                null);
            entries.Add(entry);
        }

        return new(null, 1, "2023-12-01", entries.ToArray());
    }
}
