using System.Text.Json;
using WebAuthn.Net.FidoConformance.Constants;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

namespace WebAuthn.Net.FidoConformance.Services.ConformanceMetadata;

public class LocalFilesFidoMetadataProvider : IFidoMetadataProvider
{
    public Task<Result<MetadataBLOBPayloadJSON>> DownloadMetadataAsync(CancellationToken cancellationToken)
    {
        var blob = BuildMetadataBlobPayload();
        var result = Result<MetadataBLOBPayloadJSON>.Success(blob);
        return Task.FromResult(result);
    }

    private static DirectoryInfo? GetConformanceMetadataDirectory()
    {
        var assemblyDirectory = new FileInfo(typeof(LocalFilesFidoMetadataProvider).Assembly.Location).Directory;
        if (assemblyDirectory is null || !assemblyDirectory.Exists)
        {
            throw new InvalidOperationException("Failed to retrieve the path to the current assembly on disk");
        }

        return assemblyDirectory
            .GetDirectories()
            .FirstOrDefault(static x => string.Equals(x.Name, FidoConformanceMetadata.RootDirectory, StringComparison.OrdinalIgnoreCase));
    }

    private static MetadataBLOBPayloadJSON BuildMetadataBlobPayload()
    {
        var entries = new List<MetadataBLOBPayloadEntryJSON>();

        var jsonsDirectory = GetConformanceMetadataDirectory()?
            .GetDirectories()
            .FirstOrDefault(x => string.Equals(x.Name, FidoConformanceMetadata.MetadataStatementsSubdirectory, StringComparison.OrdinalIgnoreCase));

        var jsons = jsonsDirectory?
            .GetFiles()
            .Where(static x => string.Equals(x.Extension, ".json", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (jsons is not null)
        {
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
        }

        return new(null, 1, "2023-12-01", entries.ToArray());
    }
}
