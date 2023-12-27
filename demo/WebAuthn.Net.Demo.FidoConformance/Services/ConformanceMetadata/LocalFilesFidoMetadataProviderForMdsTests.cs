using System.Text.Json;
using Microsoft.Extensions.Options;
using Polly;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Demo.FidoConformance.Constants;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Json;

namespace WebAuthn.Net.Demo.FidoConformance.Services.ConformanceMetadata;

public class LocalFilesFidoMetadataProviderForMdsTests : DefaultFidoMetadataProvider
{
    private readonly ResiliencePipeline<Result<MetadataBLOBPayloadJSON>> _resiliencePipeline;

    public LocalFilesFidoMetadataProviderForMdsTests(
        IOptionsMonitor<WebAuthnOptions> options,
        ISafeJsonSerializer safeJsonSerializer,
        IFidoMetadataHttpClient metadataHttpClient,
        ITimeProvider timeProvider,
        ResiliencePipeline<Result<MetadataBLOBPayloadJSON>> resiliencePipeline)
        : base(options, safeJsonSerializer, metadataHttpClient, timeProvider)
    {
        ArgumentNullException.ThrowIfNull(resiliencePipeline);
        _resiliencePipeline = resiliencePipeline;
    }

    public override async Task<Result<MetadataBLOBPayloadJSON>> DownloadMetadataAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = await _resiliencePipeline.ExecuteAsync(
            async static (self, ct) => await self.DownloadMetadataAsyncCore(ct),
            this,
            cancellationToken);
        return result;
    }

    private async Task<Result<MetadataBLOBPayloadJSON>> DownloadMetadataAsyncCore(CancellationToken cancellationToken)
    {
        var result = await base.DownloadMetadataAsync(cancellationToken);
        if (result.HasError)
        {
            return result;
        }

        var metadataStatements = GetMetadataStatements();
        var mergedResult = MergeEntries(result.Ok, metadataStatements);
        return Result<MetadataBLOBPayloadJSON>.Success(mergedResult);
    }

    private static MetadataBLOBPayloadJSON MergeEntries(MetadataBLOBPayloadJSON src, MetadataBLOBPayloadEntryJSON[] entries)
    {
        var result = new List<MetadataBLOBPayloadEntryJSON>(src.Entries);
        foreach (var entry in entries)
        {
            if (!string.IsNullOrEmpty(entry.Aaid) && !string.IsNullOrEmpty(entry.Aaguid))
            {
                var existing = result.Where(x => x.Aaid == entry.Aaid || x.Aaguid == entry.Aaguid).ToArray();
                foreach (var entryToRemove in existing)
                {
                    result.Remove(entryToRemove);
                }
            }
            else if (!string.IsNullOrEmpty(entry.Aaid))
            {
                var existing = result.Where(x => x.Aaid == entry.Aaid).ToArray();
                foreach (var entryToRemove in existing)
                {
                    result.Remove(entryToRemove);
                }
            }
            else if (!string.IsNullOrEmpty(entry.Aaguid))
            {
                var existing = result.Where(x => x.Aaguid == entry.Aaguid).ToArray();
                foreach (var entryToRemove in existing)
                {
                    result.Remove(entryToRemove);
                }
            }


            result.Add(entry);
        }

        return new(src.LegalHeader, src.No, src.NextUpdate, result.ToArray());
    }


    private static MetadataBLOBPayloadEntryJSON[] GetMetadataStatements()
    {
        var result = new List<MetadataBLOBPayloadEntryJSON>();

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
                result.Add(entry);
            }
        }

        return result.ToArray();
    }

    protected override UniqueByteArraysCollection GetEmbeddedFidoRootCertificates()
    {
        return new(GetRootCertificates());
    }

    private static byte[][] GetRootCertificates()
    {
        var rootDirectory = GetConformanceMetadataDirectory();
        var rootCertificate = rootDirectory
            .GetDirectories()
            .FirstOrDefault(static x => string.Equals(x.Name, FidoConformanceMetadata.RootCertificateSubdirectory, StringComparison.OrdinalIgnoreCase));
        if (rootCertificate is null || !rootCertificate.Exists)
        {
            throw new InvalidOperationException($"Missing \"{FidoConformanceMetadata.RootCertificateSubdirectory}\"");
        }

        var certificates = rootCertificate
            .GetFiles()
            .Where(static x => string.Equals(x.Extension, ".crt", StringComparison.OrdinalIgnoreCase)
                               || string.Equals(x.Extension, ".der", StringComparison.OrdinalIgnoreCase)
                               || string.Equals(x.Extension, ".cer", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var result = new List<byte[]>();
        foreach (var certificate in certificates)
        {
            var rootCertBytes = File.ReadAllBytes(certificate.FullName);
            result.Add(rootCertBytes);
        }

        if (result.Count == 0)
        {
            throw new InvalidOperationException($"\"{FidoConformanceMetadata.RootCertificateSubdirectory}\" is empty. Add conformance metadata root certificate.");
        }

        return result.ToArray();
    }

    private static DirectoryInfo GetConformanceMetadataDirectory()
    {
        var assemblyDirectory = new FileInfo(typeof(LocalFilesFidoMetadataProviderForMdsTests).Assembly.Location).Directory;
        if (assemblyDirectory is null || !assemblyDirectory.Exists)
        {
            throw new InvalidOperationException("Failed to retrieve the path to the current assembly on disk");
        }

        var conformanceMetadata = assemblyDirectory
            .GetDirectories()
            .FirstOrDefault(static x => string.Equals(x.Name, FidoConformanceMetadata.RootDirectory, StringComparison.OrdinalIgnoreCase));
        if (conformanceMetadata is null || !conformanceMetadata.Exists)
        {
            throw new InvalidOperationException($"The conformance metadata directory \"{FidoConformanceMetadata.RootDirectory}\" does not exist in the folder \"{assemblyDirectory.FullName}\"");
        }

        return conformanceMetadata;
    }
}
