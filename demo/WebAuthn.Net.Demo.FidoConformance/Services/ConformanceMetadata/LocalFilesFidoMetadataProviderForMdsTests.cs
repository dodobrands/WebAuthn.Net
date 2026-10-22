using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Polly;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Demo.FidoConformance.Constants;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Json;

namespace WebAuthn.Net.Demo.FidoConformance.Services.ConformanceMetadata;

public class LocalFilesFidoMetadataProviderForMdsTests : DefaultFidoMetadataProvider
{
    private readonly ConformanceCrlRevocationChecker _crlRevocationChecker;
    private readonly ResiliencePipeline<Result<MetadataBLOBPayloadJSON>> _resiliencePipeline;

    public LocalFilesFidoMetadataProviderForMdsTests(
        IOptionsMonitor<WebAuthnOptions> options,
        ISafeJsonSerializer safeJsonSerializer,
        IFidoMetadataHttpClient metadataHttpClient,
        ITimeProvider timeProvider,
        IFidoMetadataCounters counters,
        ILogger<DefaultFidoMetadataProvider> logger,
        ConformanceCrlRevocationChecker crlRevocationChecker,
        ResiliencePipeline<Result<MetadataBLOBPayloadJSON>> resiliencePipeline)
        : base(options, safeJsonSerializer, metadataHttpClient, timeProvider, counters, logger)
    {
        ArgumentNullException.ThrowIfNull(crlRevocationChecker);
        ArgumentNullException.ThrowIfNull(resiliencePipeline);
        _crlRevocationChecker = crlRevocationChecker;
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

    // The chain engine is configured not to check the revocation (see ConformanceCrlRevocationChecker.ConfigureFidoMetadataBlobJwtChain),
    // so the revocation of every certificate of the blob signing chain is checked here against the CRLs from their distribution points.
    protected override Task<bool> ValidateJwtCertificateChainAsync(X509Chain chain, CancellationToken cancellationToken)
    {
        return _crlRevocationChecker.IsChainNotRevokedAsync(chain, cancellationToken);
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


    private MetadataBLOBPayloadEntryJSON[] GetMetadataStatements()
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
                MetadataStatementJSON? metadataStatement;
                try
                {
                    metadataStatement = JsonSerializer.Deserialize<MetadataStatementJSON>(fileContent);
                }
                catch (JsonException exception)
                {
                    // A single malformed metadata statement must not prevent the other statements from being loaded.
                    Logger.WarnMetadataStatementFileSkipped(exception, json.FullName);
                    continue;
                }

                if (metadataStatement is null)
                {
                    Logger.WarnMetadataStatementFileEmpty(json.FullName);
                    continue;
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

        Logger.InfoMetadataStatementsLoaded(result.Count, jsons?.Length ?? 0);
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

/// <summary>
///     Extension methods for logging the loading of the metadata statements from the local files.
/// </summary>
public static partial class LocalFilesFidoMetadataProviderForMdsTestsLoggingExtensions
{
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The metadata statement file '{File}' was skipped because it can't be deserialized into MetadataStatementJSON")]
    public static partial void WarnMetadataStatementFileSkipped(this ILogger logger, Exception exception, string file);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The metadata statement file '{File}' was skipped because it is empty")]
    public static partial void WarnMetadataStatementFileEmpty(this ILogger logger, string file);

    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "{Loaded} of {Total} metadata statement files were loaded and merged into the FIDO Metadata Service blob")]
    public static partial void InfoMetadataStatementsLoaded(this ILogger logger, int loaded, int total);
}
