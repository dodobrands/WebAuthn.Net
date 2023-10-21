using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

public class DefaultFidoMetadataDecoderTests
{
    private FakeFidoMetadataHttpClientProvider FakeFidoHttpClientProvider { get; set; } = null!;
    private DefaultFidoMetadataProvider MetadataProvider { get; set; } = null!;
    private DefaultFidoMetadataDecoder Decoder { get; set; } = null!;
    private MetadataBLOBPayloadJSON PayloadToDecode { get; set; } = null!;

    [SetUp]
    public async Task SetupServices()
    {
        FakeFidoHttpClientProvider = new();
        MetadataProvider = new(FakeFidoHttpClientProvider.Client, new FakeTimeProvider(DateTimeOffset.Parse("2023-10-20T16:36:38Z", CultureInfo.InvariantCulture)));
        Decoder = new();
        var result = await MetadataProvider.DownloadMetadataAsync(CancellationToken.None);
        if (result.HasError)
        {
            throw new InvalidOperationException("Can't get metadata to decode");
        }

        PayloadToDecode = result.Ok;
    }

    [TearDown]
    public virtual void TearDownServices()
    {
        FakeFidoHttpClientProvider.Dispose();
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenCorrectDataProvided()
    {
        var result = Decoder.Decode(PayloadToDecode);
        Assert.That(result.HasError, Is.False);
        Assert.That(result.Ok, Is.Not.Null);
    }
}
