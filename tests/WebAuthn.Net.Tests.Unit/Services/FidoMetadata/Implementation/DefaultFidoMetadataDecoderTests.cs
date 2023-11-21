﻿using System;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;
using WebAuthn.Net.Services.Serialization.Json.Implementation;

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
        Decoder = new(
            new DefaultEnumMemberAttributeSerializer<UserVerificationMethod>(),
            new DefaultEnumMemberAttributeSerializer<ProtocolFamily>(),
            new DefaultEnumMemberAttributeSerializer<AuthenticationAlgorithm>(),
            new DefaultEnumMemberAttributeSerializer<PublicKeyRepresentationFormat>(),
            new DefaultEnumMemberAttributeSerializer<AuthenticatorAttestationType>(),
            new DefaultEnumMemberAttributeSerializer<KeyProtectionType>(),
            new DefaultEnumMemberAttributeSerializer<MatcherProtectionType>(),
            new DefaultEnumMemberAttributeSerializer<AuthenticatorAttachmentHint>(),
            new DefaultEnumMemberAttributeSerializer<TransactionConfirmationDisplayType>());
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
        var res = result.Ok!.Entries
            .Where(x => x.MetadataStatement is not null)
            .Where(x => x.MetadataStatement!.AttestationTypes.Length > 1)
            .ToArray();
        Assert.That(result.HasError, Is.False);
        Assert.That(result.Ok, Is.Not.Null);
    }
}
