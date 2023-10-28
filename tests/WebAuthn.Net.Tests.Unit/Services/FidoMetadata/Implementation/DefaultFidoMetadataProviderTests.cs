﻿using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

public class DefaultFidoMetadataProviderTests
{
    private FakeFidoMetadataHttpClientProvider FakeFidoHttpClientProvider { get; set; } = null!;
    private DefaultFidoMetadataProvider MetadataProvider { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        FakeFidoHttpClientProvider = new();
        MetadataProvider = new(FakeFidoHttpClientProvider.Client, new FakeTimeProvider(DateTimeOffset.Parse("2023-10-20T16:36:38Z", CultureInfo.InvariantCulture)));
    }

    [TearDown]
    public virtual void TearDownServices()
    {
        FakeFidoHttpClientProvider.Dispose();
    }

    [Test]
    public async Task DefaultFidoMetadataProvider_DownloadMetadata_WhenCorrectDataDownloaded()
    {
        var result = await MetadataProvider.DownloadMetadataAsync(CancellationToken.None);
        Assert.That(result.HasError, Is.False);
        Assert.That(result.Ok, Is.Not.Null);
    }
}