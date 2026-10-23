using System;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.Implementation.DefaultRegistrationCeremonyService.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateCredential;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation.DefaultRegistrationCeremonyService.AttestationTypes;

public class DefaultRegistrationCeremonyServiceFidoU2FTests : AbstractRegistrationCeremonyServiceTests
{
    // The attestation certificate of the test vector ("Yubico U2F EE Serial 413943488") carries the id-fido-gen-ce-aaguid extension with the aaguid of the fido2 entry for "YubiKey 5 Series",
    // and the u2f entry for "YubiKey 5 Series" lists its key identifier (RFC 5280 §4.2.1.2 method (1)) in 'attestationCertificateKeyIdentifiers'; the committed blob.jwt has both entries.
    private static readonly Guid YubiKey5SeriesAaguid = Guid.Parse("cb69481e-8ff7-4039-93ec-0a2729a154a8");

    private static readonly byte[] AttestationCertificateKeyIdentifier = Convert.FromHexString("bdeb7f015a66e4c8448b414ffd41ca669bba6b4a");

    protected override Uri GetRelyingPartyAddress()
    {
        return new("https://vanbukin-pc.local", UriKind.Absolute);
    }

    [Test]
    public async Task DefaultRegistrationCeremonyService_PerformsCeremonyWithoutErrorsForFidoU2F_WhenES256()
    {
        var completeResult = await CompleteCeremonyAsync();
        Assert.That(completeResult.HasError, Is.False);
    }

    [Test]
    public async Task DefaultRegistrationCeremonyService_PerformsCeremonyForFidoU2F_WhenMetadataListsAttestationCertificateOnlyByKeyIdentifier()
    {
        // there is no entry for the aaguid from the extension of the attestation certificate, so the root certificates come from the u2f entry found by the key identifier of the certificate
        await UpsertMetadataWithoutYubiKey5SeriesAaguidEntryAsync(null);

        var completeResult = await CompleteCeremonyAsync();

        Assert.That(completeResult.HasError, Is.False);
    }

    [TestCase(AuthenticatorStatus.REVOKED)]
    [TestCase(AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE)]
    public async Task DefaultRegistrationCeremonyService_FailsCeremonyForFidoU2F_WhenEntryFoundByKeyIdentifierIsUntrusted(AuthenticatorStatus status)
    {
        await UpsertMetadataWithoutYubiKey5SeriesAaguidEntryAsync(status);

        var completeResult = await CompleteCeremonyAsync();

        Assert.Multiple(() =>
        {
            Assert.That(completeResult.HasError, Is.True);
            Assert.That(FidoMetadataCounters.LookupsWithUntrustedEntry, Is.EqualTo(1));
            Assert.That(
                FidoMetadataSearchLogger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.Exactly(1).EqualTo($"The status reports of the FIDO Metadata Service entry for the authenticator with the attestation certificate key identifier {Convert.ToHexString(AttestationCertificateKeyIdentifier)} don't allow to trust the authenticator: FIDO_CERTIFIED_L1, FIDO_CERTIFIED, {status}"));
        });
    }

    // Replaces the metadata in use with a copy of the downloaded blob without the fido2 entry for "YubiKey 5 Series",
    // in which the u2f entry that lists the key identifier of the attestation certificate has one more status report with the status (if it is specified).
    private async Task UpsertMetadataWithoutYubiKey5SeriesAaguidEntryAsync(AuthenticatorStatus? status)
    {
        var entries = MetadataBlob.Entries
            .Where(static x => x.Aaguid != YubiKey5SeriesAaguid)
            .Select(x =>
            {
                if (!status.HasValue || x.AttestationCertificateKeyIdentifiers?.Any(static y => y.AsSpan().SequenceEqual(AttestationCertificateKeyIdentifier)) != true)
                {
                    return x;
                }

                var statusReport = new StatusReport(status.Value, null, null, null, null, null, null, null, null, null, null, null, null, null);
                return new MetadataBlobPayloadEntry(
                    x.Aaid,
                    x.Aaguid,
                    x.AttestationCertificateKeyIdentifiers,
                    x.MetadataStatement,
                    x.BiometricStatusReports,
                    x.StatusReports.Append(statusReport).ToArray(),
                    x.TimeOfLastStatusChange,
                    x.RogueListUrl,
                    x.RogueListHash);
            })
            .ToArray();
        Assert.That(entries, Has.Length.EqualTo(MetadataBlob.Entries.Length - 1), "the blob must have the fido2 entry for \"YubiKey 5 Series\"");
        await MetadataStorage.UpsertAsync(
            new(MetadataBlob.LegalHeader, MetadataBlob.No, MetadataBlob.NextUpdate, entries),
            CancellationToken.None);
    }

    private async Task<Result<CompleteRegistrationCeremonyResult>> CompleteCeremonyAsync()
    {
        TimeProvider.Change(DateTimeOffset.Parse("2023-10-17T15:01:40Z", CultureInfo.InvariantCulture));
        var userId = WebEncoders.Base64UrlDecode("AAAAAAAAAAAAAAAAAAAAAQ");
        var beginResult = await RegistrationCeremonyService.BeginCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                null,
                null,
                "Test Host",
                new("testuser", userId, "Test User"),
                32,
                new[] { CoseAlgorithm.ES256 },
                60000,
                RegistrationCeremonyExcludeCredentials.AllExisting(),
                new(AuthenticatorAttachment.CrossPlatform, ResidentKeyRequirement.Discouraged, false, UserVerificationRequirement.Discouraged),
                null,
                AttestationConveyancePreference.Indirect,
                null,
                null),
            CancellationToken.None);

        RegistrationCeremonyStorage.ReplaceChallengeForRegistrationCeremonyOptions(
            beginResult.RegistrationCeremonyId,
            WebEncoders.Base64UrlDecode("rVani_oJjMSJUzQQAvBh-Tjm04RfWN-eKTtP2sz_-Bs"));

        var completeResult = await RegistrationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                beginResult.RegistrationCeremonyId,
                null,
                new(
                    "Ox696mJ0yDpYMNjNAqSJIbkuvaPEk9CTyMMrvUxCwVWKJblMwcd1zzNyVf7ngMA3X5dewF6-2YDKjrgkghmAZg",
                    "Ox696mJ0yDpYMNjNAqSJIbkuvaPEk9CTyMMrvUxCwVWKJblMwcd1zzNyVf7ngMA3X5dewF6-2YDKjrgkghmAZg",
                    new(
                        "eyJjaGFsbGVuZ2UiOiJyVmFuaV9vSmpNU0pVelFRQXZCaC1Uam0wNFJmV04tZUtUdFAyc3pfLUJzIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cHM6Ly92YW5idWtpbi1wYy5sb2NhbCIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ",
                        null,
                        null,
                        null,
                        null,
                        "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIhAIoXOleqpuK0zDF9sra0FzgoqprGiCiHNKM5Y1jtYEUvAiAT9fVtclAXv0jN5wkMAVwRv-o8iJ3zx0cI97ShjCwFIWN4NWOBWQLBMIICvTCCAaWgAwIBAgIEGKxGwDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNDEzOTQzNDg4MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeeo7LHxJcBBiIwzSP-tg5SkxcdSD8QC-hZ1rD4OXAwG1Rs3Ubs_K4-PzD4Hp7WK9Jo1MHr03s7y-kqjCrutOOqNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQEEgQQy2lIHo_3QDmT7AonKaFUqDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCXnQOX2GD4LuFdMRx5brr7Ivqn4ITZurTGG7tX8-a0wYpIN7hcPE7b5IND9Nal2bHO2orh_tSRKSFzBY5e4cvda9rAdVfGoOjTaCW6FZ5_ta2M2vgEhoz5Do8fiuoXwBa1XCp61JfIlPtx11PXm5pIS2w3bXI7mY0uHUMGvxAzta74zKXLslaLaSQibSKjWKt9h-SsXy4JGqcVefOlaQlJfXL1Tga6wcO0QTu6Xq-Uw7ZPNPnrpBrLauKDd202RlN4SP7ohL3d9bG6V5hUz_3OusNEBZUn5W3VmPj1ZnFavkMB3RkRMOa58MZAORJT4imAPzrvJ0vtv94_y71C6tZ5aGF1dGhEYXRhWMTBsZHskpv_ecINL9lv9PHJR7hriu0VdoCwYBQGhBAY9UEAAAAAAAAAAAAAAAAAAAAAAAAAAABAOx696mJ0yDpYMNjNAqSJIbkuvaPEk9CTyMMrvUxCwVWKJblMwcd1zzNyVf7ngMA3X5dewF6-2YDKjrgkghmAZqUBAgMmIAEhWCAqy0-eN0gKEEZcHDXkDaypB74Pnmt2eX7uIciUbsdvkiJYIJ5gWGOaiJ0ClZUP8cP2I5oJueu1w07xf7Erftp36wn0"
                    ),
                    null,
                    new(),
                    "public-key")),
            CancellationToken.None);
        return completeResult;
    }
}
