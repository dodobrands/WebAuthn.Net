using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;
using NUnit.Framework;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.Implementation.DefaultRegistrationCeremonyService.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation.DefaultRegistrationCeremonyService;

public class DefaultRegistrationCeremonyServicePackedTests : AbstractRegistrationCeremonyServiceTests
{
    protected override Uri GetRelyingPartyAddress()
    {
        return new("https://vanbukin-pc.local", UriKind.Absolute);
    }

    [Test]
    public async Task DefaultRegistrationCeremonyService_PerformsCeremonyWithoutErrorsForPacked_WhenEcdsa()
    {
        var userId = WebEncoders.Base64UrlDecode("AAAAAAAAAAAAAAAAAAAAAQ");
        var beginResult = await RegistrationCeremonyService.BeginCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                null,
                null,
                "Test Host",
                new("testuser", userId, "Test User"),
                32,
                new[] { CoseAlgorithm.ES256, CoseAlgorithm.ES384, CoseAlgorithm.ES512 },
                60000,
                RegistrationCeremonyExcludeCredentials.AllExisting(),
                new(AuthenticatorAttachment.CrossPlatform, ResidentKeyRequirement.Preferred, null, UserVerificationRequirement.Required),
                null,
                AttestationConveyancePreference.Direct,
                null,
                null),
            CancellationToken.None);

        RegistrationCeremonyStorage.ReplaceChallengeForRegistrationCeremonyOptions(
            beginResult.RegistrationCeremonyId,
            WebEncoders.Base64UrlDecode("BovzZs80dwqI2a0BgC8tZDhK-fsOwuVZoLCIEd8L4To"));

        var competeResult = await RegistrationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(beginResult.RegistrationCeremonyId, new(
                "Ad0ybczQPZQaipL4U7QY5Q",
                "Ad0ybczQPZQaipL4U7QY5Q",
                new(
                    "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQm92elpzODBkd3FJMmEwQmdDOHRaRGhLLWZzT3d1VlpvTENJRWQ4TDRUbyIsIm9yaWdpbiI6Imh0dHBzOi8vdmFuYnVraW4tcGMubG9jYWwiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                    null,
                    null,
                    null,
                    null,
                    "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAJtgvdI0ln58pR3Quad35dZ94lhcCaSDeaKmKUuB-gQWAiBk-c80ej_qDgltZoUPkROXWbGMUOy3BFldO8Bv21jqLGN4NWOBWQLBMIICvTCCAaWgAwIBAgIEGKxGwDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNDEzOTQzNDg4MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeeo7LHxJcBBiIwzSP-tg5SkxcdSD8QC-hZ1rD4OXAwG1Rs3Ubs_K4-PzD4Hp7WK9Jo1MHr03s7y-kqjCrutOOqNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQEEgQQy2lIHo_3QDmT7AonKaFUqDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCXnQOX2GD4LuFdMRx5brr7Ivqn4ITZurTGG7tX8-a0wYpIN7hcPE7b5IND9Nal2bHO2orh_tSRKSFzBY5e4cvda9rAdVfGoOjTaCW6FZ5_ta2M2vgEhoz5Do8fiuoXwBa1XCp61JfIlPtx11PXm5pIS2w3bXI7mY0uHUMGvxAzta74zKXLslaLaSQibSKjWKt9h-SsXy4JGqcVefOlaQlJfXL1Tga6wcO0QTu6Xq-Uw7ZPNPnrpBrLauKDd202RlN4SP7ohL3d9bG6V5hUz_3OusNEBZUn5W3VmPj1ZnFavkMB3RkRMOa58MZAORJT4imAPzrvJ0vtv94_y71C6tZ5aGF1dGhEYXRhWJTBsZHskpv_ecINL9lv9PHJR7hriu0VdoCwYBQGhBAY9UUAAAABy2lIHo_3QDmT7AonKaFUqAAQAd0ybczQPZQaipL4U7QY5aUBAgMmIAEhWCAn3JT1Hqb9d8Ruop8XYC7RmAhLNL5gy__UBWvujC9s6CJYIK28tTIwbeJW7EDlk3S0nBI86qECt_narzAXY5ZyK-2G"
                ),
                null,
                null,
                "public-key")),
            CancellationToken.None);
        Assert.That(competeResult.Successful, Is.True);
    }

    [Test]
    public async Task DefaultRegistrationCeremonyService_PerformsCeremonyWithoutErrorsForPacked_WhenRsaPkcs()
    {
        var userId = WebEncoders.Base64UrlDecode("AAAAAAAAAAAAAAAAAAAAAQ");
        var beginResult = await RegistrationCeremonyService.BeginCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                null,
                null,
                "Test Host",
                new("testuser", userId, "Test User"),
                32,
                new[] { CoseAlgorithm.RS256, CoseAlgorithm.RS384, CoseAlgorithm.RS512 },
                60000,
                RegistrationCeremonyExcludeCredentials.AllExisting(),
                new(AuthenticatorAttachment.CrossPlatform, ResidentKeyRequirement.Preferred, null, UserVerificationRequirement.Required),
                null,
                AttestationConveyancePreference.Direct,
                null,
                null),
            CancellationToken.None);

        RegistrationCeremonyStorage.ReplaceChallengeForRegistrationCeremonyOptions(
            beginResult.RegistrationCeremonyId,
            WebEncoders.Base64UrlDecode("sDkwMsjdpl071DJDnjcLZtZUD3ZobaU8By9vt5LNVVE"));

        var competeResult = await RegistrationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(beginResult.RegistrationCeremonyId, new(
                "e8dWaw2dBs0abtzy9nKlIA",
                "e8dWaw2dBs0abtzy9nKlIA",
                new(
                    "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoic0Rrd01zamRwbDA3MURKRG5qY0xadFpVRDNab2JhVThCeTl2dDVMTlZWRSIsIm9yaWdpbiI6Imh0dHBzOi8vdmFuYnVraW4tcGMubG9jYWwiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                    null,
                    null,
                    null,
                    null,
                    "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhANakX_MmDXmCgcq5nXZBRQOahBrXXJM-kDW7sG3N7sflAiB9uoTvLO1sdEWeNhYa-5688Wogu7aqJRnYTGaYe6_dYGN4NWOBWQLBMIICvTCCAaWgAwIBAgIEGKxGwDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNDEzOTQzNDg4MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeeo7LHxJcBBiIwzSP-tg5SkxcdSD8QC-hZ1rD4OXAwG1Rs3Ubs_K4-PzD4Hp7WK9Jo1MHr03s7y-kqjCrutOOqNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQEEgQQy2lIHo_3QDmT7AonKaFUqDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCXnQOX2GD4LuFdMRx5brr7Ivqn4ITZurTGG7tX8-a0wYpIN7hcPE7b5IND9Nal2bHO2orh_tSRKSFzBY5e4cvda9rAdVfGoOjTaCW6FZ5_ta2M2vgEhoz5Do8fiuoXwBa1XCp61JfIlPtx11PXm5pIS2w3bXI7mY0uHUMGvxAzta74zKXLslaLaSQibSKjWKt9h-SsXy4JGqcVefOlaQlJfXL1Tga6wcO0QTu6Xq-Uw7ZPNPnrpBrLauKDd202RlN4SP7ohL3d9bG6V5hUz_3OusNEBZUn5W3VmPj1ZnFavkMB3RkRMOa58MZAORJT4imAPzrvJ0vtv94_y71C6tZ5aGF1dGhEYXRhWQFXwbGR7JKb_3nCDS_Zb_TxyUe4a4rtFXaAsGAUBoQQGPVFAAAABMtpSB6P90A5k-wKJymhVKgAEHvHVmsNnQbNGm7c8vZypSCkAQMDOQEAIFkBAMIUtnAH5NLEHDuCfnRYCxj_EE9sfKSK1RSIr9g_AFfPDDrxKXieJq-sCJxdNh5K3eOGMW8z8Qk2G7ceo1oppNL4rWNDmjlIU_-ccFJjYy1Uncqd5MRF_UO7mDyY33CBkAumYufSAmAKTTWqSw2O-Nlh2J0dt_Sgtdp8k7BNuHMg3BiYLKpnX-0VxUY0EowV0r_jN0IXM0wPvyMyU212hW7-qnUyoCokHUB7fyETC5EXs4mWrWjkCRdDimzuVMCblLhPov-r-7j8XQTRH27TPP8ZPJTX7o7zfFrj3pB337qLu5H91gAvwl0eDv6t605GWrUEbKlzJkATdXFB0kti07MhQwEAAQ"
                ),
                null,
                null,
                "public-key")),
            CancellationToken.None);
        Assert.That(competeResult.Successful, Is.True);
    }
}
