using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;
using NUnit.Framework;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.Implementation.DefaultRegistrationCeremonyService.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation.DefaultRegistrationCeremonyService.AttestationTypes;

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
                new("testuser", userId, "TestUser"),
                32,
                new[]
                {
                    CoseAlgorithm.ES256,
                    CoseAlgorithm.ES384,
                    CoseAlgorithm.ES512
                },
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
            WebEncoders.Base64UrlDecode("3ZwhSB6AQF4jz08tgB6sijflji9bSoX5_h4m0W0jxVY"));

        var completeResult = await RegistrationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                beginResult.RegistrationCeremonyId,
                null,
                new(
                    "1TPkqBH5D0bQwj75jU-33Q",
                    "1TPkqBH5D0bQwj75jU-33Q",
                    new(
                        "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiM1p3aFNCNkFRRjRqejA4dGdCNnNpamZsamk5YlNvWDVfaDRtMFcwanhWWSIsIm9yaWdpbiI6Imh0dHBzOi8vdmFuYnVraW4tcGMubG9jYWwiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                        null,
                        null,
                        null,
                        null,
                        "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhALMFIEFDsFDfHPMJC1jJWyJZ3iz2qf7bO7E2CgE4Il4nAiEAjfbpqAIDjz1CZ3qpb9V44f8GmuEFpBXCVYHdDfhMw_tjeDVjgVkCwTCCAr0wggGloAMCAQICBBisRsAwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG4xCzAJBgNVBAYTAlNFMRIwEAYDVQQKDAlZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xJzAlBgNVBAMMHll1YmljbyBVMkYgRUUgU2VyaWFsIDQxMzk0MzQ4ODBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHnqOyx8SXAQYiMM0j_rYOUpMXHUg_EAvoWdaw-DlwMBtUbN1G7PyuPj8w-B6e1ivSaNTB69N7O8vpKowq7rTjqjbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS43MBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEMtpSB6P90A5k-wKJymhVKgwDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAl50Dl9hg-C7hXTEceW66-yL6p-CE2bq0xhu7V_PmtMGKSDe4XDxO2-SDQ_TWpdmxztqK4f7UkSkhcwWOXuHL3WvawHVXxqDo02gluhWef7WtjNr4BIaM-Q6PH4rqF8AWtVwqetSXyJT7cddT15uaSEtsN21yO5mNLh1DBr8QM7Wu-Myly7JWi2kkIm0io1irfYfkrF8uCRqnFXnzpWkJSX1y9U4GusHDtEE7ul6vlMO2TzT566Qay2rig3dtNkZTeEj-6IS93fWxuleYVM_9zrrDRAWVJ-Vt1Zj49WZxWr5DAd0ZETDmufDGQDkSU-IpgD867ydL7b_eP8u9QurWeWhhdXRoRGF0YViUwbGR7JKb_3nCDS_Zb_TxyUe4a4rtFXaAsGAUBoQQGPVFAAAAAMtpSB6P90A5k-wKJymhVKgAENUz5KgR-Q9G0MI--Y1Pt92lAQIDJiABIVggWNcMr1648LHadL8fnnKyfbuvsxEFouKGoOZrhTnuSJwiWCAJAJdLG5K9XexTMiAg3rbnyQd_1NNu-d5Q3o39RCdlew"
                    ),
                    null,
                    new(),
                    "public-key")),
            CancellationToken.None);
        Assert.That(completeResult.HasError, Is.False);
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
                new[]
                {
                    CoseAlgorithm.RS256,
                    CoseAlgorithm.RS384,
                    CoseAlgorithm.RS512
                },
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

        var completeResult = await RegistrationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                beginResult.RegistrationCeremonyId,
                null,
                new(
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
                    new(),
                    "public-key")),
            CancellationToken.None);
        Assert.That(completeResult.HasError, Is.False);
    }
}
