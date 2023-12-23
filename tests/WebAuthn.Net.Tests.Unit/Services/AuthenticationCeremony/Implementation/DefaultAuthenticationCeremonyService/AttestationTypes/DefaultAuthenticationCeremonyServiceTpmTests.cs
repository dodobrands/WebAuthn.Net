﻿using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;
using NUnit.Framework;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.AuthenticationCeremony.Implementation.DefaultAuthenticationCeremonyService.Abstractions;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Implementation.DefaultAuthenticationCeremonyService.AttestationTypes;

public class DefaultAuthenticationCeremonyServiceTpmTests : AbstractAuthenticationCeremonyServiceTests
{
    protected override Uri GetRelyingPartyAddress()
    {
        return new("https://vanbukin-pc.local", UriKind.Absolute);
    }

    [SetUp]
    public async Task SetupRegistrationAsync()
    {
        await SetupEcdsaRegistrationAsync();
        await SetupRsaPkcsRegistrationAsync();
    }

    private async Task SetupEcdsaRegistrationAsync()
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
                    CoseAlgorithm.ES256,
                    CoseAlgorithm.ES384,
                    CoseAlgorithm.ES512
                },
                60000,
                RegistrationCeremonyExcludeCredentials.AllExisting(),
                new(AuthenticatorAttachment.Platform, null, null, UserVerificationRequirement.Required),
                null,
                AttestationConveyancePreference.Direct,
                null,
                null),
            CancellationToken.None);

        RegistrationCeremonyStorage.ReplaceChallengeForRegistrationCeremonyOptions(
            beginResult.RegistrationCeremonyId,
            WebEncoders.Base64UrlDecode("4x0-q1nnHnlgJsgwMfTURzR2wcTOPEFadn4TCXaKW6Y"));

        var completeResult = await RegistrationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                beginResult.RegistrationCeremonyId,
                null,
                new(
                    "4Ty0Cs5bPOCvOv_7IF3ve3oG7Sr52xECQI_uEfrshhE",
                    "4Ty0Cs5bPOCvOv_7IF3ve3oG7Sr52xECQI_uEfrshhE",
                    new(
                        "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiNHgwLXExbm5IbmxnSnNnd01mVFVSelIyd2NUT1BFRmFkbjRUQ1hhS1c2WSIsIm9yaWdpbiI6Imh0dHBzOi8vdmFuYnVraW4tcGMubG9jYWwiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                        null,
                        null,
                        null,
                        null,
                        "o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn__mNzaWdZAQCyBDz37cp_eEyGVSAhDgYE-EtprDjrsnwUD2FuWrEpdVRzLZteiKfqsxCDslRLvMye9raQyBMQLR6L9q_IAeKJP1ArQvHGDCloAv46kpx300SDUp4nA_vP7kS180FKjmbm20zfHdk5dEHskFnNksbi96eQK1YuK2wUrudlAZ2MwgWjSQtX_eTVlOghhI6wwkFxwoX4oDuPiF6o_fv5RhvjSTwwPoOcb8SD736sRhM8HYPQTmQ7dO9bko-U3X-3eUrJXTrSLYehLZ4Q9mBHHAaR1pp9C296_O1Agh1je8KTZgXVqGfOBEpX9FLoGx_vfCfKiGXoPRlDUWlrxYTRnn3hY3ZlcmMyLjBjeDVjglkFuzCCBbcwggOfoAMCAQICEBWVq6zFF0c7iiQdgQCWL-wwDQYJKoZIhvcNAQELBQAwQTE_MD0GA1UEAxM2RVVTLUFNRC1LRVlJRC1CQzhFQUMxMDg0NEY1QzdFQkZFOEJBQzJDRUI1MEU4Q0RGMzRFRjg4MB4XDTIzMTAwNTE3NDcxNloXDTI4MDQxNDE4MjkyMFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALWqOarMTXdWEyM8QLK7YJUtMeJRecG2cxezCI0rxR7gzRriuaYFCf5qkgc0SVjknDz6qBz_bp-7CG-7IP4PT_65PZarjskCVSW_6uOt2g0KAcseG-_08JCndFQnXUCmoIbpgZ7ZmJUqJfhTHdX0v1mYlZe4QvtUsJqucYOcYSiHMiHI_eM52p3DdW3KEakKrG5vjr_QShLDKCrJ_te_yAWqrs4dTC9Ut_fSlgCiDRzwazJAA0ZaXRYfU7RzHNnb7tqKDD3lyF6zCSw0qF39Iqr5tDiW7PHNBtSn8GEhrHs5nVuf_v6j-17U_ByBCNPlNqb4MPk6vhZgEzzVYANFnbUCAwEAAaOCAeowggHmMA4GA1UdDwEB_wQEAwIHgDAMBgNVHRMBAf8EAjAAMG0GA1UdIAEB_wRjMGEwXwYJKwYBBAGCNxUfMFIwUAYIKwYBBQUHAgIwRB5CAFQAQwBQAEEAIAAgAFQAcgB1AHMAdABlAGQAIAAgAFAAbABhAHQAZgBvAHIAbQAgACAASQBkAGUAbgB0AGkAdAB5MBAGA1UdJQQJMAcGBWeBBQgDMFAGA1UdEQEB_wRGMESkQjBAMRYwFAYFZ4EFAgEMC2lkOjQxNEQ0NDAwMQ4wDAYFZ4EFAgIMA0FNRDEWMBQGBWeBBQIDDAtpZDowMDAzMDAwMTAfBgNVHSMEGDAWgBR3E2MbHcNeIfGHGxCZHZ8L4MGNwjAdBgNVHQ4EFgQUDrrdtNqzpqMCfaTQQfCvLIjeFIkwgbIGCCsGAQUFBwEBBIGlMIGiMIGfBggrBgEFBQcwAoaBkmh0dHA6Ly9hemNzcHJvZGV1c2Fpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L2V1cy1hbWQta2V5aWQtYmM4ZWFjMTA4NDRmNWM3ZWJmZThiYWMyY2ViNTBlOGNkZjM0ZWY4OC80ZDNkZjQ2Mi1kYWQyLTRlNTUtYThmMC1hN2IyNmYwYWEzZmMuY2VyMA0GCSqGSIb3DQEBCwUAA4ICAQAqoj8hVQPX0wmVgO6FhH7qOh5mHDpMceR0HIVDk_UIIIeg8G3-oK0jb-eVltwd9bgdO3zJVfLDLWpABddrCisXxu7D5uIWLGE_rjllHS8hosxMRLsFuTrWT3sFgjloyxFbjTPPfE6DQuNgFI85odzBvaPMMFwNrt_LGt0Uw00_aMBBvAsv0SUgUgb7kXWT8kE4fzDwlVrYvbl-Expa1eEavMnugL-l4fNB7DZsyXpc7hwQDL3QU-rcqRMW60UC7b3x5ghsMJDfoubthZ856lBUdQtUg-ZxE2hOHd3fa_FhlxPXbnIL3L7yTbLCgCbcpgiQ0qPDs65KOJI8k0-FIN3LSoVxgevEIBKY1zfRbiS5oo_7AlhMD28G0-HYlYUFqGe9BhuVi5zjld96yJfRNqjV7zYTbIx-CRfFyjM0Ynqp477oFC-jfc2WQmrSI-GQD7bZ9j6o9puZS4QEoipjDPfwl4h47bKME_lDMMSvSpoc4-wVTcmgPMFfXpHEqRyNEzoRBQfH8kkxvGL0z6hrSDShV6C0p5PubFLH4aTm5BeIV43DY7jdlP39yU12bKnFEARmKp-lzYjUHrze-qRDyesDTuhM8e8ok69KDBwgz-_n_F6UBZnEwppI32fZ6rVK_B_1lbi4EZ2AJG5wIduIEHs3pdfDm_--xFjgfkG9Vcj-xFkG7zCCBuswggTToAMCAQICEzMAAAd7jiICI2S3Wc4AAAAAB3swDQYJKoZIhvcNAQELBQAwgYwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNjA0BgNVBAMTLU1pY3Jvc29mdCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxNDAeFw0yMjA0MTQxODI5MjBaFw0yODA0MTQxODI5MjBaMEExPzA9BgNVBAMTNkVVUy1BTUQtS0VZSUQtQkM4RUFDMTA4NDRGNUM3RUJGRThCQUMyQ0VCNTBFOENERjM0RUY4ODCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKODi9d9Um54NFsCyBsYsYOLTVPMqa9XewhPIpScPQ2_8iS9CDvIolHmViWpzNcUVwCEPWy_bbtFHeUEQeZ0My3nP21tT__Zc_BGJs4XO9ys78B1Zpp1_6mh3KoesxMjYhrdzLtIGI_RzxCff3FzYK3pFCBPz3uxBtwMsq1ckNr1GsWfZBOLjKRoYDEKM0mqd6cAaIm_IR6oWC2zulJQSmlHz35MxW_OF7MQZHt1n0PwLekZ4udfxsy6L5zfRFhJCE_Enq8ggSETBgFTNImYKpQllOcfojEF3axUnIPZmIsJNWIWSX5WyCfKD1Rfju3IntIQArY221N8BV8tALcUFeGKGBPYN10pYb1KLcdkhdvJGpqOhmAhvSVF9rxMLlzOnrWiEXVsO1YU3hSmR3WGHg8ahbCxKyBGfISYgx9bVMYijvQA33dfPJEcigHLZmqOOlLFA5td3m_hWIyD76dXkY6Cy483wtKGUdRYrjN94JMOY14PhUpFpIh-KKaPFjwKab93u9dfX_jWbmPBdUrmL2aHGUVg8ljU_-pQj9aObXPYngjomFJJ4e0kJFe4au6gTVRRMqXePkwBcmPsbhxWBR07u9nY5EGYOpikTiicOp0hRmZ-b9qn2i_r8hCSzAVeRMsbujOfgmQtIAMXeF8wjWg41f5tbgXKxR_lRGI6ojz1AgMBAAGjggGOMIIBijAOBgNVHQ8BAf8EBAMCAoQwGwYDVR0lBBQwEgYJKwYBBAGCNxUkBgVngQUIAzAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzASBgNVHRMBAf8ECDAGAQH_AgEAMB0GA1UdDgQWBBR3E2MbHcNeIfGHGxCZHZ8L4MGNwjAfBgNVHSMEGDAWgBR6jArOL0hiF-KU0a5VwVLscXSkVjBwBgNVHR8EaTBnMGWgY6Bhhl9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUUE0lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDE0LmNybDB9BggrBgEFBQcBAQRxMG8wbQYIKwYBBQUHMAKGYWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcnQwDQYJKoZIhvcNAQELBQADggIBAExrsXgXU6oRgruZcut7iICBfJj3tIuDi5OTzzdnvmHeNI0jPLk7NW8qoDdRUW8Xc8LoIxga8M_-5s88oflyhDGRPToO_uqg2DxcatGy-WxMnboGnlVYjt-kbvuMJCtxLC_3PkCtkC2uKXxTwpTEweokBSuISdcaJDk7rutWiAcmXAB4VKO1KiZajc-h7HjchVy58-CE7E2rLaHuOlQKkROahSsbTb-OZhsoRhT6Oky71mlgYwIsWHyPulVcliIy6VSM1ih7E93d2CVctz1WcbxLnmW9_liK_UyXYIKk1YVFMCeFu9DJC9LcK2wmQ_Bzn8K98RnWF5bisDmS184dQAppNRsqkjWH8p4MhvYyazDeQzIuS2wIw1wTBa4iiRFNzbT0OUcX68VO1mUJKgSN2USHLW8YO1OTJhcTvYVxIeJxezvCi31cqGDiy5jREfNTio4bKzvkDjPDn-i9p592ccLxyZzAErNB6aj3dWNy9UXNzdRzSbrgOJxxaqvN5qoCv3e97OSj191_DZPj7aOQhfhM4DqGFrORySRCGK0gIJhLhSp4sQseI98Dii-CESIhGvjKB0eSCdelwQQDtTqXmWhfx8IctXLxca2dOsNMHSvVpcIua8OgS-PTSAHfwGbh-0CrfSQdhehcMHapu5Hu0D9Ub0vDZCDvIcqJ2jp40KSlZ3B1YkFyZWFYdgAjAAsABAByACCd_8vzbDg65pn7mGjcbcuJ1xU4hL4oA5IsEkFYv60irgAQABAAAwAQACAsv9rh7Zftq17lwnFVeTD8_yRFC0tFfM1UnFEO96ESggAg7ezYLoGfNnzGDge314AkOepy1jMPQkg6arxK74GcN1xoY2VydEluZm9Yof9UQ0eAFwAiAAvJ3_Ntou3kY-doNaZ7AYWYcNvyUpq14nbL_2G66MDAhgAUeJUZev4NFKIkGH8VafqWFUbOJeQAAAAC-uLtG83fbhgHoiSYAbw9Zk4_EQokACIACwOitKzxslmEbGaD3PM-p2kk7Oimus9P6GihRtz4CMUeACIAC38AlxhQxanAEgXl9S_YOFYPHnSjNXH_EJ4hgzPhYOjkaGF1dGhEYXRhWKTBsZHskpv_ecINL9lv9PHJR7hriu0VdoCwYBQGhBAY9UUAAAAACJhwWMrcS4G24TDeUNy-lgAg4Ty0Cs5bPOCvOv_7IF3ve3oG7Sr52xECQI_uEfrshhGlAQIDJiABIVggLL_a4e2X7ate5cJxVXkw_P8kRQtLRXzNVJxRDvehEoIiWCDt7NgugZ82fMYOB7fXgCQ56nLWMw9CSDpqvErvgZw3XA"
                    ),
                    null,
                    new(),
                    "public-key")),
            CancellationToken.None);
        Assert.That(completeResult.HasError, Is.False);
    }

    private async Task SetupRsaPkcsRegistrationAsync()
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
                new(AuthenticatorAttachment.Platform, null, null, UserVerificationRequirement.Required),
                null,
                AttestationConveyancePreference.Direct,
                null,
                null),
            CancellationToken.None);

        RegistrationCeremonyStorage.ReplaceChallengeForRegistrationCeremonyOptions(
            beginResult.RegistrationCeremonyId,
            WebEncoders.Base64UrlDecode("r8bwKDi4O_mRtPDj6RxxQtdKKcfoCTj_f_Bd_07taoo"));

        var completeResult = await RegistrationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                beginResult.RegistrationCeremonyId,
                null,
                new(
                    "lrA87WnB7tFuif1m5qghLIeOH8yn109USo6wq31EVjA",
                    "lrA87WnB7tFuif1m5qghLIeOH8yn109USo6wq31EVjA",
                    new(
                        "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoicjhid0tEaTRPX21SdFBEajZSeHhRdGRLS2Nmb0NUal9mX0JkXzA3dGFvbyIsIm9yaWdpbiI6Imh0dHBzOi8vdmFuYnVraW4tcGMubG9jYWwiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                        null,
                        null,
                        null,
                        null,
                        "o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn__mNzaWdZAQCK21mSjJlYRipS1cVylixSEF_TlaYKRwSRsQVmmgndlsUVrcliKPRSWBkCR4mDfSiOLsXr3Gi1AaB734uxaDKx74PVDNy_yFZ2Z0xlzc5KNyamZVTTNAsBQYB-Dvo2CsBwQS9GH5w7n_X9yROAwChUV8GDye2dBxt3-SYEWgcTQA7mRMGQKbh8esmrDy8pFwrkTqfUF_CguZomZtyFapgMuFeLzrhHyH1thcL2Fms4COhvMNYz6QXWYQcupMsP8Q3YtRbUZjUmW6yl2Dv39vtBiM3dWISWib1nC_e63xTqSf2kr8JKxRWpNq2pWN17yOmSKHakV6Y_gJk1uHguDKBTY3ZlcmMyLjBjeDVjglkFuzCCBbcwggOfoAMCAQICEBWVq6zFF0c7iiQdgQCWL-wwDQYJKoZIhvcNAQELBQAwQTE_MD0GA1UEAxM2RVVTLUFNRC1LRVlJRC1CQzhFQUMxMDg0NEY1QzdFQkZFOEJBQzJDRUI1MEU4Q0RGMzRFRjg4MB4XDTIzMTAwNTE3NDcxNloXDTI4MDQxNDE4MjkyMFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALWqOarMTXdWEyM8QLK7YJUtMeJRecG2cxezCI0rxR7gzRriuaYFCf5qkgc0SVjknDz6qBz_bp-7CG-7IP4PT_65PZarjskCVSW_6uOt2g0KAcseG-_08JCndFQnXUCmoIbpgZ7ZmJUqJfhTHdX0v1mYlZe4QvtUsJqucYOcYSiHMiHI_eM52p3DdW3KEakKrG5vjr_QShLDKCrJ_te_yAWqrs4dTC9Ut_fSlgCiDRzwazJAA0ZaXRYfU7RzHNnb7tqKDD3lyF6zCSw0qF39Iqr5tDiW7PHNBtSn8GEhrHs5nVuf_v6j-17U_ByBCNPlNqb4MPk6vhZgEzzVYANFnbUCAwEAAaOCAeowggHmMA4GA1UdDwEB_wQEAwIHgDAMBgNVHRMBAf8EAjAAMG0GA1UdIAEB_wRjMGEwXwYJKwYBBAGCNxUfMFIwUAYIKwYBBQUHAgIwRB5CAFQAQwBQAEEAIAAgAFQAcgB1AHMAdABlAGQAIAAgAFAAbABhAHQAZgBvAHIAbQAgACAASQBkAGUAbgB0AGkAdAB5MBAGA1UdJQQJMAcGBWeBBQgDMFAGA1UdEQEB_wRGMESkQjBAMRYwFAYFZ4EFAgEMC2lkOjQxNEQ0NDAwMQ4wDAYFZ4EFAgIMA0FNRDEWMBQGBWeBBQIDDAtpZDowMDAzMDAwMTAfBgNVHSMEGDAWgBR3E2MbHcNeIfGHGxCZHZ8L4MGNwjAdBgNVHQ4EFgQUDrrdtNqzpqMCfaTQQfCvLIjeFIkwgbIGCCsGAQUFBwEBBIGlMIGiMIGfBggrBgEFBQcwAoaBkmh0dHA6Ly9hemNzcHJvZGV1c2Fpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L2V1cy1hbWQta2V5aWQtYmM4ZWFjMTA4NDRmNWM3ZWJmZThiYWMyY2ViNTBlOGNkZjM0ZWY4OC80ZDNkZjQ2Mi1kYWQyLTRlNTUtYThmMC1hN2IyNmYwYWEzZmMuY2VyMA0GCSqGSIb3DQEBCwUAA4ICAQAqoj8hVQPX0wmVgO6FhH7qOh5mHDpMceR0HIVDk_UIIIeg8G3-oK0jb-eVltwd9bgdO3zJVfLDLWpABddrCisXxu7D5uIWLGE_rjllHS8hosxMRLsFuTrWT3sFgjloyxFbjTPPfE6DQuNgFI85odzBvaPMMFwNrt_LGt0Uw00_aMBBvAsv0SUgUgb7kXWT8kE4fzDwlVrYvbl-Expa1eEavMnugL-l4fNB7DZsyXpc7hwQDL3QU-rcqRMW60UC7b3x5ghsMJDfoubthZ856lBUdQtUg-ZxE2hOHd3fa_FhlxPXbnIL3L7yTbLCgCbcpgiQ0qPDs65KOJI8k0-FIN3LSoVxgevEIBKY1zfRbiS5oo_7AlhMD28G0-HYlYUFqGe9BhuVi5zjld96yJfRNqjV7zYTbIx-CRfFyjM0Ynqp477oFC-jfc2WQmrSI-GQD7bZ9j6o9puZS4QEoipjDPfwl4h47bKME_lDMMSvSpoc4-wVTcmgPMFfXpHEqRyNEzoRBQfH8kkxvGL0z6hrSDShV6C0p5PubFLH4aTm5BeIV43DY7jdlP39yU12bKnFEARmKp-lzYjUHrze-qRDyesDTuhM8e8ok69KDBwgz-_n_F6UBZnEwppI32fZ6rVK_B_1lbi4EZ2AJG5wIduIEHs3pdfDm_--xFjgfkG9Vcj-xFkG7zCCBuswggTToAMCAQICEzMAAAd7jiICI2S3Wc4AAAAAB3swDQYJKoZIhvcNAQELBQAwgYwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNjA0BgNVBAMTLU1pY3Jvc29mdCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxNDAeFw0yMjA0MTQxODI5MjBaFw0yODA0MTQxODI5MjBaMEExPzA9BgNVBAMTNkVVUy1BTUQtS0VZSUQtQkM4RUFDMTA4NDRGNUM3RUJGRThCQUMyQ0VCNTBFOENERjM0RUY4ODCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKODi9d9Um54NFsCyBsYsYOLTVPMqa9XewhPIpScPQ2_8iS9CDvIolHmViWpzNcUVwCEPWy_bbtFHeUEQeZ0My3nP21tT__Zc_BGJs4XO9ys78B1Zpp1_6mh3KoesxMjYhrdzLtIGI_RzxCff3FzYK3pFCBPz3uxBtwMsq1ckNr1GsWfZBOLjKRoYDEKM0mqd6cAaIm_IR6oWC2zulJQSmlHz35MxW_OF7MQZHt1n0PwLekZ4udfxsy6L5zfRFhJCE_Enq8ggSETBgFTNImYKpQllOcfojEF3axUnIPZmIsJNWIWSX5WyCfKD1Rfju3IntIQArY221N8BV8tALcUFeGKGBPYN10pYb1KLcdkhdvJGpqOhmAhvSVF9rxMLlzOnrWiEXVsO1YU3hSmR3WGHg8ahbCxKyBGfISYgx9bVMYijvQA33dfPJEcigHLZmqOOlLFA5td3m_hWIyD76dXkY6Cy483wtKGUdRYrjN94JMOY14PhUpFpIh-KKaPFjwKab93u9dfX_jWbmPBdUrmL2aHGUVg8ljU_-pQj9aObXPYngjomFJJ4e0kJFe4au6gTVRRMqXePkwBcmPsbhxWBR07u9nY5EGYOpikTiicOp0hRmZ-b9qn2i_r8hCSzAVeRMsbujOfgmQtIAMXeF8wjWg41f5tbgXKxR_lRGI6ojz1AgMBAAGjggGOMIIBijAOBgNVHQ8BAf8EBAMCAoQwGwYDVR0lBBQwEgYJKwYBBAGCNxUkBgVngQUIAzAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzASBgNVHRMBAf8ECDAGAQH_AgEAMB0GA1UdDgQWBBR3E2MbHcNeIfGHGxCZHZ8L4MGNwjAfBgNVHSMEGDAWgBR6jArOL0hiF-KU0a5VwVLscXSkVjBwBgNVHR8EaTBnMGWgY6Bhhl9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUUE0lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDE0LmNybDB9BggrBgEFBQcBAQRxMG8wbQYIKwYBBQUHMAKGYWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcnQwDQYJKoZIhvcNAQELBQADggIBAExrsXgXU6oRgruZcut7iICBfJj3tIuDi5OTzzdnvmHeNI0jPLk7NW8qoDdRUW8Xc8LoIxga8M_-5s88oflyhDGRPToO_uqg2DxcatGy-WxMnboGnlVYjt-kbvuMJCtxLC_3PkCtkC2uKXxTwpTEweokBSuISdcaJDk7rutWiAcmXAB4VKO1KiZajc-h7HjchVy58-CE7E2rLaHuOlQKkROahSsbTb-OZhsoRhT6Oky71mlgYwIsWHyPulVcliIy6VSM1ih7E93d2CVctz1WcbxLnmW9_liK_UyXYIKk1YVFMCeFu9DJC9LcK2wmQ_Bzn8K98RnWF5bisDmS184dQAppNRsqkjWH8p4MhvYyazDeQzIuS2wIw1wTBa4iiRFNzbT0OUcX68VO1mUJKgSN2USHLW8YO1OTJhcTvYVxIeJxezvCi31cqGDiy5jREfNTio4bKzvkDjPDn-i9p592ccLxyZzAErNB6aj3dWNy9UXNzdRzSbrgOJxxaqvN5qoCv3e97OSj191_DZPj7aOQhfhM4DqGFrORySRCGK0gIJhLhSp4sQseI98Dii-CESIhGvjKB0eSCdelwQQDtTqXmWhfx8IctXLxca2dOsNMHSvVpcIua8OgS-PTSAHfwGbh-0CrfSQdhehcMHapu5Hu0D9Ub0vDZCDvIcqJ2jp40KSlZ3B1YkFyZWFZATYAAQALAAYEcgAgnf_L82w4OuaZ-5ho3G3LidcVOIS-KAOSLBJBWL-tIq4AEAAQCAAAAAAAAQDFDUWoiW3cyTF1U1_JXxw7LXpUDgM5C9yT3MnttgDi-pCXUWKy_uVjy01YNPBjM5mVAY2n3u1BZuCywXKMI14rF9lP75X3wcrglfjT8HjJLMJBBQyzb590VF6JN_IZTLIKru8ABB7AC0HGcEQ9OhsYVRPG7bQe9IaQMrWbLu-WLnxKC0kbBbiwWCHV0yUDjlwzr9ZVgDpuDpUPcFw1KR2znKr3lqI7xighrNTZu3OehrQ5KqU7qP7qY-bmArjAkqJyIyCDvHMsnPXesLLQ1zGnpI3suohkrnjP0hbDZ074E4ZgIk0qDxTzCMbxVGFZ_eTnDAcURGb7_Cf_LSmuRFDLaGNlcnRJbmZvWKH_VENHgBcAIgALyd_zbaLt5GPnaDWmewGFmHDb8lKateJ2y_9huujAwIYAFJiWZNORqhB90ezuUD1PiN-4eBDkAAAAAvri7RvN324YB6IkmAG8PWZOPxEKJAAiAAsJ_1MoAQe5NSYcoHJnEnfkrviEq0oYWLwB3NWmQBO2EgAiAAvWAlj5mIfOmc3b5ZSHHN1OrnChuexo6MVctkho2ulrvGhhdXRoRGF0YVkBZ8GxkeySm_95wg0v2W_08clHuGuK7RV2gLBgFAaEEBj1RQAAAAAImHBYytxLgbbhMN5Q3L6WACCWsDztacHu0W6J_WbmqCEsh44fzKfXT1RKjrCrfURWMKQBAwM5AQAgWQEAxQ1FqIlt3MkxdVNfyV8cOy16VA4DOQvck9zJ7bYA4vqQl1Fisv7lY8tNWDTwYzOZlQGNp97tQWbgssFyjCNeKxfZT--V98HK4JX40_B4ySzCQQUMs2-fdFReiTfyGUyyCq7vAAQewAtBxnBEPTobGFUTxu20HvSGkDK1my7vli58SgtJGwW4sFgh1dMlA45cM6_WVYA6bg6VD3BcNSkds5yq95aiO8YoIazU2btznoa0OSqlO6j-6mPm5gK4wJKiciMgg7xzLJz13rCy0Ncxp6SN7LqIZK54z9IWw2dO-BOGYCJNKg8U8wjG8VRhWf3k5wwHFERm-_wn_y0prkRQyyFDAQAB"
                    ),
                    null,
                    new(),
                    "public-key")),
            CancellationToken.None);
        Assert.That(completeResult.HasError, Is.False);
    }

    [Test]
    public async Task DefaultAuthenticationCeremonyService_PerformsCeremonyWithoutErrorsForTpm_WhenEcdsa()
    {
        var beginRequest = new BeginAuthenticationCeremonyRequest(
            null,
            null,
            null,
            32,
            60000,
            null,
            UserVerificationRequirement.Required,
            null,
            null,
            null,
            null);
        var beginResult = await AuthenticationCeremonyService.BeginCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            beginRequest,
            CancellationToken.None);

        AuthenticationCeremonyStorage.ReplaceChallengeForAuthenticationCeremonyOptions(
            beginResult.AuthenticationCeremonyId,
            WebEncoders.Base64UrlDecode("yw5GgV3aHLT0rKGOppwRSdKavos9Ev_Qy7f7jU2VHyY"));

        var completeResult = await AuthenticationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(beginResult.AuthenticationCeremonyId,
                new("4Ty0Cs5bPOCvOv_7IF3ve3oG7Sr52xECQI_uEfrshhE",
                    "4Ty0Cs5bPOCvOv_7IF3ve3oG7Sr52xECQI_uEfrshhE",
                    new("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoieXc1R2dWM2FITFQwcktHT3Bwd1JTZEthdm9zOUV2X1F5N2Y3alUyVkh5WSIsIm9yaWdpbiI6Imh0dHBzOi8vdmFuYnVraW4tcGMubG9jYWwiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                        "wbGR7JKb_3nCDS_Zb_TxyUe4a4rtFXaAsGAUBoQQGPUFAAAAAQ",
                        "MEUCIQDRxkvjn5ZH5xCPkbQz_xKXrrlKzWdyg5PfGAzxdEAA0wIgK8LqEx7_VR6JNtY3ssoYmqqYNLu1adiiG73EOCYKRQM",
                        "AAAAAAAAAAAAAAAAAAAAAQ",
                        null),
                    null,
                    new(),
                    "public-key")),
            CancellationToken.None);
        Assert.That(completeResult.HasError, Is.False);
    }

    [Test]
    public async Task DefaultAuthenticationCeremonyService_PerformsCeremonyWithoutErrorsForTpm_WhenRsaPkcs()
    {
        var beginRequest = new BeginAuthenticationCeremonyRequest(
            null,
            null,
            null,
            32,
            60000,
            null,
            UserVerificationRequirement.Required,
            null,
            null,
            null,
            null);
        var beginResult = await AuthenticationCeremonyService.BeginCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            beginRequest,
            CancellationToken.None);

        AuthenticationCeremonyStorage.ReplaceChallengeForAuthenticationCeremonyOptions(
            beginResult.AuthenticationCeremonyId,
            WebEncoders.Base64UrlDecode("aR8ghlSX-2TEPZ4B8slObm_rvHS3p17AnXAYyhJ0Cm8"));

        var completeResult = await AuthenticationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(beginResult.AuthenticationCeremonyId,
                new("lrA87WnB7tFuif1m5qghLIeOH8yn109USo6wq31EVjA",
                    "lrA87WnB7tFuif1m5qghLIeOH8yn109USo6wq31EVjA",
                    new("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiYVI4Z2hsU1gtMlRFUFo0QjhzbE9ibV9ydkhTM3AxN0FuWEFZeWhKMENtOCIsIm9yaWdpbiI6Imh0dHBzOi8vdmFuYnVraW4tcGMubG9jYWwiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                        "wbGR7JKb_3nCDS_Zb_TxyUe4a4rtFXaAsGAUBoQQGPUFAAAAAQ",
                        "SSQnknI6v9589-_YIYGHqyA8dBFLPHi9mUcfPXTFlN3H90Fi-muuBhDUPXvcipkQtKcBflAXkiiMcTWuLPudfEozJjvQW3ak-P7hnVn2a_vzgfOreVWPjYmBWOWkQB_Fz3xxKI-AZseCAXzRhFcGDk7jb8b8fuvKui0wd-xsSGKvR6j0BNpyWDog7Mt6klmD11bYon4ihy_E2JRIHuudjdlHd0StVv6rPYPbu8T7rOF8Ibo6s70WpPAYOF4Ab8xi6hhwzRNl6ROqXxeM8egNIqUQEUF1EggZ3DBRokg2ePru9wXXVzkC4m33Cqak3ZbVI01jyb1P31Mb4Dyq1c7WyQ",
                        "AAAAAAAAAAAAAAAAAAAAAQ",
                        null),
                    null,
                    new(),
                    "public-key")),
            CancellationToken.None);
        Assert.That(completeResult.HasError, Is.False);
    }
}
