﻿using System;
using System.Globalization;
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

public class DefaultAuthenticationCeremonyServiceAndroidKeyTests : AbstractAuthenticationCeremonyServiceTests
{
    protected override Uri GetRelyingPartyAddress()
    {
        return new("https://vanbukin-pc.local", UriKind.Absolute);
    }

    [SetUp]
    public async Task SetupRegistrationAsync()
    {
        TimeProvider.Change(DateTimeOffset.Parse("2023-11-02T13:29:06Z", CultureInfo.InvariantCulture));
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
                new(AuthenticatorAttachment.Platform, null, null, UserVerificationRequirement.Required),
                null,
                AttestationConveyancePreference.Direct,
                null,
                null),
            CancellationToken.None);

        RegistrationCeremonyStorage.ReplaceChallengeForRegistrationCeremonyOptions(
            beginResult.RegistrationCeremonyId,
            WebEncoders.Base64UrlDecode("8jSRetKG3xneEajEfed_vmEb9U7bXZ2yrBcvytlj-cI"));

        var completeResult = await RegistrationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                beginResult.RegistrationCeremonyId,
                null,
                new(
                    "OThmNjc3YmUtMDEwNy00Mzg0LWEzMGMtODczMmI5ZDFiOGI0",
                    "OThmNjc3YmUtMDEwNy00Mzg0LWEzMGMtODczMmI5ZDFiOGI0",
                    new(
                        "eyJjaGFsbGVuZ2UiOiI4alNSZXRLRzN4bmVFYWpFZmVkX3ZtRWI5VTdiWFoyeXJCY3Z5dGxqLWNJIiwib3JpZ2luIjoiaHR0cHM6Ly92YW5idWtpbi1wYy5sb2NhbCIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ",
                        null,
                        null,
                        null,
                        null,
                        "o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmNzaWdYRjBEAiAiRVQFW6i3w4LQsna0lgsC-lhRdktaAxBeV2SSNJ0LFgIgXvT4c1Up--xjkjSH7dN0z6wGmSWS2-Rx2QSt6Nv6cuJjeDVjhFkC7zCCAuswggKRoAMCAQICAQEwCgYIKoZIzj0EAwIwOTEMMAoGA1UEDAwDVEVFMSkwJwYDVQQFEyA1YWM5NTk1MjUxNTRlYTVjOGQ3N2RkYzM0MWVhZjExODAeFw0yMzExMDIxMzI5MDVaFw0yMzExMDIxMzI5MzVaMFcxJjAkBgNVBAsTHWNvbS5nb29nbGUuYXR0ZXN0YXRpb25leGFtcGxlMS0wKwYDVQQDEyQ5OGY2NzdiZS0wMTA3LTQzODQtYTMwYy04NzMyYjlkMWI4YjQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT3o4nKCw7TAdn6ovDDuP8y_t5TYWKUvaaw_jeqvC6iP5oK6u9za1Jy4CgJ_ZtVyiKyaDj6vFrlNxKs8p8MYhrMo4IBajCCAWYwDgYDVR0PAQH_BAQDAgeAMIIBUgYKKwYBBAHWeQIBEQSCAUIwggE-AgFkCgEBAgFkCgEBBCA6OtRHdyNcZQrbxsAWkFbTFcDkhwpGMayvJ-Hw8hqh7AQAMF6_hT0IAgYBi5XNRmC_hUVOBEwwSjEkMCIEHWNvbS5nb29nbGUuYXR0ZXN0YXRpb25leGFtcGxlAgEBMSIEIA-T4G66HdZ5-CExZVPkUBei3a2GrvwP7oahblj10cJIMIGroQUxAwIBAqIDAgEDowQCAgEApQUxAwIBBKoDAgEBv4N4AwIBA7-DeQUCAwFRgL-FPgMCAQC_hUBMMEoEIAesZaSzJKErJgOHWm3qsgPn9ioGl0iuC5ZN6CLTtLVWAQH_CgEABCBC1gc0zXkjTfjTMhZctuF9lDajTqhlix-8VSWKoU_RUr-FQQUCAwH70L-FQgUCAwMWRL-FTgYCBAE0spG_hU8GAgQBNLKRMAoGCCqGSM49BAMCA0gAMEUCIQDOuxsHVbHoS4vZcV4ro_1ougs7PWvP0HNcocw3NiQhBgIgDvq8IBc7Vs1xnOm866JzjH0PqgjzcUsrVCyzzCT7NDlZAfcwggHzMIIBeaADAgECAhB_dtP4N9qMbhbOQHikLXhFMAoGCCqGSM49BAMCMDkxDDAKBgNVBAwMA1RFRTEpMCcGA1UEBRMgZDhiZmU5NTFjODQwYTA0ZDUxNzBiNWFkZTA2ZDNhNTQwHhcNMjIwMTI1MjMzNDMyWhcNMzIwMTIzMjMzNDMyWjA5MQwwCgYDVQQMDANURUUxKTAnBgNVBAUTIDVhYzk1OTUyNTE1NGVhNWM4ZDc3ZGRjMzQxZWFmMTE4MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtejaUFXkCCqva6ywNOKchJIWmPtkwy1jQb6zQn6PTm9tqxKUbqbc3wYcZ1yHYFfuSYeKefVmAKa3iFJSVCYvkKNjMGEwHQYDVR0OBBYEFA5CFMhCp4SGROHaF3KU2oVk9zkxMB8GA1UdIwQYMBaAFEj0jo62sMa_xVrPqc8Av9aoDutTMA8GA1UdEwEB_wQFMAMBAf8wDgYDVR0PAQH_BAQDAgIEMAoGCCqGSM49BAMCA2gAMGUCMQCCcc3qyvg0x7wqZdKyatPVl6Hrb-FpcCyWVj_kgsnYRafZRxQV53BhJ3AXiF1Z2PcCMEGZYRpUILVxqMtYAYpAZhsI6Xnn2JS_mLQDCGJbUcZBkE85kgVtF3boqbMQYys20lkDmDCCA5QwggF8oAMCAQICEQCVQk09vSnKOiW9ysXuURh8MA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMTI1MjMzMjQ4WhcNMzIwMTIzMjMzMjQ4WjA5MQwwCgYDVQQMDANURUUxKTAnBgNVBAUTIGQ4YmZlOTUxYzg0MGEwNGQ1MTcwYjVhZGUwNmQzYTU0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEFsCH8rVxtxwoj-QPOpYTR-mMSzOZyIJ7LE_AHoxMALRf0IfKyPfvuZMpeAqEk1vHYe3O7LET6fAHpJ4DfwcxwdwOzLsOmdlevc8EFcnth2lTJq7MtAAB79eVJ5oN_9Tco2MwYTAdBgNVHQ4EFgQUSPSOjrawxr_FWs-pzwC_1qgO61MwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR_8aTMnqTxIwDwYDVR0TAQH_BAUwAwEB_zAOBgNVHQ8BAf8EBAMCAgQwDQYJKoZIhvcNAQELBQADggIBADPbCCqD3ZfDniH9m34jcaKb4NLv0msbv6nzEwcsM167KZAZgoF5NDVR0Z0vivgWLCDMXexk3D1PfPuvTDi0gR-ahGNRv9brvsCJVNwev795PqMgBswsGYjQTJCBfAEmI_7d7O_YevcueAlQBaisFgV2Vnl2WsBmOiXUN_XS5ZC6cQatiW9HyQv_Znb1N5cO4-qlUD6VwyirpNZeZk7L-8q0h8sVAch6fCLxfkcSGxnt6j6TJUQfJEkSSroLTDz7toNLAGMSPR8PA5tVEL4EAFo9iifbR3YmZ42928h5Jt3dPsBM0nM436kOZOQ0Ujo1nUJPL0r90hznlBtucP95Sr4NQFYoYIq6Jy3Ug2IwpunPRyZfAGuo_aHyMGUCGZ-655fHtgBmvwTYJr4jZ3NmYJ5MNZ4VLGzZnX6DW8n-bCytD60nIGfiDZse2an5Z16t9ubaHabFti2JD0fkunDhvIRf_TPO4AiukRwtBgaA5zIQOjLRp_9zE4rxAUogd11Q_GvcsBYbnjpMrzADfutVSxUg0ItxwBcZUBNy6P71WRrULmX9KcX__tkwPh_qHiUe3553-S8JZVCATe9F34FYwNaMT50mH9hFBBccBsQxoQzxycvrnydUkIrs6WiG6bgY6u1xzZ15Kw21TU0_P_E_KxTxfqadomkShNLVYW8fPSwTWQUgMIIFHDCCAwSgAwIBAgIJAMNrfES5rhgxMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjExMTE3MjMxMDQyWhcNMzYxMTEzMjMxMDQyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd_dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy_4lj4_7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1-di-y9TFRtv6y__0rb-T-W8a9nsNL_ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB_M0n1n_W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl_m00QLVWutHQoVJYnFPlXTcHYvASLu-RhhsbDmxMgJJ0mcDpvsC4PjvB-TxywElgS70vE0XmLD-OJtvsBslHZvPBKCOdT0MS-tgSOIfga-z1Z1g7-DVagf7quvmag8jfPioyKvxnK_EgsTUVi2ghzq8wm27ud_mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws-W0rB5N-er5_2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI_-MRPjy02i59lINMRRev56GKtcd9qO_0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab-9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ-8PTWm2QgBR_bkwSWc-NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf_GkzJ6k8SMB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf_GkzJ6k8SMA8GA1UdEwEB_wQFMAMBAf8wDgYDVR0PAQH_BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQBTNNZe5cuf8oiq-jV0itTGzWVhSTjOBEk2FQvh11J3o3lna0o7rd8RFHnN00q4hi6TapFhh4qaw_iG6Xg-xOan63niLWIC5GOPFgPeYXM9-nBb3zZzC8ABypYuCusWCmt6Tn3-Pjbz3MTVhRGXuT_TQH4KGFY4PhvzAyXwdjTOCXID-aHud4RLcSySr0Fq_L-R8TWalvM1wJJPhyRjqRCJerGtfBagiALzvhnmY7U1qFcS0NCnKjoO7oFedKdWlZz0YAfu3aGCJd4KHT0MsGiLZez9WP81xYSrKMNEsDK-zK5fVzw6jA7cxmpXcARTnmAuGUeI7VVDhDzKeVOctf3a0qQLwC-d0-xrETZ4r2fRGNw2YEs2W8Qj6oDcfPvq9JySe7pJ6wcHnl5EZ0lwc4xH7Y4Dx9RA1JlfooLMw3tOdJZH0enxPXaydfAD3YifeZpFaUzicHeLzVJLt9dvGB0bHQLE4-EqKFgOZv2EoP686DQqbVS1u-9k0p2xbMA105TBIk7npraa8VM0fnrRKi7wlZKwdH-aNAyhbXRW9xsnODJ-g8eF452zvbiKKngEKirK5LGieoXBX7tZ9D1GNBH2Ob3bKOwwIWdEFle_YF_h6zWgdeoaNGDqVBrLr2-0DtWoiB1aDEjLWl9FmyIUyUm7mD_vFDkzF-wm7cyWpQpCVWhhdXRoRGF0YViowbGR7JKb_3nCDS_Zb_TxyUe4a4rtFXaAsGAUBoQQGPVFAAAAAAAAAAAAAAAAAAAAAAAAAAAAJDk4ZjY3N2JlLTAxMDctNDM4NC1hMzBjLTg3MzJiOWQxYjhiNKUBAgMmIAEhWCD3o4nKCw7TAdn6ovDDuP8y_t5TYWKUvaaw_jeqvC6iPyJYIJoK6u9za1Jy4CgJ_ZtVyiKyaDj6vFrlNxKs8p8MYhrM"
                    ),
                    null,
                    new(),
                    "public-key")),
            CancellationToken.None);
        Assert.That(completeResult.HasError, Is.False);
    }

    [Test]
    public async Task DefaultAuthenticationCeremonyService_PerformsCeremonyWithoutErrorsForAndroidKey_WhenAllAlgorithms()
    {
        TimeProvider.Change(DateTimeOffset.Parse("2023-11-03T13:29:06Z", CultureInfo.InvariantCulture));
        var beginRequest = new BeginAuthenticationCeremonyRequest(
            null,
            null,
            WebEncoders.Base64UrlDecode("AAAAAAAAAAAAAAAAAAAAAQ"),
            32,
            60000,
            AuthenticationCeremonyIncludeCredentials.None(),
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
            WebEncoders.Base64UrlDecode("mm8-K3sJH6aY0bxmLRQIVo65TKDhPiPD862sOvx23sk"));

        var completeResult = await AuthenticationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(beginResult.AuthenticationCeremonyId,
                new("OThmNjc3YmUtMDEwNy00Mzg0LWEzMGMtODczMmI5ZDFiOGI0",
                    "OThmNjc3YmUtMDEwNy00Mzg0LWEzMGMtODczMmI5ZDFiOGI0",
                    new("eyJjaGFsbGVuZ2UiOiJtbTgtSzNzSkg2YVkwYnhtTFJRSVZvNjVUS0RoUGlQRDg2MnNPdngyM3NrIiwib3JpZ2luIjoiaHR0cHM6Ly92YW5idWtpbi1wYy5sb2NhbCIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ",
                        "wbGR7JKb_3nCDS_Zb_TxyUe4a4rtFXaAsGAUBoQQGPUFAAAAAA",
                        "MEYCIQCsyX9N9Izqtgilz6VaXeG7J5x8wavs4TXrLFVqQpWqrwIhAK-C-O_faJT3UE3C2lqE_mprfZLeBtPlzOV_8YMsSG9A",
                        "AAAAAAAAAAAAAAAAAAAAAQ",
                        null),
                    null,
                    new(),
                    "public-key")),
            CancellationToken.None);
        Assert.That(completeResult.HasError, Is.False);
    }
}
