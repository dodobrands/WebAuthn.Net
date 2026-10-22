using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationObjectDecoder.Implementation;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Constants;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Implementation;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Implementation;
using WebAuthn.Net.Services.Serialization.Cose.Implementation;
using WebAuthn.Net.Services.Serialization.Json.Implementation;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;

// Regression tests for the hardening of DefaultTpmAttestationStatementVerifier.VerifyAsync beyond the steps of WebAuthn L3 §8.3:
// the key-protection attributes of the credential key, the SHA-1 nameAlg report, the empty-trust-anchor configuration and the sanitization of untrusted strings in log messages.
public class DefaultTpmAttestationStatementVerifierHardeningTests
{
    // TPM 2.0 Library Part 2 v185, 8.3 TPMA_OBJECT (Table 37)
    private const uint FixedTpm = 1u << 1;
    private const uint FixedParent = 1u << 4;
    private const uint SensitiveDataOrigin = 1u << 5;

    // The two Windows Hello test vectors of DefaultRegistrationCeremonyServiceTpmTests: AMD fTPM (id:414D4400), AIK certificate issued by EUS-AMD-KEYID-... under Microsoft TPM Root Certificate Authority 2014,
    // ECDSA P-256 and RSA 2048 credential keys with SHA-256 Names and the objectAttributes 0x00040072 / 0x00060472, both certified with alg = RS1 (-65535, a 20-byte extraData).
    // Their certificates expire on 2028-04-14, so they are verified at a fixed time.
    private static readonly DateTimeOffset WindowsHelloTime = new(2026, 10, 17, 17, 20, 2, TimeSpan.Zero);

    private const string WindowsHelloEcdsaClientDataJson = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiNHgwLXExbm5IbmxnSnNnd01mVFVSelIyd2NUT1BFRmFkbjRUQ1hhS1c2WSIsIm9yaWdpbiI6Imh0dHBzOi8vdmFuYnVraW4tcGMubG9jYWwiLCJjcm9zc09yaWdpbiI6ZmFsc2V9";

    private const string WindowsHelloEcdsaAttestationObject = "o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn__mNzaWdZAQCyBDz37cp_eEyGVSAhDgYE-EtprDjrsnwUD2FuWrEpdVRzLZteiKfqsxCDslRLvMye9raQyBMQLR6L9q_IAeKJP1ArQvHGDCloAv46kpx300SDUp4nA_vP7kS180FKjmbm20zfHdk5dEHskFnNksbi96eQK1YuK2wUrudlAZ2MwgWjSQtX_eTVlOghhI6wwkFxwoX4oDuPiF6o_fv5RhvjSTwwPoOcb8SD736sRhM8HYPQTmQ7dO9bko-U3X-3eUrJXTrSLYehLZ4Q9mBHHAaR1pp9C296_O1Agh1je8KTZgXVqGfOBEpX9FLoGx_vfCfKiGXoPRlDUWlrxYTRnn3hY3ZlcmMyLjBjeDVjglkFuzCCBbcwggOfoAMCAQICEBWVq6zFF0c7iiQdgQCWL-wwDQYJKoZIhvcNAQELBQAwQTE_MD0GA1UEAxM2RVVTLUFNRC1LRVlJRC1CQzhFQUMxMDg0NEY1QzdFQkZFOEJBQzJDRUI1MEU4Q0RGMzRFRjg4MB4XDTIzMTAwNTE3NDcxNloXDTI4MDQxNDE4MjkyMFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALWqOarMTXdWEyM8QLK7YJUtMeJRecG2cxezCI0rxR7gzRriuaYFCf5qkgc0SVjknDz6qBz_bp-7CG-7IP4PT_65PZarjskCVSW_6uOt2g0KAcseG-_08JCndFQnXUCmoIbpgZ7ZmJUqJfhTHdX0v1mYlZe4QvtUsJqucYOcYSiHMiHI_eM52p3DdW3KEakKrG5vjr_QShLDKCrJ_te_yAWqrs4dTC9Ut_fSlgCiDRzwazJAA0ZaXRYfU7RzHNnb7tqKDD3lyF6zCSw0qF39Iqr5tDiW7PHNBtSn8GEhrHs5nVuf_v6j-17U_ByBCNPlNqb4MPk6vhZgEzzVYANFnbUCAwEAAaOCAeowggHmMA4GA1UdDwEB_wQEAwIHgDAMBgNVHRMBAf8EAjAAMG0GA1UdIAEB_wRjMGEwXwYJKwYBBAGCNxUfMFIwUAYIKwYBBQUHAgIwRB5CAFQAQwBQAEEAIAAgAFQAcgB1AHMAdABlAGQAIAAgAFAAbABhAHQAZgBvAHIAbQAgACAASQBkAGUAbgB0AGkAdAB5MBAGA1UdJQQJMAcGBWeBBQgDMFAGA1UdEQEB_wRGMESkQjBAMRYwFAYFZ4EFAgEMC2lkOjQxNEQ0NDAwMQ4wDAYFZ4EFAgIMA0FNRDEWMBQGBWeBBQIDDAtpZDowMDAzMDAwMTAfBgNVHSMEGDAWgBR3E2MbHcNeIfGHGxCZHZ8L4MGNwjAdBgNVHQ4EFgQUDrrdtNqzpqMCfaTQQfCvLIjeFIkwgbIGCCsGAQUFBwEBBIGlMIGiMIGfBggrBgEFBQcwAoaBkmh0dHA6Ly9hemNzcHJvZGV1c2Fpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L2V1cy1hbWQta2V5aWQtYmM4ZWFjMTA4NDRmNWM3ZWJmZThiYWMyY2ViNTBlOGNkZjM0ZWY4OC80ZDNkZjQ2Mi1kYWQyLTRlNTUtYThmMC1hN2IyNmYwYWEzZmMuY2VyMA0GCSqGSIb3DQEBCwUAA4ICAQAqoj8hVQPX0wmVgO6FhH7qOh5mHDpMceR0HIVDk_UIIIeg8G3-oK0jb-eVltwd9bgdO3zJVfLDLWpABddrCisXxu7D5uIWLGE_rjllHS8hosxMRLsFuTrWT3sFgjloyxFbjTPPfE6DQuNgFI85odzBvaPMMFwNrt_LGt0Uw00_aMBBvAsv0SUgUgb7kXWT8kE4fzDwlVrYvbl-Expa1eEavMnugL-l4fNB7DZsyXpc7hwQDL3QU-rcqRMW60UC7b3x5ghsMJDfoubthZ856lBUdQtUg-ZxE2hOHd3fa_FhlxPXbnIL3L7yTbLCgCbcpgiQ0qPDs65KOJI8k0-FIN3LSoVxgevEIBKY1zfRbiS5oo_7AlhMD28G0-HYlYUFqGe9BhuVi5zjld96yJfRNqjV7zYTbIx-CRfFyjM0Ynqp477oFC-jfc2WQmrSI-GQD7bZ9j6o9puZS4QEoipjDPfwl4h47bKME_lDMMSvSpoc4-wVTcmgPMFfXpHEqRyNEzoRBQfH8kkxvGL0z6hrSDShV6C0p5PubFLH4aTm5BeIV43DY7jdlP39yU12bKnFEARmKp-lzYjUHrze-qRDyesDTuhM8e8ok69KDBwgz-_n_F6UBZnEwppI32fZ6rVK_B_1lbi4EZ2AJG5wIduIEHs3pdfDm_--xFjgfkG9Vcj-xFkG7zCCBuswggTToAMCAQICEzMAAAd7jiICI2S3Wc4AAAAAB3swDQYJKoZIhvcNAQELBQAwgYwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNjA0BgNVBAMTLU1pY3Jvc29mdCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxNDAeFw0yMjA0MTQxODI5MjBaFw0yODA0MTQxODI5MjBaMEExPzA9BgNVBAMTNkVVUy1BTUQtS0VZSUQtQkM4RUFDMTA4NDRGNUM3RUJGRThCQUMyQ0VCNTBFOENERjM0RUY4ODCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKODi9d9Um54NFsCyBsYsYOLTVPMqa9XewhPIpScPQ2_8iS9CDvIolHmViWpzNcUVwCEPWy_bbtFHeUEQeZ0My3nP21tT__Zc_BGJs4XO9ys78B1Zpp1_6mh3KoesxMjYhrdzLtIGI_RzxCff3FzYK3pFCBPz3uxBtwMsq1ckNr1GsWfZBOLjKRoYDEKM0mqd6cAaIm_IR6oWC2zulJQSmlHz35MxW_OF7MQZHt1n0PwLekZ4udfxsy6L5zfRFhJCE_Enq8ggSETBgFTNImYKpQllOcfojEF3axUnIPZmIsJNWIWSX5WyCfKD1Rfju3IntIQArY221N8BV8tALcUFeGKGBPYN10pYb1KLcdkhdvJGpqOhmAhvSVF9rxMLlzOnrWiEXVsO1YU3hSmR3WGHg8ahbCxKyBGfISYgx9bVMYijvQA33dfPJEcigHLZmqOOlLFA5td3m_hWIyD76dXkY6Cy483wtKGUdRYrjN94JMOY14PhUpFpIh-KKaPFjwKab93u9dfX_jWbmPBdUrmL2aHGUVg8ljU_-pQj9aObXPYngjomFJJ4e0kJFe4au6gTVRRMqXePkwBcmPsbhxWBR07u9nY5EGYOpikTiicOp0hRmZ-b9qn2i_r8hCSzAVeRMsbujOfgmQtIAMXeF8wjWg41f5tbgXKxR_lRGI6ojz1AgMBAAGjggGOMIIBijAOBgNVHQ8BAf8EBAMCAoQwGwYDVR0lBBQwEgYJKwYBBAGCNxUkBgVngQUIAzAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzASBgNVHRMBAf8ECDAGAQH_AgEAMB0GA1UdDgQWBBR3E2MbHcNeIfGHGxCZHZ8L4MGNwjAfBgNVHSMEGDAWgBR6jArOL0hiF-KU0a5VwVLscXSkVjBwBgNVHR8EaTBnMGWgY6Bhhl9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUUE0lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDE0LmNybDB9BggrBgEFBQcBAQRxMG8wbQYIKwYBBQUHMAKGYWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcnQwDQYJKoZIhvcNAQELBQADggIBAExrsXgXU6oRgruZcut7iICBfJj3tIuDi5OTzzdnvmHeNI0jPLk7NW8qoDdRUW8Xc8LoIxga8M_-5s88oflyhDGRPToO_uqg2DxcatGy-WxMnboGnlVYjt-kbvuMJCtxLC_3PkCtkC2uKXxTwpTEweokBSuISdcaJDk7rutWiAcmXAB4VKO1KiZajc-h7HjchVy58-CE7E2rLaHuOlQKkROahSsbTb-OZhsoRhT6Oky71mlgYwIsWHyPulVcliIy6VSM1ih7E93d2CVctz1WcbxLnmW9_liK_UyXYIKk1YVFMCeFu9DJC9LcK2wmQ_Bzn8K98RnWF5bisDmS184dQAppNRsqkjWH8p4MhvYyazDeQzIuS2wIw1wTBa4iiRFNzbT0OUcX68VO1mUJKgSN2USHLW8YO1OTJhcTvYVxIeJxezvCi31cqGDiy5jREfNTio4bKzvkDjPDn-i9p592ccLxyZzAErNB6aj3dWNy9UXNzdRzSbrgOJxxaqvN5qoCv3e97OSj191_DZPj7aOQhfhM4DqGFrORySRCGK0gIJhLhSp4sQseI98Dii-CESIhGvjKB0eSCdelwQQDtTqXmWhfx8IctXLxca2dOsNMHSvVpcIua8OgS-PTSAHfwGbh-0CrfSQdhehcMHapu5Hu0D9Ub0vDZCDvIcqJ2jp40KSlZ3B1YkFyZWFYdgAjAAsABAByACCd_8vzbDg65pn7mGjcbcuJ1xU4hL4oA5IsEkFYv60irgAQABAAAwAQACAsv9rh7Zftq17lwnFVeTD8_yRFC0tFfM1UnFEO96ESggAg7ezYLoGfNnzGDge314AkOepy1jMPQkg6arxK74GcN1xoY2VydEluZm9Yof9UQ0eAFwAiAAvJ3_Ntou3kY-doNaZ7AYWYcNvyUpq14nbL_2G66MDAhgAUeJUZev4NFKIkGH8VafqWFUbOJeQAAAAC-uLtG83fbhgHoiSYAbw9Zk4_EQokACIACwOitKzxslmEbGaD3PM-p2kk7Oimus9P6GihRtz4CMUeACIAC38AlxhQxanAEgXl9S_YOFYPHnSjNXH_EJ4hgzPhYOjkaGF1dGhEYXRhWKTBsZHskpv_ecINL9lv9PHJR7hriu0VdoCwYBQGhBAY9UUAAAAACJhwWMrcS4G24TDeUNy-lgAg4Ty0Cs5bPOCvOv_7IF3ve3oG7Sr52xECQI_uEfrshhGlAQIDJiABIVggLL_a4e2X7ate5cJxVXkw_P8kRQtLRXzNVJxRDvehEoIiWCDt7NgugZ82fMYOB7fXgCQ56nLWMw9CSDpqvErvgZw3XA";

    private const string WindowsHelloRsaClientDataJson = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoicjhid0tEaTRPX21SdFBEajZSeHhRdGRLS2Nmb0NUal9mX0JkXzA3dGFvbyIsIm9yaWdpbiI6Imh0dHBzOi8vdmFuYnVraW4tcGMubG9jYWwiLCJjcm9zc09yaWdpbiI6ZmFsc2V9";

    private const string WindowsHelloRsaAttestationObject = "o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn__mNzaWdZAQCK21mSjJlYRipS1cVylixSEF_TlaYKRwSRsQVmmgndlsUVrcliKPRSWBkCR4mDfSiOLsXr3Gi1AaB734uxaDKx74PVDNy_yFZ2Z0xlzc5KNyamZVTTNAsBQYB-Dvo2CsBwQS9GH5w7n_X9yROAwChUV8GDye2dBxt3-SYEWgcTQA7mRMGQKbh8esmrDy8pFwrkTqfUF_CguZomZtyFapgMuFeLzrhHyH1thcL2Fms4COhvMNYz6QXWYQcupMsP8Q3YtRbUZjUmW6yl2Dv39vtBiM3dWISWib1nC_e63xTqSf2kr8JKxRWpNq2pWN17yOmSKHakV6Y_gJk1uHguDKBTY3ZlcmMyLjBjeDVjglkFuzCCBbcwggOfoAMCAQICEBWVq6zFF0c7iiQdgQCWL-wwDQYJKoZIhvcNAQELBQAwQTE_MD0GA1UEAxM2RVVTLUFNRC1LRVlJRC1CQzhFQUMxMDg0NEY1QzdFQkZFOEJBQzJDRUI1MEU4Q0RGMzRFRjg4MB4XDTIzMTAwNTE3NDcxNloXDTI4MDQxNDE4MjkyMFowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALWqOarMTXdWEyM8QLK7YJUtMeJRecG2cxezCI0rxR7gzRriuaYFCf5qkgc0SVjknDz6qBz_bp-7CG-7IP4PT_65PZarjskCVSW_6uOt2g0KAcseG-_08JCndFQnXUCmoIbpgZ7ZmJUqJfhTHdX0v1mYlZe4QvtUsJqucYOcYSiHMiHI_eM52p3DdW3KEakKrG5vjr_QShLDKCrJ_te_yAWqrs4dTC9Ut_fSlgCiDRzwazJAA0ZaXRYfU7RzHNnb7tqKDD3lyF6zCSw0qF39Iqr5tDiW7PHNBtSn8GEhrHs5nVuf_v6j-17U_ByBCNPlNqb4MPk6vhZgEzzVYANFnbUCAwEAAaOCAeowggHmMA4GA1UdDwEB_wQEAwIHgDAMBgNVHRMBAf8EAjAAMG0GA1UdIAEB_wRjMGEwXwYJKwYBBAGCNxUfMFIwUAYIKwYBBQUHAgIwRB5CAFQAQwBQAEEAIAAgAFQAcgB1AHMAdABlAGQAIAAgAFAAbABhAHQAZgBvAHIAbQAgACAASQBkAGUAbgB0AGkAdAB5MBAGA1UdJQQJMAcGBWeBBQgDMFAGA1UdEQEB_wRGMESkQjBAMRYwFAYFZ4EFAgEMC2lkOjQxNEQ0NDAwMQ4wDAYFZ4EFAgIMA0FNRDEWMBQGBWeBBQIDDAtpZDowMDAzMDAwMTAfBgNVHSMEGDAWgBR3E2MbHcNeIfGHGxCZHZ8L4MGNwjAdBgNVHQ4EFgQUDrrdtNqzpqMCfaTQQfCvLIjeFIkwgbIGCCsGAQUFBwEBBIGlMIGiMIGfBggrBgEFBQcwAoaBkmh0dHA6Ly9hemNzcHJvZGV1c2Fpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L2V1cy1hbWQta2V5aWQtYmM4ZWFjMTA4NDRmNWM3ZWJmZThiYWMyY2ViNTBlOGNkZjM0ZWY4OC80ZDNkZjQ2Mi1kYWQyLTRlNTUtYThmMC1hN2IyNmYwYWEzZmMuY2VyMA0GCSqGSIb3DQEBCwUAA4ICAQAqoj8hVQPX0wmVgO6FhH7qOh5mHDpMceR0HIVDk_UIIIeg8G3-oK0jb-eVltwd9bgdO3zJVfLDLWpABddrCisXxu7D5uIWLGE_rjllHS8hosxMRLsFuTrWT3sFgjloyxFbjTPPfE6DQuNgFI85odzBvaPMMFwNrt_LGt0Uw00_aMBBvAsv0SUgUgb7kXWT8kE4fzDwlVrYvbl-Expa1eEavMnugL-l4fNB7DZsyXpc7hwQDL3QU-rcqRMW60UC7b3x5ghsMJDfoubthZ856lBUdQtUg-ZxE2hOHd3fa_FhlxPXbnIL3L7yTbLCgCbcpgiQ0qPDs65KOJI8k0-FIN3LSoVxgevEIBKY1zfRbiS5oo_7AlhMD28G0-HYlYUFqGe9BhuVi5zjld96yJfRNqjV7zYTbIx-CRfFyjM0Ynqp477oFC-jfc2WQmrSI-GQD7bZ9j6o9puZS4QEoipjDPfwl4h47bKME_lDMMSvSpoc4-wVTcmgPMFfXpHEqRyNEzoRBQfH8kkxvGL0z6hrSDShV6C0p5PubFLH4aTm5BeIV43DY7jdlP39yU12bKnFEARmKp-lzYjUHrze-qRDyesDTuhM8e8ok69KDBwgz-_n_F6UBZnEwppI32fZ6rVK_B_1lbi4EZ2AJG5wIduIEHs3pdfDm_--xFjgfkG9Vcj-xFkG7zCCBuswggTToAMCAQICEzMAAAd7jiICI2S3Wc4AAAAAB3swDQYJKoZIhvcNAQELBQAwgYwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNjA0BgNVBAMTLU1pY3Jvc29mdCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxNDAeFw0yMjA0MTQxODI5MjBaFw0yODA0MTQxODI5MjBaMEExPzA9BgNVBAMTNkVVUy1BTUQtS0VZSUQtQkM4RUFDMTA4NDRGNUM3RUJGRThCQUMyQ0VCNTBFOENERjM0RUY4ODCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKODi9d9Um54NFsCyBsYsYOLTVPMqa9XewhPIpScPQ2_8iS9CDvIolHmViWpzNcUVwCEPWy_bbtFHeUEQeZ0My3nP21tT__Zc_BGJs4XO9ys78B1Zpp1_6mh3KoesxMjYhrdzLtIGI_RzxCff3FzYK3pFCBPz3uxBtwMsq1ckNr1GsWfZBOLjKRoYDEKM0mqd6cAaIm_IR6oWC2zulJQSmlHz35MxW_OF7MQZHt1n0PwLekZ4udfxsy6L5zfRFhJCE_Enq8ggSETBgFTNImYKpQllOcfojEF3axUnIPZmIsJNWIWSX5WyCfKD1Rfju3IntIQArY221N8BV8tALcUFeGKGBPYN10pYb1KLcdkhdvJGpqOhmAhvSVF9rxMLlzOnrWiEXVsO1YU3hSmR3WGHg8ahbCxKyBGfISYgx9bVMYijvQA33dfPJEcigHLZmqOOlLFA5td3m_hWIyD76dXkY6Cy483wtKGUdRYrjN94JMOY14PhUpFpIh-KKaPFjwKab93u9dfX_jWbmPBdUrmL2aHGUVg8ljU_-pQj9aObXPYngjomFJJ4e0kJFe4au6gTVRRMqXePkwBcmPsbhxWBR07u9nY5EGYOpikTiicOp0hRmZ-b9qn2i_r8hCSzAVeRMsbujOfgmQtIAMXeF8wjWg41f5tbgXKxR_lRGI6ojz1AgMBAAGjggGOMIIBijAOBgNVHQ8BAf8EBAMCAoQwGwYDVR0lBBQwEgYJKwYBBAGCNxUkBgVngQUIAzAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzASBgNVHRMBAf8ECDAGAQH_AgEAMB0GA1UdDgQWBBR3E2MbHcNeIfGHGxCZHZ8L4MGNwjAfBgNVHSMEGDAWgBR6jArOL0hiF-KU0a5VwVLscXSkVjBwBgNVHR8EaTBnMGWgY6Bhhl9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUUE0lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDE0LmNybDB9BggrBgEFBQcBAQRxMG8wbQYIKwYBBQUHMAKGYWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcnQwDQYJKoZIhvcNAQELBQADggIBAExrsXgXU6oRgruZcut7iICBfJj3tIuDi5OTzzdnvmHeNI0jPLk7NW8qoDdRUW8Xc8LoIxga8M_-5s88oflyhDGRPToO_uqg2DxcatGy-WxMnboGnlVYjt-kbvuMJCtxLC_3PkCtkC2uKXxTwpTEweokBSuISdcaJDk7rutWiAcmXAB4VKO1KiZajc-h7HjchVy58-CE7E2rLaHuOlQKkROahSsbTb-OZhsoRhT6Oky71mlgYwIsWHyPulVcliIy6VSM1ih7E93d2CVctz1WcbxLnmW9_liK_UyXYIKk1YVFMCeFu9DJC9LcK2wmQ_Bzn8K98RnWF5bisDmS184dQAppNRsqkjWH8p4MhvYyazDeQzIuS2wIw1wTBa4iiRFNzbT0OUcX68VO1mUJKgSN2USHLW8YO1OTJhcTvYVxIeJxezvCi31cqGDiy5jREfNTio4bKzvkDjPDn-i9p592ccLxyZzAErNB6aj3dWNy9UXNzdRzSbrgOJxxaqvN5qoCv3e97OSj191_DZPj7aOQhfhM4DqGFrORySRCGK0gIJhLhSp4sQseI98Dii-CESIhGvjKB0eSCdelwQQDtTqXmWhfx8IctXLxca2dOsNMHSvVpcIua8OgS-PTSAHfwGbh-0CrfSQdhehcMHapu5Hu0D9Ub0vDZCDvIcqJ2jp40KSlZ3B1YkFyZWFZATYAAQALAAYEcgAgnf_L82w4OuaZ-5ho3G3LidcVOIS-KAOSLBJBWL-tIq4AEAAQCAAAAAAAAQDFDUWoiW3cyTF1U1_JXxw7LXpUDgM5C9yT3MnttgDi-pCXUWKy_uVjy01YNPBjM5mVAY2n3u1BZuCywXKMI14rF9lP75X3wcrglfjT8HjJLMJBBQyzb590VF6JN_IZTLIKru8ABB7AC0HGcEQ9OhsYVRPG7bQe9IaQMrWbLu-WLnxKC0kbBbiwWCHV0yUDjlwzr9ZVgDpuDpUPcFw1KR2znKr3lqI7xighrNTZu3OehrQ5KqU7qP7qY-bmArjAkqJyIyCDvHMsnPXesLLQ1zGnpI3suohkrnjP0hbDZ074E4ZgIk0qDxTzCMbxVGFZ_eTnDAcURGb7_Cf_LSmuRFDLaGNlcnRJbmZvWKH_VENHgBcAIgALyd_zbaLt5GPnaDWmewGFmHDb8lKateJ2y_9huujAwIYAFJiWZNORqhB90ezuUD1PiN-4eBDkAAAAAvri7RvN324YB6IkmAG8PWZOPxEKJAAiAAsJ_1MoAQe5NSYcoHJnEnfkrviEq0oYWLwB3NWmQBO2EgAiAAvWAlj5mIfOmc3b5ZSHHN1OrnChuexo6MVctkho2ulrvGhhdXRoRGF0YVkBZ8GxkeySm_95wg0v2W_08clHuGuK7RV2gLBgFAaEEBj1RQAAAAAImHBYytxLgbbhMN5Q3L6WACCWsDztacHu0W6J_WbmqCEsh44fzKfXT1RKjrCrfURWMKQBAwM5AQAgWQEAxQ1FqIlt3MkxdVNfyV8cOy16VA4DOQvck9zJ7bYA4vqQl1Fisv7lY8tNWDTwYzOZlQGNp97tQWbgssFyjCNeKxfZT--V98HK4JX40_B4ySzCQQUMs2-fdFReiTfyGUyyCq7vAAQewAtBxnBEPTobGFUTxu20HvSGkDK1my7vli58SgtJGwW4sFgh1dMlA45cM6_WVYA6bg6VD3BcNSkds5yq95aiO8YoIazU2btznoa0OSqlO6j-6mPm5gK4wJKiciMgg7xzLJz13rCy0Ncxp6SN7LqIZK54z9IWw2dO-BOGYCJNKg8U8wjG8VRhWf3k5wwHFERm-_wn_y0prkRQyyFDAQAB";

    // ---------------------------------------------------------------------------------------------
    // The credential key is bound to the TPM (fixedTPM, fixedParent and sensitiveDataOrigin SET): otherwise reported, and rejected only on request

    [TestCase(0x00040040u)] // sign | userWithAuth only: the attributes of a key imported with TPM2_Import() or loaded with TPM2_LoadExternal()
    [TestCase(TpmAttestationBuilder.EccObjectAttributes & ~FixedTpm)] // fixedTPM CLEAR
    [TestCase(TpmAttestationBuilder.EccObjectAttributes & ~(FixedTpm | FixedParent))] // fixedTPM and fixedParent CLEAR (fixedTPM SET requires fixedParent SET, so fixedParent cannot be CLEAR alone)
    [TestCase(TpmAttestationBuilder.EccObjectAttributes & ~SensitiveDataOrigin)] // sensitiveDataOrigin CLEAR
    public async Task VerifyAsync_Succeeds_AndReportsAnomaly_WhenCredentialKeyIsNotTpmBound(uint objectAttributes)
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { ObjectAttributes = objectAttributes }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok!.AttestationType, Is.EqualTo(AttestationType.AttCa));
            AssertAnomaly(verifier, TpmAttestationStatementAnomalies.PubAreaKeyNotTpmBound, true);
            Assert.That(verifier.FakeCounters.AttestationStatementAnomalies, Has.Count.EqualTo(1));
            AssertWarning(verifier, "is not bound to the TPM: fixedTPM, fixedParent or sensitiveDataOrigin is CLEAR in its objectAttributes");
            AssertWarning(verifier, "; tolerated");
        });
    }

    [Test]
    public async Task VerifyAsync_Succeeds_AndReportsAnomaly_WhenRsaCredentialKeyIsNotTpmBound()
    {
        var verifier = new TestTpmAttestationStatementVerifier();
        var attestation = new TpmAttestationBuilder
        {
            RsaCredentialKey = true,
            ObjectAttributes = TpmAttestationBuilder.RsaObjectAttributes & ~(FixedTpm | FixedParent | SensitiveDataOrigin)
        }.Build();

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            AssertAnomaly(verifier, TpmAttestationStatementAnomalies.PubAreaKeyNotTpmBound, true);
            AssertWarning(verifier, "The credential key in the 'pubArea' of the TPM attestation statement is not bound to the TPM: fixedTPM, fixedParent or sensitiveDataOrigin is CLEAR in its objectAttributes (UserWithAuth, NoDa, Decrypt, SignEncrypt); tolerated");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_AndReportsAnomaly_WhenCredentialKeyIsNotTpmBound_AndTpmBoundKeyIsRequired()
    {
        // the policy hook (IsTpmBoundCredentialKeyRequired) turns the tolerated anomaly into a rejection
        var verifier = new TestTpmAttestationStatementVerifier { RequireTpmBoundCredentialKey = true };

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { ObjectAttributes = 0x00040040 }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertAnomaly(verifier, TpmAttestationStatementAnomalies.PubAreaKeyNotTpmBound, false);
            Assert.That(verifier.FakeCounters.AttestationStatementAnomalies, Has.Count.EqualTo(1));
            AssertWarning(verifier, "The credential key in the 'pubArea' of the TPM attestation statement is not bound to the TPM: fixedTPM, fixedParent or sensitiveDataOrigin is CLEAR in its objectAttributes (UserWithAuth, SignEncrypt); rejected, a TPM-bound credential key is required");
        });
    }

    [TestCase(false)]
    [TestCase(true)]
    public async Task VerifyAsync_Succeeds_WithoutAnomaly_WhenCredentialKeyIsTpmBound_AndTpmBoundKeyIsRequired(bool rsaCredentialKey)
    {
        // the default objectAttributes of the builder are those of the Windows Hello keys: fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | [noDA | decrypt |] sign
        var verifier = new TestTpmAttestationStatementVerifier { RequireTpmBoundCredentialKey = true };

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { RsaCredentialKey = rsaCredentialKey }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(verifier.FakeCounters.AttestationStatementAnomalies, Is.Empty);
            Assert.That(verifier.FakeLogger.Entries, Is.Empty);
        });
    }

    [TestCase(WindowsHelloEcdsaAttestationObject, WindowsHelloEcdsaClientDataJson)]
    [TestCase(WindowsHelloRsaAttestationObject, WindowsHelloRsaClientDataJson)]
    public async Task VerifyAsync_Succeeds_WithoutAnomaly_ForWindowsHelloAttestation_EvenWhenTpmBoundKeyIsRequired(string attestationObjectBase64Url, string clientDataJsonBase64Url)
    {
        // a genuine TPM attestation (alg = RS1, SHA-256 Names, TPM-bound keys) is accepted without a single anomaly or log entry, even under the strict policy
        var verifier = new TestTpmAttestationStatementVerifier(WindowsHelloTime) { RequireTpmBoundCredentialKey = true };
        var attestation = DecodeAttestation(attestationObjectBase64Url, clientDataJsonBase64Url);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok!.AttestationType, Is.EqualTo(AttestationType.AttCa));
            Assert.That(result.Ok.AttestationTrustPath, Has.Length.EqualTo(2)); // aikCert and the EUS-AMD-KEYID intermediate CA certificate
            Assert.That(result.Ok.AttestationRootCertificates, Is.EquivalentTo(TpmRoots.AMD));
            Assert.That(verifier.FakeCounters.AttestationStatementAnomalies, Is.Empty);
            Assert.That(verifier.FakeLogger.Entries, Is.Empty);
        });
    }

    // ---------------------------------------------------------------------------------------------
    // A SHA-1 nameAlg is accepted, but reported; alg = RS1 is what Windows Hello sends, so it is accepted without a report

    [Test]
    public async Task VerifyAsync_Succeeds_WithoutAnomaly_WhenAlgIsRs1()
    {
        // alg = RS1: the attestation signature is RSASSA-PKCS1-v1_5 with SHA-1 and extraData = SHA-1(attToBeSigned) - the algorithm of every Windows Hello TPM attestation (see the vectors above)
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { SignWithRs1 = true }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok!.AttestationType, Is.EqualTo(AttestationType.AttCa));
            Assert.That(verifier.FakeCounters.AttestationStatementAnomalies, Is.Empty);
            Assert.That(verifier.FakeLogger.Entries, Is.Empty);
        });
    }

    [Test]
    public async Task VerifyAsync_Succeeds_AndReportsAnomaly_WhenNameAlgIsSha1()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { NameAlg = 0x0004 }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok!.AttestationType, Is.EqualTo(AttestationType.AttCa));
            AssertAnomaly(verifier, TpmAttestationStatementAnomalies.PubAreaNameAlgSha1, true);
            Assert.That(verifier.FakeCounters.AttestationStatementAnomalies, Has.Count.EqualTo(1));
            AssertWarning(verifier, "The nameAlg of the 'pubArea' of the TPM attestation statement is TPM_ALG_SHA1: the Name in 'certInfo' is a SHA-1 digest; tolerated");
        });
    }

    [Test]
    public async Task VerifyAsync_Succeeds_AndReportsOnlyTheNameAlgAnomaly_WhenAlgIsRs1AndNameAlgIsSha1()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { SignWithRs1 = true, NameAlg = 0x0004 }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            AssertAnomaly(verifier, TpmAttestationStatementAnomalies.PubAreaNameAlgSha1, true);
            Assert.That(verifier.FakeCounters.AttestationStatementAnomalies, Has.Count.EqualTo(1));
        });
    }

    [TestCase((ushort) 0x000B)] // TPM_ALG_SHA256
    [TestCase((ushort) 0x000C)] // TPM_ALG_SHA384
    [TestCase((ushort) 0x000D)] // TPM_ALG_SHA512
    public async Task VerifyAsync_Succeeds_WithoutAnomaly_WhenNameAlgIsSha2(ushort nameAlg)
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { NameAlg = nameAlg }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(verifier.FakeCounters.AttestationStatementAnomalies, Is.Empty);
            Assert.That(verifier.FakeLogger.Entries, Is.Empty);
        });
    }

    // ---------------------------------------------------------------------------------------------
    // No acceptable trust anchors: a configuration outcome that is rejected, not an exception

    [Test]
    public async Task VerifyAsync_Fails_WithoutException_WhenNeitherManufacturerVerifierNorFidoMetadataSupplyTrustAnchors()
    {
        // a manufacturer verifier that knows the vendor but supplies no roots (its contract allows that: "additional trust anchors come from the FIDO Metadata Service"), and no metadata for the aaguid
        var verifier = new TestTpmAttestationStatementVerifier(new NoRootsTpmManufacturerVerifier());
        var attestation = new TpmAttestationBuilder().Build();

        Result<VerifiedAttestationStatement>? result = null;
        await Assert.DoesNotThrowAsync(async () => result = await verifier.VerifyAsync(attestation));
        Assert.Multiple(() =>
        {
            Assert.That(result!.HasError, Is.True);
            AssertWarning(verifier, "There are no acceptable trust anchors for the TPM attestation statement: neither the TPM manufacturer verifier nor the FIDO Metadata Service supplied a root certificate");
        });
    }

    [Test]
    public async Task VerifyAsync_Succeeds_WhenOnlyFidoMetadataSuppliesTrustAnchors()
    {
        var metadataRoots = new UniqueByteArraysCollection(TpmRoots.Microsoft);
        var verifier = new TestTpmAttestationStatementVerifier(new NoRootsTpmManufacturerVerifier()) { FidoMetadataRoots = metadataRoots };

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder().Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok!.AttestationRootCertificates, Is.EquivalentTo(metadataRoots));
            Assert.That(verifier.FakeLogger.Entries, Is.Empty);
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Untrusted strings in log messages: control characters are neutralized, the length is bounded

    [Test]
    public async Task VerifyAsync_NeutralizesControlCharacters_WhenLoggingUnknownManufacturer()
    {
        // the TPMManufacturer attribute comes from a certificate that has not been authenticated yet: CR LF would forge a log line and ESC start an escape sequence in a text sink,
        // U+2028 (LINE SEPARATOR) is rendered as a line break by some sinks
        var verifier = new TestTpmAttestationStatementVerifier();
        var attestation = new TpmAttestationBuilder { TpmManufacturer = "id:414D4400\r\n2026-10-19 00:00:00 [INF] forged line \u001b[31m\u2028" }.Build();

        var result = await verifier.VerifyAsync(attestation);

        var warnings = verifier.FakeLogger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message).ToArray();
        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(warnings, Has.Some.EqualTo("The TPMManufacturer 'id:414D4400??2026-10-19 00:00:00 [INF] forged line ?[31m?' of the AIK certificate is not a vendor identifier known to the library (TCG TPM Vendor ID Registry)"));
            AssertNoControlCharacters(warnings);
        });
    }

    [Test]
    public async Task VerifyAsync_TruncatesAndNeutralizesUnknownManufacturer_InLogMessage()
    {
        var verifier = new TestTpmAttestationStatementVerifier();
        var manufacturer = "id:" + new string('\n', 200);

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { TpmManufacturer = manufacturer }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, $"The TPMManufacturer 'id:{new string('?', 61)}...' of the AIK certificate");
        });
    }

    [Test]
    public async Task VerifyAsync_LogsNotCanonicalManufacturer_UnchangedBySanitization()
    {
        // the other sanitized log value: a known vendor identifier that is not canonical (lowercase hexadecimal digits) contains nothing to neutralize and is logged unchanged
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { TpmManufacturer = "id:414d4400" }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            AssertWarning(verifier, "The TPMManufacturer 'id:414d4400' of the AIK certificate is not in the canonical form");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers

    private static TpmAttestation DecodeAttestation(string attestationObjectBase64Url, string clientDataJsonBase64Url)
    {
        var cborDeserializer = new DefaultCborDeserializer(NullLogger<DefaultCborDeserializer>.Instance);
        var attestationObjectDecoder = new DefaultAttestationObjectDecoder(
            cborDeserializer,
            new DefaultEnumMemberAttributeSerializer<AttestationStatementFormat>(),
            NullLogger<DefaultAttestationObjectDecoder>.Instance);
        var authenticatorDataDecoder = new DefaultAuthenticatorDataDecoder(
            new DefaultCoseKeyDeserializer(cborDeserializer, NullLogger<DefaultCoseKeyDeserializer>.Instance),
            cborDeserializer,
            NullLogger<DefaultAuthenticatorDataDecoder>.Instance);
        var attestationStatementDecoder = new DefaultTpmAttestationStatementDecoder(new FakeRegistrationCeremonyCounters(), NullLogger<DefaultTpmAttestationStatementDecoder>.Instance);

        var attestationObject = attestationObjectDecoder.Decode(WebEncoders.Base64UrlDecode(attestationObjectBase64Url));
        Assert.That(attestationObject.HasError, Is.False, "the attestation object must decode");
        Assert.That(attestationObject.Ok!.Fmt, Is.EqualTo(AttestationStatementFormat.Tpm));
        var authenticatorData = authenticatorDataDecoder.Decode(attestationObject.Ok.AuthData!);
        Assert.That(authenticatorData.HasError, Is.False, "the authenticator data must decode");
        var attStmt = attestationStatementDecoder.Decode(attestationObject.Ok.AttStmt);
        Assert.That(attStmt.HasError, Is.False, "the attestation statement must decode");
        var clientDataHash = SHA256.HashData(WebEncoders.Base64UrlDecode(clientDataJsonBase64Url));
        return new(attStmt.Ok!, (AttestedAuthenticatorData) authenticatorData.Ok!, clientDataHash);
    }

    private static void AssertAnomaly(TestTpmAttestationStatementVerifier verifier, string anomaly, bool tolerated)
    {
        Assert.That(
            verifier.FakeCounters.AttestationStatementAnomalies,
            Has.Exactly(1).EqualTo(new FakeAttestationStatementAnomaly(TpmAttestationStatementAnomalies.Format, anomaly, tolerated)),
            $"expected exactly one '{anomaly}' anomaly (tolerated: {tolerated})");
    }

    private static void AssertWarning(TestTpmAttestationStatementVerifier verifier, string messagePart)
    {
        Assert.That(
            verifier.FakeLogger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
            Has.Some.Contains(messagePart),
            $"expected a Warning containing '{messagePart}'");
    }

    // an ordinal check: the culture-sensitive string comparison of NUnit's Contains treats some control characters (e.g. ESC) as ignorable
    private static void AssertNoControlCharacters(IEnumerable<string> messages)
    {
        Assert.That(
            messages,
            Has.All.Matches<string>(static message => message is not null && !message.Any(static character => char.IsControl(character) || character is '\u2028' or '\u2029')),
            "expected no control character, line separator or paragraph separator in any log message");
    }

    // ITpmManufacturerVerifier that knows every vendor but supplies no root certificates, deferring to the FIDO Metadata Service (as its contract allows)
    private sealed class NoRootsTpmManufacturerVerifier : ITpmManufacturerVerifier
    {
        public Result<UniqueByteArraysCollection?> IsValid(string tpmManufacturer)
        {
            return Result<UniqueByteArraysCollection?>.Success(null);
        }
    }
}
