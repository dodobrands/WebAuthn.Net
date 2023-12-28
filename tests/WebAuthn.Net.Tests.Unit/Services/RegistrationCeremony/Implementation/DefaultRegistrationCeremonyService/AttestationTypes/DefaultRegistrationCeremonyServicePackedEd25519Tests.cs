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

public class DefaultRegistrationCeremonyServicePackedEd25519Tests : AbstractRegistrationCeremonyServiceTests
{
    protected override Uri GetRelyingPartyAddress()
    {
        return new("https://sunny-rightly-civet.ngrok-free.app", UriKind.Absolute);
    }

    [Test]
    public async Task DefaultRegistrationCeremonyService_PerformsCeremonyWithoutErrorsForPacked_WhenEd25519()
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
                new[] { CoseAlgorithm.EdDSA },
                60000,
                RegistrationCeremonyExcludeCredentials.AllExisting(),
                new(null, ResidentKeyRequirement.Required, false, UserVerificationRequirement.Required),
                null,
                AttestationConveyancePreference.Direct,
                null,
                null),
            CancellationToken.None);

        RegistrationCeremonyStorage.ReplaceChallengeForRegistrationCeremonyOptions(
            beginResult.RegistrationCeremonyId,
            WebEncoders.Base64UrlDecode("hoduAzRM8bdQVUaasqAHOA"));

        var completeResult = await RegistrationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                beginResult.RegistrationCeremonyId,
                null,
                new(
                    "cNOQx_X1dUKCYDdmFfQ4v6FS0xc_D-IlzHkXgI-EgTXs-ah8e_KCSou1igeou7iq",
                    "cNOQx_X1dUKCYDdmFfQ4v6FS0xc_D-IlzHkXgI-EgTXs-ah8e_KCSou1igeou7iq",
                    new(
                        "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiaG9kdUF6Uk04YmRRVlVhYXNxQUhPQSIsIm9yaWdpbiI6Imh0dHBzOi8vc3VubnktcmlnaHRseS1jaXZldC5uZ3Jvay1mcmVlLmFwcCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
                        null,
                        null,
                        null,
                        null,
                        "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgKWpaL8DITbfzZidzJVpfxDIVmzopLyfFNn--ExsbAZoCIQDWda4WCqKMLfc2FFQHz7vcWRyki9fcdFrlnAFAyTFlTmN4NWOBWQLdMIIC2TCCAcGgAwIBAgIJAPDqu31oBEyKMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjBvMQswCQYDVQQGEwJTRTESMBAGA1UECgwJWXViaWNvIEFCMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMSgwJgYDVQQDDB9ZdWJpY28gVTJGIEVFIFNlcmlhbCAyMTA5NDY3Mzc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5mfTO7qcRZuAnvzLaguuLFz8S9eB1XNIPZb96SUfZCzN5sIGVRTzM4JGrJlSgAAq0jivvANxttf6w7_LnnnSMKOBgTB_MBMGCisGAQQBgsQKDQEEBQQDBQQDMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS43MBMGCysGAQQBguUcAgEBBAQDAgQwMCEGCysGAQQBguUcAQEEBBIEEC_AV5-BE0fqsRa7Wo25ICowDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAtjGoKNeTOK0pAIoNf3mjoD3PLgybH2L6z7SKnlWVd6dRbJWbZCsY8AxMdyKNGfnUQiJcEmi9IxigjGoXcwZPApnJm7JDike7Z7HQ2yUrlJZ-EgFamivp5C3UVCaIkGH-HyJW_vh23XOZMkaDcRqwbeq8b0Voavnu4YF5bCM7PtnsPcCsvfL5DahPGSfpc9YyANG49OQBOZolNF3MBKKrspOAI7RfW0JSQY0NUnWFYx9hxFbNuYsKFN4NblJ_Zz9tMk1YYSkTJ6VfxHTo5tfIcaLfZ1dIrMeY12-WevjMufFW_qB4ErY5Gjft3cbiZBELmbQ9QLUyLX78lHiLC9pJImhhdXRoRGF0YVif9LDXMfg-tpDkp8NkozQ4wEZ932qRlKLYEvVDB6WER_jFAAAAAS_AV5-BE0fqsRa7Wo25ICoAMHDTkMf19XVCgmA3ZhX0OL-hUtMXPw_iJcx5F4CPhIE17PmofHvygkqLtYoHqLu4qqQBAQMnIAYhWCBw05DH9fV1QoJgN2YVHF4OZwokUxU_G3R9_pLUTxgF0KFrY3JlZFByb3RlY3QC"
                    ),
                    null,
                    new(),
                    "public-key")),
            CancellationToken.None);
        Assert.That(completeResult.HasError, Is.False);
    }
}
