using System;
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

public class DefaultAuthenticationCeremonyServiceAppleAnonymousTests : AbstractAuthenticationCeremonyServiceTests
{
    protected override Uri GetRelyingPartyAddress()
    {
        return new("https://goose-wondrous-overly.ngrok-free.app", UriKind.Absolute);
    }

    [SetUp]
    public async Task SetupRegistrationAsync()
    {
        TimeProvider.Change(DateTimeOffset.Parse("2023-10-16T08:43:33Z", CultureInfo.InvariantCulture));
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
                    CoseAlgorithm.ES512,
                    CoseAlgorithm.RS256,
                    CoseAlgorithm.RS384,
                    CoseAlgorithm.RS512,
                    CoseAlgorithm.PS256,
                    CoseAlgorithm.PS384,
                    CoseAlgorithm.PS512
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
            WebEncoders.Base64UrlDecode("yup7N3Elt8TEfOl0hjWTyvBZ66Cfd9fCvNVZlpSzVI0"));

        var completeResult = await RegistrationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                beginResult.RegistrationCeremonyId,
                null,
                new(
                    "hQH9wsekUgtg2RJpgkUcvqDU1cA",
                    "hQH9wsekUgtg2RJpgkUcvqDU1cA",
                    new(
                        "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoieXVwN04zRWx0OFRFZk9sMGhqV1R5dkJaNjZDZmQ5ZkN2TlZabHBTelZJMCIsIm9yaWdpbiI6Imh0dHBzOi8vZ29vc2Utd29uZHJvdXMtb3Zlcmx5Lm5ncm9rLWZyZWUuYXBwIn0",
                        null,
                        null,
                        null,
                        null,
                        "o2NmbXRlYXBwbGVnYXR0U3RtdKFjeDVjglkCRzCCAkMwggHJoAMCAQICBgGLN6eehzAKBggqhkjOPQQDAjBIMRwwGgYDVQQDDBNBcHBsZSBXZWJBdXRobiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIzMTAxNTA4NDMzM1oXDTIzMTAxODA4NDMzM1owgZExSTBHBgNVBAMMQDExZTU0NWRiNWYzOGI5Y2YwNWFjZTI4MTM1MzU3MjcyNTQ5MWQzMDViODI4MTdlMTY5OWMwNjZhYjU5ZjA1YjgxGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVqnK5tBbRJ2ju7mG58Fo22n-g7unkA3wiWzH16IvF3D9VTKCGFIVCc5Ash_fbYM7z4Kd1D6pjmeez8-PTw4HL6NVMFMwDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCBPAwMwYJKoZIhvdjZAgCBCYwJKEiBCARkoy5fP-rtLSo1R55DnhkTL_KseledyR14nsg0YYa0jAKBggqhkjOPQQDAgNoADBlAjEAzKHjTlbA5eykslm25gOtQHJw3CRERt9D0ewUl13KegkrCInZ1WjrzTF7ofnvz1rMAjASN1mx2pLJBHILgwcSp2zGWlF-KqCKVttpeLBRuUsollvDT2MXpwlyhY7ujbGJPdBZAjgwggI0MIIBuqADAgECAhBWJVOVx6f7QOviKNgmCFO2MAoGCCqGSM49BAMDMEsxHzAdBgNVBAMMFkFwcGxlIFdlYkF1dGhuIFJvb3QgQ0ExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwMzE4MTgzODAxWhcNMzAwMzEzMDAwMDAwWjBIMRwwGgYDVQQDDBNBcHBsZSBXZWJBdXRobiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgy6HLyYUkYECJbn1_Na7Y3i19V8_ywRbxzWZNHX9VJBE35v-GSEXZcaaHdoFCzjUUINAGkNPsk0RLVbD4c-_y5iR_sBpYIG--Wy8d8iN3a9Gpa7h3VFbWvqrk76cCyaRo2YwZDASBgNVHRMBAf8ECDAGAQH_AgEAMB8GA1UdIwQYMBaAFCbXZNnFeMJaZ9Gn3msS0Btj8cbXMB0GA1UdDgQWBBTrroLE_6GsW1HUzyRhBQC-Y713iDAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIxAN2LGjSBpfrZ27TnZXuEHhRMJ7dbh2pBhsKxR1dQM3In7-VURX72SJUMYy5cSD5wwQIwLIpgRNwgH8_lm8NNKTDBSHhR2WDtanXx60rKvjjNJbiX0MgFvvDH94sHpXHG6A4HaGF1dGhEYXRhWJiaI8k6vrhiKSN-_wzLIUEsHADjbrQK5uMK0eabhm22xUUAAAAA8kqOcNDT-CwpNzJSPMTeWgAUhQH9wsekUgtg2RJpgkUcvqDU1cClAQIDJiABIVggVqnK5tBbRJ2ju7mG58Fo22n-g7unkA3wiWzH16IvF3AiWCD9VTKCGFIVCc5Ash_fbYM7z4Kd1D6pjmeez8-PTw4HLw"
                    ),
                    null,
                    new(),
                    "public-key")),
            CancellationToken.None);
        Assert.That(completeResult.HasError, Is.False);
    }

    [Test]
    public async Task DefaultAuthenticationCeremonyService_PerformsCeremonyWithoutErrorsForApple_WhenAllAlgorithms()
    {
        TimeProvider.Change(DateTimeOffset.Parse("2023-10-16T08:43:43Z", CultureInfo.InvariantCulture));
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
            WebEncoders.Base64UrlDecode("qq74tcXbJQwmJREHIjTnDNpHwvmFq7ZuJDDzvAr0Ffc"));

        var completeResult = await AuthenticationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(beginResult.AuthenticationCeremonyId,
                new("hQH9wsekUgtg2RJpgkUcvqDU1cA",
                    "hQH9wsekUgtg2RJpgkUcvqDU1cA",
                    new("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoicXE3NHRjWGJKUXdtSlJFSElqVG5ETnBId3ZtRnE3WnVKRER6dkFyMEZmYyIsIm9yaWdpbiI6Imh0dHBzOi8vZ29vc2Utd29uZHJvdXMtb3Zlcmx5Lm5ncm9rLWZyZWUuYXBwIn0",
                        "miPJOr64Yikjfv8MyyFBLBwA4260CubjCtHmm4ZttsUFAAAAAA",
                        "MEQCIAtHt5DbKSW1AMor7SgAhNiqrnsihqvq2befT1lVMIKAAiAdlE_FYWJTUvhlStf9AwCKdWh6gSNIahGRWhfwxtXPrw",
                        "AAAAAAAAAAAAAAAAAAAAAQ",
                        null),
                    null,
                    new(),
                    "public-key")),
            CancellationToken.None);
        Assert.That(completeResult.HasError, Is.False);
    }
}
