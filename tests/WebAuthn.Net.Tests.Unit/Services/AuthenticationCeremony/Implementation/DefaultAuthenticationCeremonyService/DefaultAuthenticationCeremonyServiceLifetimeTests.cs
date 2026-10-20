using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;
using NUnit.Framework;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Configuration.Options.AttestationTypes;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.VerifyAssertion;
using WebAuthn.Net.Services.AuthenticationCeremony.Implementation.DefaultAuthenticationCeremonyService.Abstractions;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Implementation.DefaultAuthenticationCeremonyService;

// https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges
// The vectors come from an authenticator that always reports signCount = 0, so the signature counter can't detect a replay.
public class DefaultAuthenticationCeremonyServiceLifetimeTests : AbstractAuthenticationCeremonyServiceTests
{
    private const uint CeremonyTimeout = 60000;

    protected override IEnumerable<KeyValuePair<string, string?>>? GetConfiguration()
    {
        yield return new($"{nameof(WebAuthnOptions.AttestationTypes)}:{nameof(AttestationTypeOptions.None)}:{nameof(NoneAttestationTypeOptions.IsAcceptable)}", "true");
    }

    protected override Uri GetRelyingPartyAddress()
    {
        return new("https://vanbukin-pc.local", UriKind.Absolute);
    }

    [SetUp]
    public async Task SetupRegistrationAsync()
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
                    CoseAlgorithm.RS256
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
            WebEncoders.Base64UrlDecode("EQahQOdHceOWoC3RvPolTLybjIjLwCrhR8b1ZMpijyQ"));

        var completeResult = await RegistrationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                beginResult.RegistrationCeremonyId,
                null,
                new(
                    "iDFd_AQcKvKWSPeteal0SjVcYuo",
                    "iDFd_AQcKvKWSPeteal0SjVcYuo",
                    new(
                        "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiRVFhaFFPZEhjZU9Xb0MzUnZQb2xUTHliaklqTHdDcmhSOGIxWk1waWp5USIsIm9yaWdpbiI6Imh0dHBzOi8vdmFuYnVraW4tcGMubG9jYWwifQ",
                        null,
                        null,
                        null,
                        null,
                        "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYwbGR7JKb_3nCDS_Zb_TxyUe4a4rtFXaAsGAUBoQQGPVdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFIgxXfwEHCrylkj3rXmpdEo1XGLqpQECAyYgASFYICRm7Ppob1RBskUFZmOz0De8LRHkyBmEy_tja6XcAPdbIlggZZc4w5BaGG4IqtOG7lHgTijKOqGUJR98CaU5spPCiTY"
                    ),
                    null,
                    new(),
                    "public-key")),
            CancellationToken.None);
        Assert.That(completeResult.HasError, Is.False);
    }

    [Test]
    public async Task DefaultAuthenticationCeremonyService_FailsCeremony_WhenTheSameResponseIsReplayed()
    {
        var authenticationCeremonyId = await BeginCeremonyAsync();

        var firstResult = await AuthenticationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(authenticationCeremonyId, CreateResponse()),
            CancellationToken.None);
        Assert.That(firstResult.HasError, Is.False);

        var replayResult = await AuthenticationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(authenticationCeremonyId, CreateResponse()),
            CancellationToken.None);
        Assert.That(replayResult.HasError, Is.True);
    }

    [Test]
    public async Task DefaultAuthenticationCeremonyService_CompletesCeremony_WhenCompletedBeforeExpiration()
    {
        var authenticationCeremonyId = await BeginCeremonyAsync();
        TimeProvider.Change(TimeProvider.GetPreciseUtcDateTime().AddMilliseconds(CeremonyTimeout / 2));

        var completeResult = await AuthenticationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(authenticationCeremonyId, CreateResponse()),
            CancellationToken.None);
        Assert.That(completeResult.HasError, Is.False);
    }

    [Test]
    public async Task DefaultAuthenticationCeremonyService_FailsCeremony_WhenCeremonyHasExpired()
    {
        var authenticationCeremonyId = await BeginCeremonyAsync();
        TimeProvider.Change(TimeProvider.GetPreciseUtcDateTime().AddMilliseconds(CeremonyTimeout + 1000));

        var completeResult = await AuthenticationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(authenticationCeremonyId, CreateResponse()),
            CancellationToken.None);
        Assert.That(completeResult.HasError, Is.True);
    }

    private async Task<string> BeginCeremonyAsync()
    {
        var beginRequest = new BeginAuthenticationCeremonyRequest(
            null,
            null,
            null,
            32,
            CeremonyTimeout,
            null,
            UserVerificationRequirement.Required,
            null,
            null);
        var beginResult = await AuthenticationCeremonyService.BeginCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            beginRequest,
            CancellationToken.None);

        AuthenticationCeremonyStorage.ReplaceChallengeForAuthenticationCeremonyOptions(
            beginResult.AuthenticationCeremonyId,
            WebEncoders.Base64UrlDecode("6Sv-6C5arRYUGiGFMgPVXl1anVBeKyiQvEqrkqIPxsc"));
        return beginResult.AuthenticationCeremonyId;
    }

    private static AuthenticationResponseJSON CreateResponse()
    {
        return new(
            "iDFd_AQcKvKWSPeteal0SjVcYuo",
            "iDFd_AQcKvKWSPeteal0SjVcYuo",
            new(
                "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiNlN2LTZDNWFyUllVR2lHRk1nUFZYbDFhblZCZUt5aVF2RXFya3FJUHhzYyIsIm9yaWdpbiI6Imh0dHBzOi8vdmFuYnVraW4tcGMubG9jYWwifQ",
                "wbGR7JKb_3nCDS_Zb_TxyUe4a4rtFXaAsGAUBoQQGPUdAAAAAA",
                "MEYCIQDebfWSh29hMhN8N6I9LsedJIMKBTLYBykMarfAvNdm0gIhAKRD4M6VApPke-qG3eqms-PrlJ_VTteF6MU9sdlihMBj",
                "AAAAAAAAAAAAAAAAAAAAAQ"),
            null,
            new(),
            "public-key");
    }
}
