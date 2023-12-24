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
using WebAuthn.Net.Services.RegistrationCeremony.Implementation.DefaultRegistrationCeremonyService.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation.DefaultRegistrationCeremonyService.AttestationTypes;

public class DefaultRegistrationCeremonyServiceNoneTests : AbstractRegistrationCeremonyServiceTests
{
    protected override IEnumerable<KeyValuePair<string, string?>>? GetConfiguration()
    {
        yield return new($"{nameof(WebAuthnOptions.AttestationTypes)}:{nameof(AttestationTypeOptions.None)}:{nameof(NoneAttestationTypeOptions.IsAcceptable)}", "true");
    }

    protected override Uri GetRelyingPartyAddress()
    {
        return new("https://vanbukin-pc.local", UriKind.Absolute);
    }

    [Test]
    public async Task DefaultRegistrationCeremonyService_PerformsCeremonyWithoutErrorsForNone_WhenEcdsaRsa()
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
}
