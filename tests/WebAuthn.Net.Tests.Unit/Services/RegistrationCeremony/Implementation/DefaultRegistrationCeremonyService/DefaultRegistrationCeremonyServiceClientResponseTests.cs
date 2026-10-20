using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;
using NUnit.Framework;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Configuration.Options.AttestationTypes;
using WebAuthn.Net.DSL;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Services.RegistrationCeremony.Implementation.DefaultRegistrationCeremonyService.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateCredential;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation.DefaultRegistrationCeremonyService;

// Responses built by a software authenticator, so that the client data and the identifiers can be anything a client sends.
public class DefaultRegistrationCeremonyServiceClientResponseTests : AbstractRegistrationCeremonyServiceTests
{
    private const string RpId = "vanbukin-pc.local";
    private const string Origin = "https://vanbukin-pc.local";
    private const string PartnerOrigin = "https://partner.example";

    protected override IEnumerable<KeyValuePair<string, string?>>? GetConfiguration()
    {
        yield return new($"{nameof(WebAuthnOptions.AttestationTypes)}:{nameof(AttestationTypeOptions.None)}:{nameof(NoneAttestationTypeOptions.IsAcceptable)}", "true");
    }

    protected override Uri GetRelyingPartyAddress()
    {
        return new(Origin, UriKind.Absolute);
    }

    [Test]
    public async Task DefaultRegistrationCeremonyService_CompletesCeremony_WhenResponseIsConsistent()
    {
        using var authenticator = new SoftwareAuthenticator();
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null);

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            authenticator.CreateRegistrationResponse(RpId, SoftwareAuthenticator.CreateClientDataJson("webauthn.create", challenge, Origin)));

        Assert.That(result.HasError, Is.False);
    }

    // https://www.w3.org/TR/webauthn-3/#reg-ceremony-verify-cross-origin
    [Test]
    public async Task DefaultRegistrationCeremonyService_FailsCeremony_WhenCrossOriginWithoutTopOriginIsNotExpected()
    {
        using var authenticator = new SoftwareAuthenticator();
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null);

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            authenticator.CreateRegistrationResponse(RpId, SoftwareAuthenticator.CreateClientDataJson("webauthn.create", challenge, Origin, true)));

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public async Task DefaultRegistrationCeremonyService_CompletesCeremony_WhenCrossOriginWithoutTopOriginIsExpected()
    {
        using var authenticator = new SoftwareAuthenticator();
        var (ceremonyId, challenge) = await BeginCeremonyAsync(new(new[] { PartnerOrigin }));

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            authenticator.CreateRegistrationResponse(RpId, SoftwareAuthenticator.CreateClientDataJson("webauthn.create", challenge, Origin, true)));

        Assert.That(result.HasError, Is.False);
    }

    // https://www.w3.org/TR/webauthn-3/#reg-ceremony-verify-top-origin
    [Test]
    public async Task DefaultRegistrationCeremonyService_FailsCeremony_WhenUnexpectedTopOriginComesWithoutCrossOrigin()
    {
        using var authenticator = new SoftwareAuthenticator();
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null);

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            authenticator.CreateRegistrationResponse(RpId, SoftwareAuthenticator.CreateClientDataJson("webauthn.create", challenge, Origin, false, PartnerOrigin)));

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public async Task DefaultRegistrationCeremonyService_FailsCeremony_WhenTopOriginIsNotOneOfTheExpected()
    {
        using var authenticator = new SoftwareAuthenticator();
        var (ceremonyId, challenge) = await BeginCeremonyAsync(new(new[] { PartnerOrigin }));

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            authenticator.CreateRegistrationResponse(RpId, SoftwareAuthenticator.CreateClientDataJson("webauthn.create", challenge, Origin, true, "https://evil.example")));

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public async Task DefaultRegistrationCeremonyService_CompletesCeremony_WhenTopOriginIsExpected()
    {
        using var authenticator = new SoftwareAuthenticator();
        var (ceremonyId, challenge) = await BeginCeremonyAsync(new(new[] { PartnerOrigin }));

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            authenticator.CreateRegistrationResponse(RpId, SoftwareAuthenticator.CreateClientDataJson("webauthn.create", challenge, Origin, true, PartnerOrigin)));

        Assert.That(result.HasError, Is.False);
    }

    // https://www.w3.org/TR/webauthn-3/#sctn-validating-origin
    // A web application that does not wish to be embedded in a cross-origin iframe might require topOrigin to exactly equal origin.
    [Test]
    public async Task DefaultRegistrationCeremonyService_CompletesCeremony_WhenTopOriginEqualsOrigin()
    {
        using var authenticator = new SoftwareAuthenticator();
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null);

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            authenticator.CreateRegistrationResponse(RpId, SoftwareAuthenticator.CreateClientDataJson("webauthn.create", challenge, Origin, true, Origin)));

        Assert.That(result.HasError, Is.False);
    }

    [Test]
    public async Task DefaultRegistrationCeremonyService_FailsCeremony_WhenIdDoesNotMatchRawId()
    {
        using var authenticator = new SoftwareAuthenticator();
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null);

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            authenticator.CreateRegistrationResponse(
                RpId,
                SoftwareAuthenticator.CreateClientDataJson("webauthn.create", challenge, Origin),
                id: RandomNumberGenerator.GetBytes(32)));

        Assert.That(result.HasError, Is.True);
    }

    // The client-supplied credential ID must be the one in the attested credential data, otherwise it would be stored instead of the real one.
    [Test]
    public async Task DefaultRegistrationCeremonyService_FailsCeremony_WhenRawIdDoesNotMatchAttestedCredentialId()
    {
        using var authenticator = new SoftwareAuthenticator();
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null);
        var otherCredentialId = RandomNumberGenerator.GetBytes(2000);

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            authenticator.CreateRegistrationResponse(
                RpId,
                SoftwareAuthenticator.CreateClientDataJson("webauthn.create", challenge, Origin),
                id: otherCredentialId,
                rawId: otherCredentialId));

        Assert.That(result.HasError, Is.True);
    }

    private async Task<(string CeremonyId, string Challenge)> BeginCeremonyAsync(RegistrationCeremonyOriginParameters? topOrigins)
    {
        var beginResult = await RegistrationCeremonyService.BeginCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                null,
                topOrigins,
                "Test Host",
                new("testuser", WebEncoders.Base64UrlDecode("AAAAAAAAAAAAAAAAAAAAAQ"), "Test User"),
                32,
                new[]
                {
                    CoseAlgorithm.ES256
                },
                60000,
                RegistrationCeremonyExcludeCredentials.AllExisting(),
                new(null, null, null, UserVerificationRequirement.Required),
                null,
                AttestationConveyancePreference.None,
                null,
                null),
            CancellationToken.None);
        return (beginResult.RegistrationCeremonyId, beginResult.Options.Challenge);
    }

    private async Task<Result<CompleteRegistrationCeremonyResult>> CompleteCeremonyAsync(
        string ceremonyId,
        RegistrationResponseJSON response)
    {
        return await RegistrationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(ceremonyId, null, response),
            CancellationToken.None);
    }
}
