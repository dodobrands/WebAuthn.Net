using System;
using System.Collections.Generic;
using System.Linq;
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
using WebAuthn.Net.Models.Protocol;
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
    private static readonly byte[] UserHandle = WebEncoders.Base64UrlDecode("AAAAAAAAAAAAAAAAAAAAAQ");
    private static readonly string[] KnownTransports = { "internal", "hybrid" };
    private static readonly string[] TransportsWithUnknownValue = { "future-transport", "hybrid", "internal" };
    private static readonly string[] RepeatedTransports = { "usb", "nfc", "usb" };

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

    // https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential (step 10)
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

    // https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential (step 11)
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

    // The specified top origins replace the default rule, so the origin itself is no longer an acceptable top origin.
    [Test]
    public async Task DefaultRegistrationCeremonyService_FailsCeremony_WhenTopOriginEqualsOriginButIsNotOneOfTheExpected()
    {
        using var authenticator = new SoftwareAuthenticator();
        var (ceremonyId, challenge) = await BeginCeremonyAsync(new(new[] { PartnerOrigin }));

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            authenticator.CreateRegistrationResponse(RpId, SoftwareAuthenticator.CreateClientDataJson("webauthn.create", challenge, Origin, true, Origin)));

        Assert.That(result.HasError, Is.True);
    }

    // https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-origin
    // The client reports an internationalized domain name in its Punycode form.
    [Test]
    public async Task DefaultRegistrationCeremonyService_CompletesCeremony_WhenInternationalizedOriginIsSpecifiedAsUri()
    {
        using var authenticator = new SoftwareAuthenticator();
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null, new(new[] { new Uri("https://пример.рф", UriKind.Absolute) }));

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            authenticator.CreateRegistrationResponse(RpId, SoftwareAuthenticator.CreateClientDataJson("webauthn.create", challenge, "https://xn--e1afmkfd.xn--p1ai")));

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

    // https://www.w3.org/TR/webauthn-3/#reg-ceremony-create-credential-record
    [Test]
    public async Task DefaultRegistrationCeremonyService_StoresAttestedCredentialIdAndTransports()
    {
        using var authenticator = new SoftwareAuthenticator();
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null);

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            authenticator.CreateRegistrationResponse(
                RpId,
                SoftwareAuthenticator.CreateClientDataJson("webauthn.create", challenge, Origin),
                transports: KnownTransports));

        Assert.That(result.HasError, Is.False);
        var descriptor = await FindStoredDescriptorAsync(authenticator.CredentialId);
        Assert.That(descriptor.Transports, Is.EqualTo(new[] { AuthenticatorTransport.Internal, AuthenticatorTransport.Hybrid }));
    }

    // https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-transports-slot - the library can store only the transports it knows,
    // and it doesn't modify the transports reported by the client (https://www.w3.org/TR/webauthn-3/#abstract-opdef-credential-record-transports)
    [Test]
    public async Task DefaultRegistrationCeremonyService_FailsCeremony_WhenTransportIsUnknown()
    {
        using var authenticator = new SoftwareAuthenticator();
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null);

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            authenticator.CreateRegistrationResponse(
                RpId,
                SoftwareAuthenticator.CreateClientDataJson("webauthn.create", challenge, Origin),
                transports: TransportsWithUnknownValue));

        Assert.That(result.HasError, Is.True);
    }

    // https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-transports-slot - the values are unique
    [Test]
    public async Task DefaultRegistrationCeremonyService_FailsCeremony_WhenTransportsRepeat()
    {
        using var authenticator = new SoftwareAuthenticator();
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null);

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            authenticator.CreateRegistrationResponse(
                RpId,
                SoftwareAuthenticator.CreateClientDataJson("webauthn.create", challenge, Origin),
                transports: RepeatedTransports));

        Assert.That(result.HasError, Is.True);
    }

    // A client reports each transport of the authenticator once, so a response with more than 100 transports is rejected
    [Test]
    public async Task DefaultRegistrationCeremonyService_FailsCeremony_WhenThereAreMoreThanOneHundredTransports()
    {
        using var authenticator = new SoftwareAuthenticator();
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null);

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            authenticator.CreateRegistrationResponse(
                RpId,
                SoftwareAuthenticator.CreateClientDataJson("webauthn.create", challenge, Origin),
                transports: Enumerable.Repeat("usb", 101).ToArray()));

        Assert.That(result.HasError, Is.True);
    }

    private async Task<PublicKeyCredentialDescriptor> FindStoredDescriptorAsync(byte[] credentialId)
    {
        await using var context = await ContextFactory.CreateAsync(new DefaultHttpContext(new FeatureCollection()), CancellationToken.None);
        var descriptors = await CredentialStorage.FindDescriptorsAsync(context, RpId, UserHandle, CancellationToken.None);
        return descriptors.Single(x => x.Id.AsSpan().SequenceEqual(credentialId));
    }

    private async Task<(string CeremonyId, string Challenge)> BeginCeremonyAsync(
        RegistrationCeremonyOriginParameters? topOrigins,
        RegistrationCeremonyOriginParameters? origins = null)
    {
        var beginResult = await RegistrationCeremonyService.BeginCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                origins,
                topOrigins,
                "Test Host",
                new("testuser", UserHandle, "Test User"),
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
