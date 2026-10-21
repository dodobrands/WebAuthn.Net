using System;
using System.Collections.Generic;
using System.Linq;
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
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.VerifyAssertion;
using WebAuthn.Net.Services.AuthenticationCeremony.Implementation.DefaultAuthenticationCeremonyService.Abstractions;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.VerifyAssertion;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Implementation.DefaultAuthenticationCeremonyService;

// Responses built by software authenticators, so that the client data and the identifiers can be anything a client sends.
public class DefaultAuthenticationCeremonyServiceClientResponseTests : AbstractAuthenticationCeremonyServiceTests
{
    private const string RpId = "vanbukin-pc.local";
    private const string Origin = "https://vanbukin-pc.local";
    private const string PartnerOrigin = "https://partner.example";
    private static readonly byte[] UserHandle = WebEncoders.Base64UrlDecode("AAAAAAAAAAAAAAAAAAAAAQ");
    private static readonly string[] RegisteredTransports = { "internal", "hybrid" };

    private SoftwareAuthenticator FirstAuthenticator { get; set; } = null!;
    private SoftwareAuthenticator SecondAuthenticator { get; set; } = null!;

    protected override IEnumerable<KeyValuePair<string, string?>>? GetConfiguration()
    {
        yield return new($"{nameof(WebAuthnOptions.AttestationTypes)}:{nameof(AttestationTypeOptions.None)}:{nameof(NoneAttestationTypeOptions.IsAcceptable)}", "true");
        yield return new($"{nameof(WebAuthnOptions.AuthenticationCeremony)}:{nameof(AuthenticationCeremonyOptions.AbortCeremonyWhenSignCountIsLessOrEqualStoredValue)}", "false");
    }

    protected override Uri GetRelyingPartyAddress()
    {
        return new(Origin, UriKind.Absolute);
    }

    [SetUp]
    public async Task SetupRegistrationsAsync()
    {
        FirstAuthenticator = new();
        SecondAuthenticator = new();
        await RegisterAsync(FirstAuthenticator, 5);
        await RegisterAsync(SecondAuthenticator, 0);
    }

    [TearDown]
    public void TearDownAuthenticators()
    {
        FirstAuthenticator.Dispose();
        SecondAuthenticator.Dispose();
    }

    [Test]
    public async Task DefaultAuthenticationCeremonyService_CompletesCeremony_WhenResponseIsConsistent()
    {
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null);

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            SecondAuthenticator.CreateAuthenticationResponse(RpId, SoftwareAuthenticator.CreateClientDataJson("webauthn.get", challenge, Origin), UserHandle));

        Assert.That(result.HasError, Is.False);
    }

    // https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion (step 13)
    [Test]
    public async Task DefaultAuthenticationCeremonyService_FailsCeremony_WhenCrossOriginWithoutTopOriginIsNotExpected()
    {
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null);

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            SecondAuthenticator.CreateAuthenticationResponse(RpId, SoftwareAuthenticator.CreateClientDataJson("webauthn.get", challenge, Origin, true), UserHandle));

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public async Task DefaultAuthenticationCeremonyService_CompletesCeremony_WhenCrossOriginWithoutTopOriginIsExpected()
    {
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null, new(new[] { PartnerOrigin }));

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            SecondAuthenticator.CreateAuthenticationResponse(RpId, SoftwareAuthenticator.CreateClientDataJson("webauthn.get", challenge, Origin, true), UserHandle));

        Assert.That(result.HasError, Is.False);
    }

    // https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion (step 14)
    [Test]
    public async Task DefaultAuthenticationCeremonyService_FailsCeremony_WhenUnexpectedTopOriginComesWithoutCrossOrigin()
    {
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null);

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            SecondAuthenticator.CreateAuthenticationResponse(RpId, SoftwareAuthenticator.CreateClientDataJson("webauthn.get", challenge, Origin, null, PartnerOrigin), UserHandle));

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public async Task DefaultAuthenticationCeremonyService_FailsCeremony_WhenTopOriginIsNotOneOfTheExpected()
    {
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null, new(new[] { PartnerOrigin }));

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            SecondAuthenticator.CreateAuthenticationResponse(RpId, SoftwareAuthenticator.CreateClientDataJson("webauthn.get", challenge, Origin, true, "https://evil.example"), UserHandle));

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public async Task DefaultAuthenticationCeremonyService_CompletesCeremony_WhenTopOriginIsExpected()
    {
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null, new(new[] { PartnerOrigin }));

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            SecondAuthenticator.CreateAuthenticationResponse(RpId, SoftwareAuthenticator.CreateClientDataJson("webauthn.get", challenge, Origin, true, PartnerOrigin), UserHandle));

        Assert.That(result.HasError, Is.False);
    }

    // https://www.w3.org/TR/webauthn-3/#sctn-validating-origin
    // A web application that does not wish to be embedded in a cross-origin iframe might require topOrigin to exactly equal origin.
    [Test]
    public async Task DefaultAuthenticationCeremonyService_CompletesCeremony_WhenTopOriginEqualsOrigin()
    {
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null);

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            SecondAuthenticator.CreateAuthenticationResponse(RpId, SoftwareAuthenticator.CreateClientDataJson("webauthn.get", challenge, Origin, true, Origin), UserHandle));

        Assert.That(result.HasError, Is.False);
    }

    // The specified top origins replace the default rule, so the origin itself is no longer an acceptable top origin.
    [Test]
    public async Task DefaultAuthenticationCeremonyService_FailsCeremony_WhenTopOriginEqualsOriginButIsNotOneOfTheExpected()
    {
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null, new(new[] { PartnerOrigin }));

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            SecondAuthenticator.CreateAuthenticationResponse(RpId, SoftwareAuthenticator.CreateClientDataJson("webauthn.get", challenge, Origin, true, Origin), UserHandle));

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public async Task DefaultAuthenticationCeremonyService_IncludesOnlyManuallySpecifiedCredentials()
    {
        var beginResult = await AuthenticationCeremonyService.BeginCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            CreateBeginRequest(AuthenticationCeremonyIncludeCredentials.ManuallySpecified(new[]
            {
                new AuthenticationCeremonyPublicKeyCredentialDescriptor(PublicKeyCredentialType.PublicKey, FirstAuthenticator.CredentialId)
            })),
            CancellationToken.None);

        Assert.That(beginResult.Options.AllowCredentials, Is.Not.Null);
        Assert.That(beginResult.Options.AllowCredentials!.Select(static x => x.Id), Is.EqualTo(new[] { WebEncoders.Base64UrlEncode(FirstAuthenticator.CredentialId) }));
    }

    // https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion (step 5)
    [Test]
    public async Task DefaultAuthenticationCeremonyService_FailsCeremony_WhenCredentialIsNotAllowed()
    {
        var (ceremonyId, challenge) = await BeginCeremonyAsync(FirstAuthenticator.CredentialId);

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            SecondAuthenticator.CreateAuthenticationResponse(RpId, SoftwareAuthenticator.CreateClientDataJson("webauthn.get", challenge, Origin), UserHandle));

        Assert.That(result.HasError, Is.True);
    }

    // 'id' passes the allowCredentials check (step 5), while 'rawId' selects the credential record that verifies the signature (step 6).
    [Test]
    public async Task DefaultAuthenticationCeremonyService_FailsCeremony_WhenIdDoesNotMatchRawId()
    {
        var (ceremonyId, challenge) = await BeginCeremonyAsync(FirstAuthenticator.CredentialId);

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            SecondAuthenticator.CreateAuthenticationResponse(
                RpId,
                SoftwareAuthenticator.CreateClientDataJson("webauthn.get", challenge, Origin),
                UserHandle,
                id: FirstAuthenticator.CredentialId));

        Assert.That(result.HasError, Is.True);
    }

    // https://www.w3.org/TR/webauthn-3/#reg-ceremony-create-credential-record
    [Test]
    public async Task DefaultRegistrationCeremonyService_StoresAttestedCredentialIdAndTransports()
    {
        await using var context = await ContextFactory.CreateAsync(new DefaultHttpContext(new FeatureCollection()), CancellationToken.None);
        var descriptors = await CredentialStorage.FindDescriptorsAsync(context, RpId, UserHandle, CancellationToken.None);
        var descriptor = descriptors.Single(x => x.Id.AsSpan().SequenceEqual(FirstAuthenticator.CredentialId));

        Assert.That(descriptor.Transports, Is.EqualTo(new[] { AuthenticatorTransport.Internal, AuthenticatorTransport.Hybrid }));
    }

    // https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion (step 22): the Relying Party may decide to continue.
    [Test]
    public async Task DefaultAuthenticationCeremonyService_CompletesCeremony_WhenSignCountDidNotIncreaseAndAbortIsDisabled()
    {
        var (ceremonyId, challenge) = await BeginCeremonyAsync(null);

        var result = await CompleteCeremonyAsync(
            ceremonyId,
            FirstAuthenticator.CreateAuthenticationResponse(RpId, SoftwareAuthenticator.CreateClientDataJson("webauthn.get", challenge, Origin), UserHandle, signCount: 3));

        Assert.That(result.HasError, Is.False);
    }

    private async Task RegisterAsync(SoftwareAuthenticator authenticator, uint signCount)
    {
        var beginResult = await RegistrationCeremonyService.BeginCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                null,
                null,
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
        var completeResult = await RegistrationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                beginResult.RegistrationCeremonyId,
                null,
                authenticator.CreateRegistrationResponse(
                    RpId,
                    SoftwareAuthenticator.CreateClientDataJson("webauthn.create", beginResult.Options.Challenge, Origin),
                    signCount: signCount,
                    transports: RegisteredTransports)),
            CancellationToken.None);
        Assert.That(completeResult.HasError, Is.False);
    }

    private async Task<(string CeremonyId, string Challenge)> BeginCeremonyAsync(
        byte[]? allowedCredentialId,
        AuthenticationCeremonyOriginParameters? topOrigins = null)
    {
        var allowCredentials = allowedCredentialId is null
            ? null
            : AuthenticationCeremonyIncludeCredentials.ManuallySpecified(new[]
            {
                new AuthenticationCeremonyPublicKeyCredentialDescriptor(PublicKeyCredentialType.PublicKey, allowedCredentialId)
            });
        var beginResult = await AuthenticationCeremonyService.BeginCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            CreateBeginRequest(allowCredentials, topOrigins),
            CancellationToken.None);
        return (beginResult.AuthenticationCeremonyId, beginResult.Options.Challenge);
    }

    private static BeginAuthenticationCeremonyRequest CreateBeginRequest(
        AuthenticationCeremonyIncludeCredentials? allowCredentials,
        AuthenticationCeremonyOriginParameters? topOrigins = null)
    {
        return new(
            null,
            topOrigins,
            allowCredentials is null ? null : UserHandle,
            32,
            60000,
            allowCredentials,
            UserVerificationRequirement.Required,
            null,
            null);
    }

    private async Task<Result<CompleteAuthenticationCeremonyResult>> CompleteCeremonyAsync(
        string ceremonyId,
        AuthenticationResponseJSON response)
    {
        return await AuthenticationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(ceremonyId, response),
            CancellationToken.None);
    }
}
