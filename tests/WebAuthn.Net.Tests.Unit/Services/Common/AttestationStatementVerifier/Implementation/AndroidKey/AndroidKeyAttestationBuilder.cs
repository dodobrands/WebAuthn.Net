using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.Cryptography.Sign.Implementation;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.Serialization.Asn1.Implementation;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using static WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AttestationStatementVerifierTestHelpers;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidKey;

/// <summary>
///     Builds a complete, valid Android Key attestation statement - credCert issued by a test CA for a fresh credential key, with a KeyDescription whose attestationChallenge is the client data hash
///     and whose teeEnforced authorization list says KM_PURPOSE_SIGN and KM_ORIGIN_GENERATED, and 'sig' over the authenticator data and the client data hash -
///     with one switch per rule of WebAuthn L3 §8.4, so that a test can break exactly one rule.
///     Everything is generated at a fixed point in time (<see cref="AttestationStatementVerifierTestHelpers.Now" />), so the tests do not depend on the current date.
/// </summary>
internal sealed class AndroidKeyAttestationBuilder
{
    public const string KeyDescriptionOid = "1.3.6.1.4.1.11129.2.1.17";
    public const int KeyPurposeSign = 2;
    public const int KeyPurposeVerify = 3;
    public const int KeyOriginGenerated = 0;
    public const int KeyOriginImported = 2;
    public const int SecurityLevelSoftware = 0;
    public const int SecurityLevelTrustedEnvironment = 1;
    public const int SecurityLevelStrongBox = 2;

    // the aaguid of the Android Authenticator
    public static readonly Guid Aaguid = Guid.Parse("b93fd961-f2e6-462f-b122-82002247de78");

    // the root certificate that the FIDO Metadata Service stand-in of TestAndroidKeyAttestationStatementVerifier lists for Aaguid by default (a "basic_full" entry);
    // the verifier doesn't build the chain (the attestation trust path validator does), so it is not the issuer of credCert
    public static readonly byte[] MetadataRoot = CreateMetadataRoot();

    // ---------- authenticator data and signature

    // the aaguid in the authenticator data, chosen by the client (nothing in the attestation statement attests it)
    public Guid AuthenticatorDataAaguid { get; init; } = Aaguid;

    public bool MismatchedCoseKey { get; init; }

    public bool CorruptSignature { get; init; }

    public bool EmptyX5C { get; init; }

    // ---------- the android key attestation certificate extension data (KeyDescription)

    public bool OmitKeyDescription { get; init; }

    public bool DuplicateKeyDescription { get; init; }

    // the encoded extension value, instead of the KeyDescription built from the properties below
    public byte[]? KeyDescriptionValue { get; init; }

    public bool WrongAttestationChallenge { get; init; }

    public int AttestationSecurityLevel { get; init; } = SecurityLevelTrustedEnvironment;

    public int KeyMintSecurityLevel { get; init; } = SecurityLevelTrustedEnvironment;

    // the fields of the authorization lists (null - the field is absent)
    public int[]? TeeEnforcedPurpose { get; init; } = { KeyPurposeSign };

    public int? TeeEnforcedOrigin { get; init; } = KeyOriginGenerated;

    public bool TeeEnforcedAllApplications { get; init; }

    public int[]? SoftwareEnforcedPurpose { get; init; }

    public int? SoftwareEnforcedOrigin { get; init; }

    public bool SoftwareEnforcedAllApplications { get; init; }

    // encoded fields appended to the authorization lists as they are (a malformed or a repeated field)
    public byte[][] TeeEnforcedExtraFields { get; init; } = Array.Empty<byte[]>();

    public byte[][] SoftwareEnforcedExtraFields { get; init; } = Array.Empty<byte[]>();

    public AndroidKeyAttestation Build()
    {
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var authenticatorData = CreateAuthenticatorData(AuthenticatorDataAaguid, ToCoseEc2Key(MismatchedCoseKey ? otherKey : credentialKey));
        var clientDataHash = CreateClientDataHash();

        var extensions = new List<X509Extension>();
        if (!OmitKeyDescription)
        {
            var keyDescription = KeyDescriptionValue ?? BuildKeyDescription(clientDataHash);
            extensions.Add(new(KeyDescriptionOid, keyDescription, false));
            if (DuplicateKeyDescription)
            {
                extensions.Add(new(KeyDescriptionOid, keyDescription, false));
            }
        }

        var credCert = BuildCertificate(issuerKey, "CN=WebAuthn.Net Android Key Test CA", "CN=Android Keystore Key", credentialKey.ExportSubjectPublicKeyInfo(), extensions);
        var signature = credentialKey.SignData(Concat(authenticatorData.Raw, clientDataHash), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        if (CorruptSignature)
        {
            signature[^1] ^= 0xFF;
        }

        var attStmt = new AndroidKeyAttestationStatement(CoseAlgorithm.ES256, signature, EmptyX5C ? Array.Empty<byte[]>() : new[] { credCert });
        return new(attStmt, authenticatorData, clientDataHash);
    }

    private byte[] BuildKeyDescription(byte[] clientDataHash)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(300); // attestationVersion: KeyMint 3.0
            writer.WriteEncodedValue(new byte[] { 0x0A, 0x01, (byte) AttestationSecurityLevel }); // attestationSecurityLevel: ENUMERATED
            writer.WriteInteger(300); // keyMintVersion
            writer.WriteEncodedValue(new byte[] { 0x0A, 0x01, (byte) KeyMintSecurityLevel }); // keyMintSecurityLevel: ENUMERATED
            writer.WriteOctetString(WrongAttestationChallenge ? new byte[clientDataHash.Length] : clientDataHash);
            writer.WriteOctetString(Array.Empty<byte>()); // uniqueId
            WriteAuthorizationList(writer, SoftwareEnforcedPurpose, SoftwareEnforcedAllApplications, SoftwareEnforcedOrigin, SoftwareEnforcedExtraFields);
            WriteAuthorizationList(writer, TeeEnforcedPurpose, TeeEnforcedAllApplications, TeeEnforcedOrigin, TeeEnforcedExtraFields);
        }

        return writer.Encode();
    }

    // AuthorizationList ::= SEQUENCE { purpose [1] EXPLICIT SET OF INTEGER OPTIONAL, ..., allApplications [600] EXPLICIT NULL OPTIONAL, ..., origin [702] EXPLICIT INTEGER OPTIONAL, ... }
    private static void WriteAuthorizationList(AsnWriter writer, int[]? purpose, bool allApplications, int? origin, byte[][] extraFields)
    {
        using (writer.PushSequence())
        {
            if (purpose is not null)
            {
                using (writer.PushSequence(new(TagClass.ContextSpecific, 1, true)))
                using (writer.PushSetOf())
                {
                    foreach (var value in purpose)
                    {
                        writer.WriteInteger(value);
                    }
                }
            }

            if (allApplications)
            {
                using (writer.PushSequence(new(TagClass.ContextSpecific, 600, true)))
                {
                    writer.WriteNull();
                }
            }

            if (origin.HasValue)
            {
                using (writer.PushSequence(new(TagClass.ContextSpecific, 702, true)))
                {
                    writer.WriteInteger(origin.Value);
                }
            }

            foreach (var field in extraFields)
            {
                writer.WriteEncodedValue(field);
            }
        }
    }

    private static byte[] CreateMetadataRoot()
    {
        using var certificate = CreateSelfSigned("CN=WebAuthn.Net Android Key Test Metadata Root", true);
        return certificate.RawData;
    }
}

internal sealed record AndroidKeyAttestation(AndroidKeyAttestationStatement AttStmt, AttestedAuthenticatorData AuthenticatorData, byte[] ClientDataHash);

/// <summary>
///     <see cref="DefaultAndroidKeyAttestationStatementVerifier{TContext}" /> with the default signature verifier and ASN.1 deserializer, a fixed clock, a recording logger,
///     the options of the library with the given AcceptKeysOnlyFromTrustedExecutionEnvironment, and a FIDO Metadata Service stand-in that answers only what it is given
///     (by default a "basic_full" entry for <see cref="AndroidKeyAttestationBuilder.Aaguid" /> that lists <see cref="AndroidKeyAttestationBuilder.MetadataRoot" />, and nothing for any other aaguid).
/// </summary>
internal sealed class TestAndroidKeyAttestationStatementVerifier : DefaultAndroidKeyAttestationStatementVerifier<FakeWebAuthnContext>
{
    public TestAndroidKeyAttestationStatementVerifier()
        : this(DefaultFidoMetadataSearchService(), true)
    {
    }

    public TestAndroidKeyAttestationStatementVerifier(bool acceptKeysOnlyFromTrustedExecutionEnvironment)
        : this(DefaultFidoMetadataSearchService(), acceptKeysOnlyFromTrustedExecutionEnvironment)
    {
    }

    public TestAndroidKeyAttestationStatementVerifier(RecordingFidoMetadataSearchService fidoMetadataSearchService)
        : this(fidoMetadataSearchService, true)
    {
    }

    public TestAndroidKeyAttestationStatementVerifier(RecordingFidoMetadataSearchService fidoMetadataSearchService, bool acceptKeysOnlyFromTrustedExecutionEnvironment)
        : this(new OptionsMonitorStub(acceptKeysOnlyFromTrustedExecutionEnvironment), fidoMetadataSearchService, new FakeLogger<DefaultAndroidKeyAttestationStatementVerifier<FakeWebAuthnContext>>())
    {
    }

    private TestAndroidKeyAttestationStatementVerifier(
        OptionsMonitorStub options,
        RecordingFidoMetadataSearchService fidoMetadataSearchService,
        FakeLogger<DefaultAndroidKeyAttestationStatementVerifier<FakeWebAuthnContext>> logger)
        : base(
            options,
            new FakeTimeProvider(Now),
            new DefaultDigitalSignatureVerifier(),
            new DefaultAsn1Deserializer(NullLogger<DefaultAsn1Deserializer>.Instance),
            fidoMetadataSearchService,
            logger)
    {
        FakeFidoMetadataSearchService = fidoMetadataSearchService;
        FakeLogger = logger;
    }

    public RecordingFidoMetadataSearchService FakeFidoMetadataSearchService { get; }

    public FakeLogger<DefaultAndroidKeyAttestationStatementVerifier<FakeWebAuthnContext>> FakeLogger { get; }

    public static RecordingFidoMetadataSearchService DefaultFidoMetadataSearchService()
    {
        return new RecordingFidoMetadataSearchService()
            .WithAaguid(AndroidKeyAttestationBuilder.Aaguid, RecordingFidoMetadataSearchService.Metadata(AndroidKeyAttestationBuilder.MetadataRoot, AuthenticatorAttestationType.ATTESTATION_BASIC_FULL));
    }

    public async Task<Result<VerifiedAttestationStatement>> VerifyAsync(AndroidKeyAttestation attestation)
    {
        ArgumentNullException.ThrowIfNull(attestation);
        await using var context = CreateContext();
        return await VerifyAsync(context, attestation.AttStmt, attestation.AuthenticatorData, attestation.ClientDataHash, CancellationToken.None);
    }

    private sealed class OptionsMonitorStub : IOptionsMonitor<WebAuthnOptions>
    {
        public OptionsMonitorStub(bool acceptKeysOnlyFromTrustedExecutionEnvironment)
        {
            CurrentValue.AttestationStatements.AndroidKey.AcceptKeysOnlyFromTrustedExecutionEnvironment = acceptKeysOnlyFromTrustedExecutionEnvironment;
        }

        public WebAuthnOptions CurrentValue { get; } = new();

        public WebAuthnOptions Get(string? name)
        {
            return CurrentValue;
        }

        public IDisposable? OnChange(Action<WebAuthnOptions, string?> listener)
        {
            return null;
        }
    }
}
