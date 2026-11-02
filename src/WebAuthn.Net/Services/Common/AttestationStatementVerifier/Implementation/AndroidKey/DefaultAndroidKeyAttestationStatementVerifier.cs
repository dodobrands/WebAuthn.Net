using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.AndroidKey;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.Cryptography.Sign;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService.Enums;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidKey;

/// <summary>
///     Default implementation of <see cref="IAndroidKeyAttestationStatementVerifier{TContext}" />.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public class DefaultAndroidKeyAttestationStatementVerifier<TContext>
    : IAndroidKeyAttestationStatementVerifier<TContext> where TContext : class, IWebAuthnContext
{
    // https://www.w3.org/TR/webauthn-3/#sctn-key-attstn-cert-requirements
    // the android key attestation certificate extension data (KeyDescription)
    private const string KeyDescriptionOid = "1.3.6.1.4.1.11129.2.1.17";

    // https://source.android.com/docs/security/features/keystore/attestation#schema
    // AuthorizationList ::= SEQUENCE { purpose [1] EXPLICIT SET OF INTEGER OPTIONAL, ..., allApplications [600] EXPLICIT NULL OPTIONAL, ..., origin [702] EXPLICIT INTEGER OPTIONAL, ... }
    private const int PurposeTag = 1;
    private const int AllApplicationsTag = 600;
    private const int OriginTag = 702;

    // SecurityLevel ::= ENUMERATED { Software (0), TrustedEnvironment (1), StrongBox (2) }
    private const int SecurityLevelTrustedEnvironment = 1;
    private const int SecurityLevelStrongBox = 2;

    // the values of a field are listed in a log message up to this number (the field comes from the client, see FormatIntegers)
    private const int MaxLoggedValues = 8;

    // https://android.googlesource.com/platform/hardware/libhardware/+/refs/heads/main/include_all/hardware/keymaster_defs.h
    // KM_PURPOSE_SIGN (Usable with RSA, EC and HMAC keys.) and KM_ORIGIN_GENERATED (Generated in keymaster. Should not exist outside the TEE.);
    // KeyMint keeps the values (KeyPurpose.SIGN = 2, KeyOrigin.GENERATED = 0)
    private static readonly BigInteger KeyPurposeSign = new(2);
    private static readonly BigInteger KeyOriginGenerated = BigInteger.Zero;

    /// <summary>
    ///     Constructs <see cref="DefaultAndroidKeyAttestationStatementVerifier{TContext}" />.
    /// </summary>
    /// <param name="options">Accessor for getting the current value of global options.</param>
    /// <param name="timeProvider">Current time provider.</param>
    /// <param name="signatureVerifier">Digital signature verifier.</param>
    /// <param name="asn1Deserializer">ASN.1 format deserializer.</param>
    /// <param name="fidoMetadataSearchService">A service for searching in the data provided by the FIDO Metadata Service.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultAndroidKeyAttestationStatementVerifier(
        IOptionsMonitor<WebAuthnOptions> options,
        ITimeProvider timeProvider,
        IDigitalSignatureVerifier signatureVerifier,
        IAsn1Deserializer asn1Deserializer,
        IFidoMetadataSearchService<TContext> fidoMetadataSearchService,
        ILogger<DefaultAndroidKeyAttestationStatementVerifier<TContext>> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        ArgumentNullException.ThrowIfNull(asn1Deserializer);
        ArgumentNullException.ThrowIfNull(fidoMetadataSearchService);
        ArgumentNullException.ThrowIfNull(logger);
        Options = options;
        TimeProvider = timeProvider;
        SignatureVerifier = signatureVerifier;
        Asn1Deserializer = asn1Deserializer;
        FidoMetadataSearchService = fidoMetadataSearchService;
        Logger = logger;
    }

    /// <summary>
    ///     Accessor for getting the current value of global options.
    /// </summary>
    protected IOptionsMonitor<WebAuthnOptions> Options { get; }

    /// <summary>
    ///     Current time provider.
    /// </summary>
    protected ITimeProvider TimeProvider { get; }

    /// <summary>
    ///     Digital signature verifier.
    /// </summary>
    protected IDigitalSignatureVerifier SignatureVerifier { get; }

    /// <summary>
    ///     ASN.1 format deserializer.
    /// </summary>
    protected IAsn1Deserializer Asn1Deserializer { get; }

    /// <summary>
    ///     A service for searching in the data provided by the FIDO Metadata Service.
    /// </summary>
    protected IFidoMetadataSearchService<TContext> FidoMetadataSearchService { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultAndroidKeyAttestationStatementVerifier<TContext>> Logger { get; }

    /// <inheritdoc />
    public virtual async Task<Result<VerifiedAttestationStatement>> VerifyAsync(
        TContext context,
        AndroidKeyAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken)
    {
        // https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation
        // Android Key Attestation Statement Format

        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(authenticatorData);
        // 1) Verify that 'attStmt' is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // Performed by the attestation statement decoder (DefaultAndroidKeyAttestationStatementDecoder) that produced 'attStmt'.
        // The syntax also requires at least one certificate (credCert) in 'x5c'.
        if (attStmt.X5C.Length == 0)
        {
            Logger.AndroidKeyX5CEmpty();
            return Result<VerifiedAttestationStatement>.Fail();
        }

        // 2) Verify that 'sig' is a valid signature over the concatenation of 'authenticatorData' and 'clientDataHash'
        // using the public key in the first certificate in 'x5c' with the algorithm specified in 'alg'.
        var certificatesToDispose = new List<X509Certificate2>(attStmt.X5C.Length);
        try
        {
            var currentDate = TimeProvider.GetPreciseUtcDateTime();
            var x5CCertificates = new List<X509Certificate2>(attStmt.X5C.Length);
            foreach (var x5CBytes in attStmt.X5C)
            {
                if (!X509CertificateInMemoryLoader.TryLoad(x5CBytes, out var x5CCert))
                {
                    x5CCert?.Dispose();
                    Logger.AndroidKeyX5CCertificateInvalid();
                    return Result<VerifiedAttestationStatement>.Fail();
                }

                certificatesToDispose.Add(x5CCert);
                x5CCertificates.Add(x5CCert);
                if (currentDate < x5CCert.NotBefore || currentDate > x5CCert.NotAfter)
                {
                    Logger.AndroidKeyX5CCertificateNotValidNow();
                    return Result<VerifiedAttestationStatement>.Fail();
                }
            }

            // 'credCert' must be the first element in the array.
            var credCert = x5CCertificates.First();
            var dataToVerify = Concat(authenticatorData.Raw, clientDataHash);
            if (!SignatureVerifier.IsValidCertificateSign(credCert, attStmt.Alg, dataToVerify, attStmt.Sig))
            {
                Logger.AndroidKeySignatureInvalid();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 3) Verify that the public key in the first certificate in 'x5c'
            // matches the 'credentialPublicKey' in the 'attestedCredentialData' in 'authenticatorData'.
            if (!authenticatorData.AttestedCredentialData.CredentialPublicKey.Matches(credCert))
            {
                Logger.AndroidKeyCredentialPublicKeyMismatch();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 4) Verify that the 'attestationChallenge' field in the attestation certificate extension data
            // is identical to 'clientDataHash'.
            if (!TryGetKeyDescriptionAttestationExtension(credCert, out var keyDescription))
            {
                Logger.AndroidKeyKeyDescriptionInvalid();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (!TryGetAttestationChallenge(keyDescription, out var attestationChallenge))
            {
                Logger.AndroidKeyKeyDescriptionInvalid();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (!attestationChallenge.AsSpan().SequenceEqual(clientDataHash.AsSpan()))
            {
                Logger.AndroidKeyAttestationChallengeMismatch();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 5) Verify the following using the appropriate authorization list
            // from the attestation certificate extension data:
            // (VerifyAuthorizationLists logs the requirement that is not met)
            if (!VerifyAuthorizationLists(keyDescription))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 6) If successful, return implementation-specific values
            // representing attestation type Basic and attestation trust path 'x5c'.
            // The aaguid in 'authenticatorData' is chosen by the client: the attestation certificate extension data describes the key, not the authenticator model,
            // so the attestation statement doesn't attest the aaguid. The acceptable trust anchors are therefore the root certificates of the FIDO Metadata Service entry
            // for that aaguid (GetAcceptableTrustAnchorsAsync logs why no trust anchor is acceptable).
            var acceptableTrustAnchorsResult = await GetAcceptableTrustAnchorsAsync(
                context,
                credCert,
                authenticatorData,
                cancellationToken);
            if (acceptableTrustAnchorsResult.HasError)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            var result = new VerifiedAttestationStatement(
                AttestationStatementFormat.AndroidKey,
                AttestationType.Basic,
                attStmt.X5C,
                acceptableTrustAnchorsResult.Ok);
            return Result<VerifiedAttestationStatement>.Success(result);
        }
        finally
        {
            foreach (var certificateToDispose in certificatesToDispose)
            {
                certificateToDispose.Dispose();
            }
        }
    }

    /// <summary>
    ///     Returns the acceptable trust anchors (root X509v3 certificates) for the attestation trust path of the Android Key attestation statement.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         The aaguid in the authenticator data is chosen by the client: the authenticator data is signed with the credential private key, which the application that created it holds,
    ///         and the attestation certificate extension data describes that key, not the authenticator model. Therefore, the trust anchors are taken from the FIDO Metadata Service entry for that aaguid
    ///         (<a href="https://www.w3.org/TR/webauthn-3/#reg-ceremony-attestation-trust-anchors">§7.1 step 23</a>), which must list the "basic_full" attestation type:
    ///         the attestation certificate then has to chain up to a root certificate that the FIDO Metadata Service lists for that authenticator model.
    ///     </para>
    ///     <para>
    ///         The attestation statement is rejected when there is no usable entry for the aaguid (its aaguid is not attested), when the entry doesn't allow to trust the authenticator (for example, it is REVOKED)
    ///         and when no metadata is available.
    ///     </para>
    /// </remarks>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="credCert">X509v3 certificate containing extension data of the Android Key attestation statement</param>
    /// <param name="authenticatorData"><a href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">Authenticator data</a> that has <a href="https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata">attestedCredentialData</a>.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>If the trust anchors were determined, the result contains a non-empty <see cref="UniqueByteArraysCollection" />, otherwise the result indicates that no trust anchor is acceptable.</returns>
    protected virtual async Task<Result<UniqueByteArraysCollection>> GetAcceptableTrustAnchorsAsync(
        TContext context,
        X509Certificate2 credCert,
        AttestedAuthenticatorData authenticatorData,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authenticatorData);
        cancellationToken.ThrowIfCancellationRequested();
        var aaguid = authenticatorData.AttestedCredentialData.Aaguid;
        var metadataResult = await FidoMetadataSearchService.FindMetadataByAaguidAsync(context, aaguid, cancellationToken);
        if (metadataResult.HasError)
        {
            switch (metadataResult.Error)
            {
                case FidoMetadataSearchError.NotFound:
                    Logger.AndroidKeyMetadataNotFound(aaguid);
                    break;
                case FidoMetadataSearchError.MetadataNotAvailable:
                    // The search service has already logged and counted the lookup without metadata.
                    Logger.AndroidKeyMetadataNotAvailable(aaguid);
                    break;
                default:
                    // The entry doesn't allow to trust the authenticator (for example, it is REVOKED). The search service has already logged and counted it.
                    Logger.AndroidKeyMetadataUntrusted(aaguid);
                    break;
            }

            return Result<UniqueByteArraysCollection>.Fail();
        }

        var metadata = metadataResult.Ok;
        // §8.4: an Android Key attestation statement conveys a Basic attestation, so an authenticator whose metadata doesn't list "basic_full" can't produce a valid one.
        if (!metadata.AttestationTypes.Contains(AuthenticatorAttestationType.ATTESTATION_BASIC_FULL))
        {
            Logger.AndroidKeyMetadataAttestationTypeNotSupported(aaguid);
            return Result<UniqueByteArraysCollection>.Fail();
        }

        // ReSharper disable once ConditionalAccessQualifierIsNonNullableAccordingToAPIContract
        if (!(metadata.RootCertificates?.Length > 0))
        {
            Logger.AndroidKeyMetadataNotFound(aaguid);
            return Result<UniqueByteArraysCollection>.Fail();
        }

        return Result<UniqueByteArraysCollection>.Success(new(metadata.RootCertificates));
    }

    /// <summary>
    ///     Verifies that the appropriate authorization lists contain correct data.
    /// </summary>
    /// <param name="keyDescription">The KeyDescription containing AuthorizationLists.</param>
    /// <returns>If <paramref name="keyDescription" /> contains correct data in its AuthorizationLists - <see langword="true" />, otherwise - <see langword="false" />.</returns>
    protected virtual bool VerifyAuthorizationLists(Asn1Sequence keyDescription)
    {
        ArgumentNullException.ThrowIfNull(keyDescription);
        // https://source.android.com/docs/security/features/keystore/attestation#schema
        // KeyDescription ::= SEQUENCE {
        //   attestationVersion         INTEGER, # Keymaster 2.0 - 4.1: 1, 2, 3, 4; KeyMint 1.0 - 5.0: 100, 200, 300, 400, 500
        //   attestationSecurityLevel   SecurityLevel,
        //   keyMintVersion             INTEGER, # keymasterVersion before KeyMint
        //   keyMintSecurityLevel       SecurityLevel, # keymasterSecurityLevel before KeyMint
        //   attestationChallenge       OCTET_STRING,
        //   uniqueId                   OCTET_STRING,
        //   softwareEnforced           AuthorizationList,
        //   hardwareEnforced           AuthorizationList, # teeEnforced before KeyMint, the name WebAuthn uses
        // }
        //
        // SecurityLevel ::= ENUMERATED { Software (0), TrustedEnvironment (1), StrongBox (2) }
        //
        // AuthorizationList ::= SEQUENCE {
        //   purpose                     [1] EXPLICIT SET OF INTEGER OPTIONAL,
        //   ...
        //   allApplications             [600] EXPLICIT NULL OPTIONAL, # only in the schemas of attestation versions 1 and 2
        //   ...
        //   origin                      [702] EXPLICIT INTEGER OPTIONAL,
        //   ...
        // }
        // The positions of the fields are the same in every version of the schema.
        var keyDescriptionElements = keyDescription.Items;
        if (keyDescriptionElements.Length < 8
            || keyDescriptionElements[6] is not Asn1Sequence softwareEnforced
            || keyDescriptionElements[7] is not Asn1Sequence teeEnforced)
        {
            Logger.AndroidKeyKeyDescriptionInvalid();
            return false;
        }

        // 1) The AuthorizationList.allApplications field is not present
        // on either authorization list (softwareEnforced nor teeEnforced),
        // since PublicKeyCredential MUST be scoped to the RP ID.
        if (IsAllApplicationsPresent(softwareEnforced) || IsAllApplicationsPresent(teeEnforced))
        {
            Logger.AndroidKeyAllApplicationsPresent();
            return false;
        }

        // The fields are read from both authorization lists, so that a malformed or repeated field is rejected wherever it is,
        // instead of being taken for an absent one (which the union of the lists would then look up in the other list).
        if (!TryGetPurposeFromAuthorizationList(softwareEnforced, out var softwareEnforcedPurpose)
            || !TryGetPurposeFromAuthorizationList(teeEnforced, out var teeEnforcedPurpose))
        {
            Logger.AndroidKeyAuthorizationListFieldInvalid("purpose");
            return false;
        }

        if (!TryGetOriginFromAuthorizationList(softwareEnforced, out var softwareEnforcedOrigin)
            || !TryGetOriginFromAuthorizationList(teeEnforced, out var teeEnforcedOrigin))
        {
            Logger.AndroidKeyAuthorizationListFieldInvalid("origin");
            return false;
        }

        // A field is enforced either by the secure environment or by the software, so it is never in both authorization lists:
        // a KeyDescription that has it in both is ambiguous.
        if (softwareEnforcedPurpose is not null && teeEnforcedPurpose is not null)
        {
            Logger.AndroidKeyAuthorizationListFieldInBothLists("purpose");
            return false;
        }

        if (softwareEnforcedOrigin.HasValue && teeEnforcedOrigin.HasValue)
        {
            Logger.AndroidKeyAuthorizationListFieldInBothLists("origin");
            return false;
        }

        // 2) For the following, use only the teeEnforced authorization list
        // if the RP wants to accept only keys from a trusted execution environment,
        // otherwise use the union of 'teeEnforced' and 'softwareEnforced'.
        //  - The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED.
        //  - The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN.
        var acceptKeysOnlyFromTrustedExecutionEnvironment = Options.CurrentValue.AttestationStatements.AndroidKey.AcceptKeysOnlyFromTrustedExecutionEnvironment;
        // A key from a trusted execution environment also has to be described as such by the security levels of the KeyDescription
        // (Google's verification guidance requires attestationSecurityLevel to be TrustedEnvironment or StrongBox), not only by the authorization list its fields are in.
        if (acceptKeysOnlyFromTrustedExecutionEnvironment && !IsKeyInSecureEnvironment(keyDescription))
        {
            Logger.AndroidKeyNotInSecureEnvironment();
            return false;
        }

        var purpose = acceptKeysOnlyFromTrustedExecutionEnvironment ? teeEnforcedPurpose : teeEnforcedPurpose ?? softwareEnforcedPurpose;
        var origin = acceptKeysOnlyFromTrustedExecutionEnvironment ? teeEnforcedOrigin : teeEnforcedOrigin ?? softwareEnforcedOrigin;
        var authorizationLists = acceptKeysOnlyFromTrustedExecutionEnvironment ? "teeEnforced" : "teeEnforced or softwareEnforced";
        if (purpose is null)
        {
            Logger.AndroidKeyAuthorizationListFieldMissing("purpose", authorizationLists);
            return false;
        }

        if (!origin.HasValue)
        {
            Logger.AndroidKeyAuthorizationListFieldMissing("origin", authorizationLists);
            return false;
        }

        if (!IsPurposeSign(purpose))
        {
            Logger.AndroidKeyPurposeNotSign(FormatIntegers(purpose), authorizationLists);
            return false;
        }

        if (!IsOriginGenerated(origin.Value))
        {
            Logger.AndroidKeyOriginNotGenerated(FormatIntegers(new[] { origin.Value }), authorizationLists);
            return false;
        }

        return true;
    }

    /// <summary>
    ///     Verifies that the KeyDescription describes a key that is held by a secure environment (a trusted execution environment or StrongBox) and was attested by one.
    ///     Used only when the relying party accepts only keys from a trusted execution environment.
    /// </summary>
    /// <param name="keyDescription">The KeyDescription.</param>
    /// <returns><see langword="true" /> if both attestationSecurityLevel and keyMintSecurityLevel are TrustedEnvironment or StrongBox, otherwise - <see langword="false" />.</returns>
    protected virtual bool IsKeyInSecureEnvironment(Asn1Sequence keyDescription)
    {
        ArgumentNullException.ThrowIfNull(keyDescription);
        // https://developer.android.com/privacy-and-security/security-key-attestation (Verify hardware-backed key pairs with key attestation):
        // attestationSecurityLevel must be TrustedEnvironment or StrongBox. keyMintSecurityLevel (keymasterSecurityLevel) is the security level of the environment that holds the key.
        // SecurityLevel ::= ENUMERATED { Software (0), TrustedEnvironment (1), StrongBox (2) }
        var keyDescriptionElements = keyDescription.Items;
        return keyDescriptionElements.Length >= 4
               && TryReadSecurityLevel(keyDescriptionElements[1], out var attestationSecurityLevel)
               && TryReadSecurityLevel(keyDescriptionElements[3], out var keyMintSecurityLevel)
               && attestationSecurityLevel is SecurityLevelTrustedEnvironment or SecurityLevelStrongBox
               && keyMintSecurityLevel is SecurityLevelTrustedEnvironment or SecurityLevelStrongBox;
    }

    /// <summary>
    ///     Verifies that the value of the "purpose" field of the AuthorizationList is equal to KM_PURPOSE_SIGN.
    /// </summary>
    /// <param name="purpose">The values of the "purpose" field (SET OF INTEGER) obtained from the AuthorizationList.</param>
    /// <returns><see langword="true" /> if the purpose of the key is only signing (every value of the field is KM_PURPOSE_SIGN), otherwise - <see langword="false" />.</returns>
    protected virtual bool IsPurposeSign(BigInteger[] purpose)
    {
        ArgumentNullException.ThrowIfNull(purpose);
        // AuthorizationList.purpose == KM_PURPOSE_SIGN: the field is a SET OF INTEGER, so the key must have no other purpose than signing.
        return purpose.Length > 0 && purpose.All(static x => x == KeyPurposeSign);
    }

    /// <summary>
    ///     Verifies that the value of the "origin" field of the AuthorizationList is equal to KM_ORIGIN_GENERATED.
    /// </summary>
    /// <param name="origin">The value of the "origin" field obtained from the AuthorizationList.</param>
    /// <returns><see langword="true" /> if the key was generated in the keystore, otherwise - <see langword="false" />.</returns>
    protected virtual bool IsOriginGenerated(BigInteger origin)
    {
        return origin == KeyOriginGenerated;
    }

    /// <summary>
    ///     Extracts the values of the "purpose" field from the AuthorizationList.
    /// </summary>
    /// <param name="authorizationList">The AuthorizationList from which the "purpose" needs to be extracted.</param>
    /// <param name="purpose">Output parameter. The values of the "purpose" field (SET OF INTEGER) if the field is present, or <see langword="null" /> if it is absent.</param>
    /// <returns><see langword="false" /> if the field is malformed (not a DER-encoded [1] EXPLICIT SET OF INTEGER) or occurs more than once, otherwise - <see langword="true" />.</returns>
    protected virtual bool TryGetPurposeFromAuthorizationList(Asn1Sequence authorizationList, out BigInteger[]? purpose)
    {
        ArgumentNullException.ThrowIfNull(authorizationList);
        purpose = null;
        // purpose  [1] EXPLICIT SET OF INTEGER OPTIONAL
        if (!TryFindAuthorizationListField(authorizationList, PurposeTag, out var field))
        {
            return false;
        }

        if (field is null)
        {
            return true;
        }

        // The field comes from a certificate whose chain hasn't been validated yet, so any encoding error is a malformed field, not an exception.
        try
        {
            var reader = new AsnReader(field.RawValue, AsnEncodingRules.DER);
            var fieldReader = reader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, PurposeTag, true));
            reader.ThrowIfNotEmpty();
            var setReader = fieldReader.ReadSetOf();
            fieldReader.ThrowIfNotEmpty();
            var values = new List<BigInteger>();
            while (setReader.HasData)
            {
                values.Add(setReader.ReadInteger());
            }

            purpose = values.ToArray();
            return true;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    /// <summary>
    ///     Extracts the value of the "origin" field from the AuthorizationList.
    /// </summary>
    /// <param name="authorizationList">The AuthorizationList from which the "origin" needs to be extracted.</param>
    /// <param name="origin">Output parameter. The value of the "origin" field if the field is present, or <see langword="null" /> if it is absent.</param>
    /// <returns><see langword="false" /> if the field is malformed (not a DER-encoded [702] EXPLICIT INTEGER) or occurs more than once, otherwise - <see langword="true" />.</returns>
    protected virtual bool TryGetOriginFromAuthorizationList(Asn1Sequence authorizationList, out BigInteger? origin)
    {
        ArgumentNullException.ThrowIfNull(authorizationList);
        origin = null;
        // origin  [702] EXPLICIT INTEGER OPTIONAL
        if (!TryFindAuthorizationListField(authorizationList, OriginTag, out var field))
        {
            return false;
        }

        if (field is null)
        {
            return true;
        }

        // The field comes from a certificate whose chain hasn't been validated yet, so any encoding error is a malformed field, not an exception.
        try
        {
            var reader = new AsnReader(field.RawValue, AsnEncodingRules.DER);
            var fieldReader = reader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, OriginTag, true));
            reader.ThrowIfNotEmpty();
            var value = fieldReader.ReadInteger();
            fieldReader.ThrowIfNotEmpty();
            origin = value;
            return true;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    /// <summary>
    ///     Verifies the presence of the "allApplications" tag in the AuthorizationList.
    /// </summary>
    /// <param name="authorizationList">The AuthorizationList to be verified.</param>
    /// <returns>If the <paramref name="authorizationList" /> contains the "allApplications" tag - <see langword="true" />, otherwise - <see langword="false" />.</returns>
    protected virtual bool IsAllApplicationsPresent(Asn1Sequence authorizationList)
    {
        ArgumentNullException.ThrowIfNull(authorizationList);
        foreach (var element in authorizationList.Items)
        {
            if (element.Tag is { TagClass: TagClass.ContextSpecific, TagValue: AllApplicationsTag })
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    ///     Extracts the "attestationChallenge" value from KeyDescription.
    /// </summary>
    /// <param name="keyDescription">The KeyDescription from which the "attestationChallenge" needs to be extracted.</param>
    /// <param name="attestationChallenge">Output parameter. If a valid "attestationChallenge" is present in the <paramref name="keyDescription" />, it will return a byte array, otherwise - <see langword="null" />.</param>
    /// <returns><see langword="true" /> if the <paramref name="keyDescription" /> contains a valid "attestationChallenge", otherwise - <see langword="false" />.</returns>
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool TryGetAttestationChallenge(Asn1Sequence keyDescription, [NotNullWhen(true)] out byte[]? attestationChallenge)
    {
        if (keyDescription is null)
        {
            attestationChallenge = null;
            return false;
        }

        var keyDescriptionElements = keyDescription.Items;
        if (keyDescriptionElements.Length < 5)
        {
            attestationChallenge = null;
            return false;
        }

        // https://source.android.com/docs/security/features/keystore/attestation#schema
        // KeyDescription ::= SEQUENCE {
        //   attestationVersion         INTEGER,
        //   attestationSecurityLevel   SecurityLevel,
        //   keyMintVersion             INTEGER,
        //   keyMintSecurityLevel       SecurityLevel,
        //   attestationChallenge       OCTET_STRING,
        //   ...
        // }
        // attestationChallenge has an offset of 4 from the start of the SEQUENCE in every version of the schema.
        if (keyDescriptionElements[4] is not Asn1OctetString attestationChallengeAsn1)
        {
            attestationChallenge = null;
            return false;
        }

        attestationChallenge = attestationChallengeAsn1.Value;
        return true;
    }

    /// <summary>
    ///     Extracts the KeyDescription extension from the X509v3 certificate.
    /// </summary>
    /// <param name="credCert">X509v3 certificate containing extension data of the Android Key attestation statement</param>
    /// <param name="keyDescription">Output parameter. If a valid "KeyDescription" is present in the <paramref name="credCert" />, it will return an <see cref="Asn1Sequence" />, otherwise - <see langword="null" />.</param>
    /// <returns><see langword="true" /> if the <paramref name="credCert" /> contains exactly one valid KeyDescription extension, otherwise - <see langword="false" />.</returns>
    protected virtual bool TryGetKeyDescriptionAttestationExtension(X509Certificate2 credCert, [NotNullWhen(true)] out Asn1Sequence? keyDescription)
    {
        ArgumentNullException.ThrowIfNull(credCert);
        // https://www.w3.org/TR/webauthn-3/#sctn-key-attstn-cert-requirements
        // "Android Key Attestation Statement Certificate Requirements"
        // Android Key Attestation attestation certificate's android key attestation certificate extension data
        // is identified by the OID 1.3.6.1.4.1.11129.2.1.17, and its schema is defined in the Android developer documentation.
        // RFC 5280 §4.2: "A certificate MUST NOT include more than one instance of a particular extension." Several instances would make the checks ambiguous.
        var extensions = credCert.Extensions.Where(static x => x.Oid?.Value is KeyDescriptionOid).ToArray();
        if (extensions.Length != 1)
        {
            keyDescription = null;
            return false;
        }

        var deserializeResult = Asn1Deserializer.Deserialize(extensions[0].RawData, AsnEncodingRules.DER);
        if (deserializeResult.HasError)
        {
            keyDescription = null;
            return false;
        }

        // https://source.android.com/docs/security/features/keystore/attestation#schema
        // KeyDescription ::= SEQUENCE {
        //   ...
        // }
        if (deserializeResult.Ok is not Asn1Sequence keyDescriptionAsn1)
        {
            keyDescription = null;
            return false;
        }

        keyDescription = keyDescriptionAsn1;
        return true;
    }

    /// <summary>
    ///     Concatenates two ReadOnlySpan of bytes into one array.
    /// </summary>
    /// <param name="a">First ReadOnlySpan of bytes.</param>
    /// <param name="b">Second ReadOnlySpan of bytes.</param>
    /// <returns>An array of bytes, filled with the content of the passed ReadOnlySpans.</returns>
    protected virtual byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }

    // Finds the element of the AuthorizationList with the context-specific tag: 'false' if it occurs more than once (a SEQUENCE has each field at most once),
    // otherwise 'true' with the element, or with null if the AuthorizationList doesn't have it.
    private static bool TryFindAuthorizationListField(Asn1Sequence authorizationList, int tagValue, out Asn1RawElement? field)
    {
        field = null;
        var fields = authorizationList.Items.Where(x => x.Tag.TagClass == TagClass.ContextSpecific && x.Tag.TagValue == tagValue).ToArray();
        if (fields.Length == 0)
        {
            return true;
        }

        // the deserializer reads every context-specific element as a raw element
        if (fields.Length > 1 || fields[0] is not Asn1RawElement rawElement)
        {
            return false;
        }

        field = rawElement;
        return true;
    }

    // Reads a SecurityLevel (ENUMERATED) of the KeyDescription. The deserializer reads an ENUMERATED as a raw element, whose value hasn't been validated yet.
    private static bool TryReadSecurityLevel(AbstractAsn1Element element, out int securityLevel)
    {
        securityLevel = default;
        if (element is not Asn1RawElement { Tag: { TagClass: TagClass.Universal, TagValue: (int) UniversalTagNumber.Enumerated } } rawElement)
        {
            return false;
        }

        try
        {
            // every SecurityLevel value fits in a single content octet
            var contents = AsnDecoder.ReadEnumeratedBytes(rawElement.RawValue, AsnEncodingRules.DER, out var bytesConsumed);
            if (bytesConsumed != rawElement.RawValue.Length || contents.Length != 1)
            {
                return false;
            }

            securityLevel = (sbyte) contents[0];
            return true;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    // The values of a field for a log message. The field comes from the client: at most MaxLoggedValues values are listed,
    // and a value outside the range of a 64-bit integer is not formatted (an INTEGER can be arbitrarily long).
    private static string FormatIntegers(BigInteger[] values)
    {
        var listed = values
            .Take(MaxLoggedValues)
            .Select(static x => x >= long.MinValue && x <= long.MaxValue ? ((long) x).ToString(CultureInfo.InvariantCulture) : "<out of range>");
        return string.Join(", ", listed) + (values.Length > MaxLoggedValues ? ", ..." : string.Empty);
    }
}

/// <summary>
///     Extension methods for logging the Android Key attestation statement verifier.
/// </summary>
public static partial class DefaultAndroidKeyAttestationStatementVerifierLoggingExtensions
{
    /// <summary>
    ///     The 'x5c' of the Android Key attestation statement is empty
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'x5c' of the Android Key attestation statement is empty")]
    public static partial void AndroidKeyX5CEmpty(this ILogger logger);

    /// <summary>
    ///     Failed to load a certificate from the 'x5c' of the Android Key attestation statement
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to load a certificate from the 'x5c' of the Android Key attestation statement")]
    public static partial void AndroidKeyX5CCertificateInvalid(this ILogger logger);

    /// <summary>
    ///     A certificate from the 'x5c' of the Android Key attestation statement is not valid at the current time
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "A certificate from the 'x5c' of the Android Key attestation statement is not valid at the current time")]
    public static partial void AndroidKeyX5CCertificateNotValidNow(this ILogger logger);

    /// <summary>
    ///     The 'sig' of the Android Key attestation statement is not a valid signature over the authenticator data and the client data hash made with credCert and 'alg'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'sig' of the Android Key attestation statement is not a valid signature over the authenticator data and the client data hash made with credCert and 'alg'")]
    public static partial void AndroidKeySignatureInvalid(this ILogger logger);

    /// <summary>
    ///     The public key of credCert of the Android Key attestation statement does not match the credential public key
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The public key of credCert of the Android Key attestation statement does not match the credential public key")]
    public static partial void AndroidKeyCredentialPublicKeyMismatch(this ILogger logger);

    /// <summary>
    ///     credCert of the Android Key attestation statement doesn't have exactly one valid android key attestation certificate extension (KeyDescription, OID 1.3.6.1.4.1.11129.2.1.17)
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "credCert of the Android Key attestation statement doesn't have exactly one valid android key attestation certificate extension (KeyDescription, OID 1.3.6.1.4.1.11129.2.1.17)")]
    public static partial void AndroidKeyKeyDescriptionInvalid(this ILogger logger);

    /// <summary>
    ///     The attestationChallenge of the KeyDescription of the Android Key attestation statement is not identical to the client data hash
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The attestationChallenge of the KeyDescription of the Android Key attestation statement is not identical to the client data hash")]
    public static partial void AndroidKeyAttestationChallengeMismatch(this ILogger logger);

    /// <summary>
    ///     An authorization list of the KeyDescription of the Android Key attestation statement has the allApplications field, but the credential must be scoped to the RP ID
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "An authorization list of the KeyDescription of the Android Key attestation statement has the allApplications field, but the credential must be scoped to the RP ID")]
    public static partial void AndroidKeyAllApplicationsPresent(this ILogger logger);

    /// <summary>
    ///     The '{Field}' field of an authorization list of the KeyDescription of the Android Key attestation statement is malformed or occurs more than once
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="field">The name of the AuthorizationList field.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The '{Field}' field of an authorization list of the KeyDescription of the Android Key attestation statement is malformed or occurs more than once")]
    public static partial void AndroidKeyAuthorizationListFieldInvalid(this ILogger logger, string field);

    /// <summary>
    ///     The '{Field}' field is in both authorization lists (softwareEnforced and teeEnforced) of the KeyDescription of the Android Key attestation statement
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="field">The name of the AuthorizationList field.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The '{Field}' field is in both authorization lists (softwareEnforced and teeEnforced) of the KeyDescription of the Android Key attestation statement")]
    public static partial void AndroidKeyAuthorizationListFieldInBothLists(this ILogger logger, string field);

    /// <summary>
    ///     The '{Field}' field is missing from the {AuthorizationLists} authorization list of the KeyDescription of the Android Key attestation statement
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="field">The name of the AuthorizationList field.</param>
    /// <param name="authorizationLists">The authorization lists that were searched for the field.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The '{Field}' field is missing from the {AuthorizationLists} authorization list of the KeyDescription of the Android Key attestation statement")]
    public static partial void AndroidKeyAuthorizationListFieldMissing(this ILogger logger, string field, string authorizationLists);

    /// <summary>
    ///     The purpose ({Purpose}) in the {AuthorizationLists} authorization list of the KeyDescription of the Android Key attestation statement is not KM_PURPOSE_SIGN (2) alone
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="purpose">The values of the purpose field (at most 8 of them).</param>
    /// <param name="authorizationLists">The authorization lists that were searched for the field.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The purpose ({Purpose}) in the {AuthorizationLists} authorization list of the KeyDescription of the Android Key attestation statement is not KM_PURPOSE_SIGN (2) alone")]
    public static partial void AndroidKeyPurposeNotSign(this ILogger logger, string purpose, string authorizationLists);

    /// <summary>
    ///     The origin ({Origin}) in the {AuthorizationLists} authorization list of the KeyDescription of the Android Key attestation statement is not KM_ORIGIN_GENERATED (0)
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="origin">The value of the origin field.</param>
    /// <param name="authorizationLists">The authorization lists that were searched for the field.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The origin ({Origin}) in the {AuthorizationLists} authorization list of the KeyDescription of the Android Key attestation statement is not KM_ORIGIN_GENERATED (0)")]
    public static partial void AndroidKeyOriginNotGenerated(this ILogger logger, string origin, string authorizationLists);

    /// <summary>
    ///     The attestationSecurityLevel or the keyMintSecurityLevel of the KeyDescription of the Android Key attestation statement is not TrustedEnvironment or StrongBox, but only keys from a trusted execution environment are accepted
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The attestationSecurityLevel or the keyMintSecurityLevel of the KeyDescription of the Android Key attestation statement is not TrustedEnvironment or StrongBox, but only keys from a trusted execution environment are accepted")]
    public static partial void AndroidKeyNotInSecureEnvironment(this ILogger logger);

    /// <summary>
    ///     The FIDO Metadata Service has no usable metadata for the aaguid {Aaguid} of the Android Key attestation statement, which doesn't attest the aaguid itself, so no trust anchor is acceptable
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The FIDO Metadata Service has no usable metadata for the aaguid {Aaguid} of the Android Key attestation statement, which doesn't attest the aaguid itself, so no trust anchor is acceptable")]
    public static partial void AndroidKeyMetadataNotFound(this ILogger logger, Guid aaguid);

    /// <summary>
    ///     No metadata from the FIDO Metadata Service is available to check the aaguid {Aaguid} of the Android Key attestation statement, so no trust anchor is acceptable
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "No metadata from the FIDO Metadata Service is available to check the aaguid {Aaguid} of the Android Key attestation statement, so no trust anchor is acceptable")]
    public static partial void AndroidKeyMetadataNotAvailable(this ILogger logger, Guid aaguid);

    /// <summary>
    ///     The FIDO Metadata Service entry for the aaguid {Aaguid} of the Android Key attestation statement doesn't allow to trust the authenticator, so no trust anchor is acceptable
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The FIDO Metadata Service entry for the aaguid {Aaguid} of the Android Key attestation statement doesn't allow to trust the authenticator, so no trust anchor is acceptable")]
    public static partial void AndroidKeyMetadataUntrusted(this ILogger logger, Guid aaguid);

    /// <summary>
    ///     The metadata of the aaguid {Aaguid} doesn't list the attestation type that an Android Key attestation statement conveys (basic_full), so no trust anchor is acceptable
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The metadata of the aaguid {Aaguid} doesn't list the attestation type that an Android Key attestation statement conveys (basic_full), so no trust anchor is acceptable")]
    public static partial void AndroidKeyMetadataAttestationTypeNotSupported(this ILogger logger, Guid aaguid);
}
