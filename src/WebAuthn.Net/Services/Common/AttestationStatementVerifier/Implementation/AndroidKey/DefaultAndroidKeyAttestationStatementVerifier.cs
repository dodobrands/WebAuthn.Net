using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.AndroidKey;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidKey.Constants;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.Cryptography.Sign;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidKey;

/// <summary>
///     Default implementation of <see cref="IAndroidKeyAttestationStatementVerifier{TContext}" />.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public class DefaultAndroidKeyAttestationStatementVerifier<TContext>
    : IAndroidKeyAttestationStatementVerifier<TContext> where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     Constructs <see cref="DefaultAndroidKeyAttestationStatementVerifier{TContext}" />.
    /// </summary>
    /// <param name="options">Accessor for getting the current value of global options.</param>
    /// <param name="timeProvider">Current time provider.</param>
    /// <param name="signatureVerifier">Digital signature verifier.</param>
    /// <param name="asn1Deserializer">ASN.1 format deserializer.</param>
    /// <param name="fidoMetadataSearchService">A service for searching in the data provided by the FIDO Metadata Service.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultAndroidKeyAttestationStatementVerifier(
        IOptionsMonitor<WebAuthnOptions> options,
        ITimeProvider timeProvider,
        IDigitalSignatureVerifier signatureVerifier,
        IAsn1Deserializer asn1Deserializer,
        IFidoMetadataSearchService<TContext> fidoMetadataSearchService)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        ArgumentNullException.ThrowIfNull(asn1Deserializer);
        ArgumentNullException.ThrowIfNull(fidoMetadataSearchService);
        Options = options;
        TimeProvider = timeProvider;
        SignatureVerifier = signatureVerifier;
        Asn1Deserializer = asn1Deserializer;
        FidoMetadataSearchService = fidoMetadataSearchService;
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

    /// <inheritdoc />
    public virtual async Task<Result<VerifiedAttestationStatement>> VerifyAsync(
        TContext context,
        AndroidKeyAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken)
    {
        // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-key-attestation
        // §8.4. Android Key Attestation Statement Format

        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(authenticatorData);
        // 1) Verify that 'attStmt' is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // 2) Verify that 'sig' is a valid signature over the concatenation of 'authenticatorData' and 'clientDataHash'
        // using the public key in the first certificate in x5c with the algorithm specified in alg.
        var certificatesToDispose = new List<X509Certificate2>(attStmt.X5C.Length);
        try
        {
            if (attStmt.X5C.Length == 0)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            var currentDate = TimeProvider.GetPreciseUtcDateTime();
            var x5CCertificates = new List<X509Certificate2>(attStmt.X5C.Length);
            foreach (var x5CBytes in attStmt.X5C)
            {
                if (!X509CertificateInMemoryLoader.TryLoad(x5CBytes, out var x5CCert))
                {
                    x5CCert?.Dispose();
                    return Result<VerifiedAttestationStatement>.Fail();
                }

                certificatesToDispose.Add(x5CCert);
                x5CCertificates.Add(x5CCert);
                if (currentDate < x5CCert.NotBefore || currentDate > x5CCert.NotAfter)
                {
                    return Result<VerifiedAttestationStatement>.Fail();
                }
            }

            // 'credCert' must be the first element in the array.
            var credCert = x5CCertificates.First();
            var dataToVerify = Concat(authenticatorData.Raw, clientDataHash);
            if (!SignatureVerifier.IsValidCertificateSign(credCert, attStmt.Alg, dataToVerify, attStmt.Sig))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 3) Verify that the public key in the first certificate in 'x5c' matches the 'credentialPublicKey' in the 'attestedCredentialData' in 'authenticatorData'.
            if (!authenticatorData.AttestedCredentialData.CredentialPublicKey.Matches(credCert))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 4) Verify that the 'attestationChallenge' field in the attestation certificate extension data is identical to 'clientDataHash'.
            if (!TryGetKeyDescriptionAttestationExtension(credCert, out var keyDescription))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (!TryGetAttestationChallenge(keyDescription, out var attestationChallenge))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (!attestationChallenge.AsSpan().SequenceEqual(clientDataHash.AsSpan()))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 5) Verify the following using the appropriate authorization list from the attestation certificate extension data:
            if (!VerifyAuthorizationLists(keyDescription))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 6) If successful, return implementation-specific values representing attestation type Basic and attestation trust path 'x5c'.
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
    ///     Returns a collection of valid root X509v3 certificates.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="credCert">X509v3 certificate containing extension data of the Android Key attestation statement</param>
    /// <param name="authenticatorData"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-authenticator-data">Authenticator data</a> that has <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-attestedcredentialdata">attestedCredentialData</a>.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>If the collection of root certificates was successfully formed, the result contains <see cref="UniqueByteArraysCollection" />, otherwise the result indicates that there was an error during the collection formation process.</returns>
    protected virtual async Task<Result<UniqueByteArraysCollection>> GetAcceptableTrustAnchorsAsync(
        TContext context,
        X509Certificate2 credCert,
        AttestedAuthenticatorData authenticatorData,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authenticatorData);
        cancellationToken.ThrowIfCancellationRequested();

        var rootCertificates = new UniqueByteArraysCollection();
        var embeddedCertificates = GetEmbeddedRootCertificates();
        rootCertificates.AddRange(embeddedCertificates);
        var metadataRoots = await GetAcceptableTrustAnchorsFromFidoMetadataAsync(
            context,
            authenticatorData.AttestedCredentialData.Aaguid,
            cancellationToken);

        if (metadataRoots is not null)
        {
            rootCertificates.AddRange(metadataRoots);
        }

        return Result<UniqueByteArraysCollection>.Success(new(rootCertificates));
    }

    /// <summary>
    ///     Returns a collection of valid root certificates from the Fido Metadata Service.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>If the Fido Metadata Service contains root certificates for the specified <paramref name="aaguid" /> - then <see cref="UniqueByteArraysCollection" />, otherwise - <see langword="null" />.</returns>
    protected virtual async Task<UniqueByteArraysCollection?> GetAcceptableTrustAnchorsFromFidoMetadataAsync(
        TContext context,
        Guid aaguid,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var metadata = await FidoMetadataSearchService.FindMetadataByAaguidAsync(context, aaguid, cancellationToken);
        if (metadata is null)
        {
            return null;
        }

        if (metadata.AttestationTypes.Contains(AuthenticatorAttestationType.ATTESTATION_BASIC_FULL))
        {
            var result = new UniqueByteArraysCollection();
            // ReSharper disable once ConditionalAccessQualifierIsNonNullableAccordingToAPIContract
            if (metadata.RootCertificates?.Length > 0)
            {
                result.AddRange(metadata.RootCertificates);
            }

            return result;
        }

        return null;
    }

    /// <summary>
    ///     Returns a collection of root certificates embedded in the library.
    /// </summary>
    /// <returns>An instance of <see cref="UniqueByteArraysCollection" />. It may return an empty collection, but it never returns <see langword="null" />.</returns>
    protected virtual UniqueByteArraysCollection GetEmbeddedRootCertificates()
    {
        return new(AndroidKeyRoots.Certificates);
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
        //   attestationVersion         INTEGER, # KM2 value is 1. KM3 value is 2. KM4 value is 3.
        //   attestationSecurityLevel   SecurityLevel,
        //   keymasterVersion           INTEGER,
        //   keymasterSecurityLevel     SecurityLevel,
        //   attestationChallenge       OCTET_STRING,
        //   uniqueId                   OCTET_STRING,
        //   softwareEnforced           AuthorizationList,
        //   teeEnforced                AuthorizationList,
        // }
        //
        // AuthorizationList ::= SEQUENCE {
        //   purpose                     [1] EXPLICIT SET OF INTEGER OPTIONAL,
        //   ...
        //   allApplications             [600] EXPLICIT NULL OPTIONAL,
        //   ...
        //   origin                      [702] EXPLICIT INTEGER OPTIONAL,
        //   ...
        // }
        // ...
        // }
        var keyDescriptionElements = keyDescription.Items;
        if (keyDescriptionElements.Length < 8)
        {
            return false;
        }

        if (keyDescriptionElements[6] is not Asn1Sequence softwareEnforced)
        {
            return false;
        }

        if (keyDescriptionElements[7] is not Asn1Sequence teeEnforced)
        {
            return false;
        }

        // 1) The AuthorizationList.allApplications field is not present
        // on either authorization list (softwareEnforced nor teeEnforced), since PublicKeyCredential MUST be scoped to the RP ID.
        if (IsAllApplicationsPresent(softwareEnforced))
        {
            return false;
        }

        if (IsAllApplicationsPresent(teeEnforced))
        {
            return false;
        }

        // 2) For the following, use only the teeEnforced authorization list
        // if the RP wants to accept only keys from a trusted execution environment,
        // otherwise use the union of teeEnforced and softwareEnforced.
        //  - The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED.
        //  - The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN.
        var shouldAcceptKeysOnlyFromTrustedExecutionEnvironment = Options.CurrentValue.AttestationStatements.AndroidKey.AcceptKeysOnlyFromTrustedExecutionEnvironment;
        if (shouldAcceptKeysOnlyFromTrustedExecutionEnvironment)
        {
            if (!TryGetPurposeFromAuthorizationList(teeEnforced, out var teeEnforcedPurpose))
            {
                return false;
            }

            if (!TryGetOriginFromAuthorizationList(teeEnforced, out var teeEnforcedOrigin))
            {
                return false;
            }

            return IsOriginAndPurposeCorrect(teeEnforcedPurpose.Value, teeEnforcedOrigin.Value);
        }
        else
        {
            // purpose
            BigInteger purpose;
            if (!TryGetPurposeFromAuthorizationList(teeEnforced, out var teeEnforcedPurpose))
            {
                if (!TryGetPurposeFromAuthorizationList(softwareEnforced, out var softwareEnforcedPurpose))
                {
                    return false;
                }

                purpose = softwareEnforcedPurpose.Value;
            }
            else
            {
                // AuthorizationList.purpose should be contained either in softwareEnforced or in teeEnforced. It cannot be in both at the same time.
                if (TryGetPurposeFromAuthorizationList(softwareEnforced, out _))
                {
                    return false;
                }

                purpose = teeEnforcedPurpose.Value;
            }

            // origin
            BigInteger origin;
            if (!TryGetOriginFromAuthorizationList(teeEnforced, out var teeEnforcedOrigin))
            {
                if (!TryGetOriginFromAuthorizationList(softwareEnforced, out var softwareEnforcedOrigin))
                {
                    return false;
                }

                origin = softwareEnforcedOrigin.Value;
            }
            else
            {
                // AuthorizationList.origin should be contained either in softwareEnforced or in teeEnforced. It cannot be in both at the same time.
                if (TryGetOriginFromAuthorizationList(softwareEnforced, out _))
                {
                    return false;
                }

                origin = teeEnforcedOrigin.Value;
            }

            return IsOriginAndPurposeCorrect(purpose, origin);
        }
    }

    /// <summary>
    ///     Verifies "origin" and "purpose" in AuthorizationList
    /// </summary>
    /// <param name="purpose">The "purpose" value obtained from AuthorizationList.</param>
    /// <param name="origin">The "origin" value obtained from AuthorizationList.</param>
    /// <returns>If both values are correct - <see langword="true" />, otherwise - <see langword="false" />.</returns>
    protected virtual bool IsOriginAndPurposeCorrect(BigInteger purpose, BigInteger origin)
    {
        // https://android.googlesource.com/platform/hardware/libhardware/+/refs/heads/main/include_all/hardware/keymaster_defs.h
        // AuthorizationList.purpose == KM_PURPOSE_SIGN (Usable with RSA, EC and HMAC keys.)
        var kmPurposeSign = new BigInteger(2);
        // AuthorizationList.origin == KM_ORIGIN_GENERATED (Generated in keymaster. Should not exist outside the TEE.)
        var kmOriginGenerated = new BigInteger(0);

        return purpose == kmPurposeSign && origin == kmOriginGenerated;
    }

    /// <summary>
    ///     Extracts the "purpose" value from AuthorizationList.
    /// </summary>
    /// <param name="authorizationList">The AuthorizationList from which the "purpose" needs to be extracted.</param>
    /// <param name="value">Output parameter. If a valid "purpose" exists in the AuthorizationList, it will return a <see cref="BigInteger" />, otherwise - <see langword="null" />.</param>
    /// <returns>If there is a valid "purpose" in the <paramref name="authorizationList" />, then <see langword="true" />, otherwise - <see langword="false" />.</returns>
    protected virtual bool TryGetPurposeFromAuthorizationList(Asn1Sequence authorizationList, [NotNullWhen(true)] out BigInteger? value)
    {
        ArgumentNullException.ThrowIfNull(authorizationList);
        // purpose  [1] EXPLICIT SET OF INTEGER OPTIONAL
        const int purposeTagId = 1;
        foreach (var element in authorizationList.Items)
        {
            if (element.Tag is { TagClass: TagClass.ContextSpecific, TagValue: purposeTagId })
            {
                if (element is not Asn1RawElement rawElement)
                {
                    value = null;
                    return false;
                }

                var rawValue = rawElement.RawValue;
                var reader = new AsnReader(rawValue, AsnEncodingRules.DER);
                if (reader.PeekTag() is not { TagClass: TagClass.ContextSpecific, TagValue: purposeTagId })
                {
                    value = null;
                    return false;
                }

                var contextSpecificReader = reader.ReadSetOf(reader.PeekTag());
                if (contextSpecificReader.PeekTag() is not { TagClass: TagClass.Universal, TagValue: (int) UniversalTagNumber.Set })
                {
                    value = null;
                    return false;
                }

                var setReader = contextSpecificReader.ReadSetOf();
                var firstElementTag = setReader.PeekTag();
                if (firstElementTag is not { TagClass: TagClass.Universal, TagValue: (int) UniversalTagNumber.Integer })
                {
                    value = null;
                    return false;
                }

                value = setReader.ReadInteger(firstElementTag);
                return true;
            }
        }

        value = null;
        return false;
    }

    /// <summary>
    ///     Extracts the "origin" value from the AuthorizationList.
    /// </summary>
    /// <param name="authorizationList">The AuthorizationList from which the "origin" needs to be extracted.</param>
    /// <param name="value">Output parameter. If a valid "origin" is present in the AuthorizationList, it will return <see cref="BigInteger" />, otherwise - <see langword="null" />.</param>
    /// <returns>If there is a valid "origin" in the <paramref name="authorizationList" />, then <see langword="true" />, otherwise - <see langword="false" />.</returns>
    protected virtual bool TryGetOriginFromAuthorizationList(Asn1Sequence authorizationList, [NotNullWhen(true)] out BigInteger? value)
    {
        ArgumentNullException.ThrowIfNull(authorizationList);
        // origin  [702] EXPLICIT INTEGER OPTIONAL
        const int originTagId = 702;
        foreach (var element in authorizationList.Items)
        {
            if (element.Tag is { TagClass: TagClass.ContextSpecific, TagValue: originTagId })
            {
                if (element is not Asn1RawElement rawElement)
                {
                    value = null;
                    return false;
                }

                var rawValue = rawElement.RawValue;
                var reader = new AsnReader(rawValue, AsnEncodingRules.DER);
                if (reader.PeekTag() is not { TagClass: TagClass.ContextSpecific, TagValue: originTagId })
                {
                    value = null;
                    return false;
                }

                var contextSpecificReader = reader.ReadSetOf(reader.PeekTag());
                var firstElementTag = contextSpecificReader.PeekTag();
                if (firstElementTag is not { TagClass: TagClass.Universal, TagValue: (int) UniversalTagNumber.Integer })
                {
                    value = null;
                    return false;
                }

                value = contextSpecificReader.ReadInteger(firstElementTag);
                return true;
            }
        }

        value = null;
        return false;
    }

    /// <summary>
    ///     Verifies the presence of the "allApplications" tag in the AuthorizationList.
    /// </summary>
    /// <param name="authorizationList">The AuthorizationList to be verified.</param>
    /// <returns>If the <paramref name="authorizationList" /> contains the "allApplications" tag - <see langword="true" />, otherwise - <see langword="false" />.</returns>
    protected virtual bool IsAllApplicationsPresent(Asn1Sequence authorizationList)
    {
        ArgumentNullException.ThrowIfNull(authorizationList);
        const int allApplicationsTagId = 600;

        foreach (var element in authorizationList.Items)
        {
            if (element.Tag is { TagClass: TagClass.ContextSpecific, TagValue: allApplicationsTagId })
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
    /// <returns></returns>
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
        //   attestationVersion         INTEGER, # KM2 value is 1. KM3 value is 2. KM4 value is 3.
        //   attestationSecurityLevel   SecurityLevel,
        //   keymasterVersion           INTEGER,
        //   keymasterSecurityLevel     SecurityLevel,
        //   attestationChallenge       OCTET_STRING,
        //   uniqueId                   OCTET_STRING,
        //   softwareEnforced           AuthorizationList,
        //   teeEnforced                AuthorizationList,
        // }
        // attestationChallenge has an offset of 4 from the start of the SEQUENCE.
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
    /// <returns></returns>
    protected virtual bool TryGetKeyDescriptionAttestationExtension(X509Certificate2 credCert, [NotNullWhen(true)] out Asn1Sequence? keyDescription)
    {
        ArgumentNullException.ThrowIfNull(credCert);
        // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-key-attstn-cert-requirements
        // §8.4.1. Android Key Attestation Statement Certificate Requirements
        // Android Key Attestation attestation certificate's android key attestation certificate extension data
        // is identified by the OID 1.3.6.1.4.1.11129.2.1.17, and its schema is defined in the Android developer documentation.
        foreach (var extension in credCert.Extensions)
        {
            if (extension.Oid?.Value == "1.3.6.1.4.1.11129.2.1.17")
            {
                var deserializeResult = Asn1Deserializer.Deserialize(extension.RawData, AsnEncodingRules.DER);
                if (deserializeResult.HasError)
                {
                    keyDescription = null;
                    return false;
                }

                if (deserializeResult.Ok is null)
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
        }

        keyDescription = null;
        return false;
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
}
