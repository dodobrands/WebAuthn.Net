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

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultAndroidKeyAttestationStatementVerifier<TContext>
    : IAndroidKeyAttestationStatementVerifier<TContext> where TContext : class, IWebAuthnContext
{
    public DefaultAndroidKeyAttestationStatementVerifier(
        IOptionsMonitor<WebAuthnOptions> options,
        ITimeProvider timeProvider,
        IDigitalSignatureVerifier signatureVerifier,
        IAsn1Decoder asn1Decoder,
        IFidoMetadataSearchService<TContext> fidoMetadataSearchService)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        ArgumentNullException.ThrowIfNull(asn1Decoder);
        ArgumentNullException.ThrowIfNull(fidoMetadataSearchService);
        Options = options;
        TimeProvider = timeProvider;
        SignatureVerifier = signatureVerifier;
        Asn1Decoder = asn1Decoder;
        FidoMetadataSearchService = fidoMetadataSearchService;
    }

    protected IOptionsMonitor<WebAuthnOptions> Options { get; }
    protected ITimeProvider TimeProvider { get; }
    protected IDigitalSignatureVerifier SignatureVerifier { get; }
    protected IAsn1Decoder Asn1Decoder { get; }
    protected IFidoMetadataSearchService<TContext> FidoMetadataSearchService { get; }

    public virtual async Task<Result<AttestationStatementVerificationResult>> VerifyAsync(
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
                return Result<AttestationStatementVerificationResult>.Fail();
            }

            var currentDate = TimeProvider.GetPreciseUtcDateTime();
            var x5CCertificates = new List<X509Certificate2>(attStmt.X5C.Length);
            foreach (var x5CBytes in attStmt.X5C)
            {
                if (!X509CertificateInMemoryLoader.TryLoad(x5CBytes, out var x5CCert))
                {
                    x5CCert?.Dispose();
                    return Result<AttestationStatementVerificationResult>.Fail();
                }

                certificatesToDispose.Add(x5CCert);
                x5CCertificates.Add(x5CCert);
                if (currentDate < x5CCert.NotBefore || currentDate > x5CCert.NotAfter)
                {
                    return Result<AttestationStatementVerificationResult>.Fail();
                }
            }

            // 'credCert' must be the first element in the array.
            var credCert = x5CCertificates.First();
            var dataToVerify = Concat(authenticatorData.Raw, clientDataHash);
            if (!SignatureVerifier.IsValidCertificateSign(credCert, attStmt.Alg, dataToVerify, attStmt.Sig))
            {
                return Result<AttestationStatementVerificationResult>.Fail();
            }

            // 3) Verify that the public key in the first certificate in 'x5c' matches the 'credentialPublicKey' in the 'attestedCredentialData' in 'authenticatorData'.
            if (!authenticatorData.AttestedCredentialData.CredentialPublicKey.Matches(credCert))
            {
                return Result<AttestationStatementVerificationResult>.Fail();
            }

            // 4) Verify that the 'attestationChallenge' field in the attestation certificate extension data is identical to 'clientDataHash'.
            if (!TryGetAttestationExtension(credCert, out var attestationExtension))
            {
                return Result<AttestationStatementVerificationResult>.Fail();
            }

            if (!TryGetAttestationChallenge(attestationExtension, out var attestationChallenge))
            {
                return Result<AttestationStatementVerificationResult>.Fail();
            }

            if (!attestationChallenge.AsSpan().SequenceEqual(clientDataHash.AsSpan()))
            {
                return Result<AttestationStatementVerificationResult>.Fail();
            }

            // 5) Verify the following using the appropriate authorization list from the attestation certificate extension data:
            if (!IsAuthorizationListDataValid(attestationExtension))
            {
                return Result<AttestationStatementVerificationResult>.Fail();
            }

            // 6) If successful, return implementation-specific values representing attestation type Basic and attestation trust path 'x5c'.
            var acceptableTrustAnchorsResult = await GetAcceptableTrustAnchorsAsync(
                context,
                credCert,
                authenticatorData,
                cancellationToken);
            if (acceptableTrustAnchorsResult.HasError)
            {
                return Result<AttestationStatementVerificationResult>.Fail();
            }

            var result = new AttestationStatementVerificationResult(
                AttestationStatementFormat.AndroidKey,
                AttestationType.Basic,
                attStmt.X5C,
                acceptableTrustAnchorsResult.Ok);
            return Result<AttestationStatementVerificationResult>.Success(result);
        }
        finally
        {
            foreach (var certificateToDispose in certificatesToDispose)
            {
                certificateToDispose.Dispose();
            }
        }
    }

    protected virtual async Task<Result<AcceptableTrustAnchors>> GetAcceptableTrustAnchorsAsync(
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

        if (metadataRoots.HasValue)
        {
            rootCertificates.AddRange(metadataRoots.Value);
        }

        return Result<AcceptableTrustAnchors>.Success(new(rootCertificates));
    }

    protected virtual async Task<Optional<byte[][]>> GetAcceptableTrustAnchorsFromFidoMetadataAsync(
        TContext context,
        Guid aaguid,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var metadataResult = await FidoMetadataSearchService.FindMetadataByAaguidAsync(context, aaguid, cancellationToken);
        if (!metadataResult.HasValue)
        {
            return Optional<byte[][]>.Empty();
        }

        var metadata = metadataResult.Value;
        if (metadata.AttestationTypes.Contains(AuthenticatorAttestationType.ATTESTATION_BASIC_FULL))
        {
            return Optional<byte[][]>.Payload(metadata.RootCertificates);
        }

        return Optional<byte[][]>.Empty();
    }

    protected virtual byte[][] GetEmbeddedRootCertificates()
    {
        return AndroidKeyRoots.Certificates;
    }

    protected virtual bool IsAuthorizationListDataValid(Asn1Sequence keyDescription)
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

    protected virtual bool IsOriginAndPurposeCorrect(BigInteger purpose, BigInteger origin)
    {
        // https://android.googlesource.com/platform/hardware/libhardware/+/refs/heads/main/include_all/hardware/keymaster_defs.h
        // AuthorizationList.purpose == KM_PURPOSE_SIGN (Usable with RSA, EC and HMAC keys.)
        var kmPurposeSign = new BigInteger(2);
        // AuthorizationList.origin == KM_ORIGIN_GENERATED (Generated in keymaster. Should not exist outside the TEE.)
        var kmOriginGenerated = new BigInteger(0);

        return purpose == kmPurposeSign && origin == kmOriginGenerated;
    }

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

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool TryGetAttestationChallenge(Asn1Sequence asn1AttestationExtension, [NotNullWhen(true)] out byte[]? attestationChallenge)
    {
        if (asn1AttestationExtension is null)
        {
            attestationChallenge = null;
            return false;
        }

        var keyDescriptionElements = asn1AttestationExtension.Items;
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

    protected virtual bool TryGetAttestationExtension(X509Certificate2 credCert, [NotNullWhen(true)] out Asn1Sequence? asn1AttestationExtension)
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
                var decodeResult = Asn1Decoder.Decode(extension.RawData, AsnEncodingRules.DER);
                if (decodeResult.HasError)
                {
                    asn1AttestationExtension = null;
                    return false;
                }

                if (!decodeResult.Ok.HasValue)
                {
                    asn1AttestationExtension = null;
                    return false;
                }

                // https://source.android.com/docs/security/features/keystore/attestation#schema
                // KeyDescription ::= SEQUENCE {
                //   ...
                // }
                if (decodeResult.Ok.Value is not Asn1Sequence keyDescriptionAsn1)
                {
                    asn1AttestationExtension = null;
                    return false;
                }

                asn1AttestationExtension = keyDescriptionAsn1;
                return true;
            }
        }

        asn1AttestationExtension = null;
        return false;
    }

    protected virtual byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }
}
