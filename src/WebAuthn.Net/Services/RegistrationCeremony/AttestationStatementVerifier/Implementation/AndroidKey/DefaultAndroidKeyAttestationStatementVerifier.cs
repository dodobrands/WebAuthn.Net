using System;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Cryptography.Sign;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.AndroidKey;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Models;
using WebAuthn.Net.Services.Serialization.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;
using WebAuthn.Net.Services.TimeProvider;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.AndroidKey;

public class DefaultAndroidKeyAttestationStatementVerifier : IAndroidKeyAttestationStatementVerifier
{
    private readonly IAsn1Decoder _asn1Decoder;
    private readonly IOptionsMonitor<WebAuthnOptions> _options;
    private readonly IDigitalSignatureVerifier _signatureVerifier;
    private readonly ITimeProvider _timeProvider;

    public DefaultAndroidKeyAttestationStatementVerifier(
        IOptionsMonitor<WebAuthnOptions> options,
        ITimeProvider timeProvider,
        IDigitalSignatureVerifier signatureVerifier,
        IAsn1Decoder asn1Decoder)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        ArgumentNullException.ThrowIfNull(asn1Decoder);
        _timeProvider = timeProvider;
        _signatureVerifier = signatureVerifier;
        _asn1Decoder = asn1Decoder;
        _options = options;
    }

    public Result<AttestationStatementVerificationResult> Verify(
        AndroidKeyAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(authData);
        ArgumentNullException.ThrowIfNull(clientDataHash);
        // 1) Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // 2) Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
        // using the public key in the first certificate in x5c with the algorithm specified in alg.
        var trustPath = new X509Certificate2[attStmt.X5C.Length];
        for (var i = 0; i < trustPath.Length; i++)
        {
            var x5CCert = new X509Certificate2(attStmt.X5C[i]);
            var currentDate = _timeProvider.GetUtcDateTime();
            if (currentDate < x5CCert.NotBefore || currentDate > x5CCert.NotAfter)
            {
                return Result<AttestationStatementVerificationResult>.Fail();
            }

            trustPath[i] = x5CCert;
        }

        // 'credCert' must be the first element in the array.
        var credCert = trustPath.First();
        var dataToVerify = Concat(authData.RawAuthData, clientDataHash);
        if (!_signatureVerifier.IsValidCertificateSign(credCert, attStmt.Alg, dataToVerify, attStmt.Sig))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 3) Verify that the public key in the first certificate in x5c
        // matches the credentialPublicKey in the attestedCredentialData in authenticatorData.
        // --------
        // To verify, we will check if the signature using authData.AttestedCredentialData.CredentialPublicKey is valid.
        // For this, we will use the same parameters as for credCert.
        // If the same signature is valid for the same input data (dataToVerify, sig), it means the keys match.
        if (!_signatureVerifier.IsValidCoseKeySign(authData.AttestedCredentialData.CredentialPublicKey, dataToVerify, attStmt.Sig))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 4) Verify that the attestationChallenge field in the attestation certificate extension data is identical to clientDataHash.
        if (!TryGetExtensionData(credCert, out var extensionData))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        if (!TryGetKeyDescriptionAsn1(extensionData, out var keyDescription))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        if (!IsAttestationChallengeContainsClientDataHash(keyDescription, clientDataHash))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 5) Verify the following using the appropriate authorization list from the attestation certificate extension data:
        if (!IsAuthorizationListDataValid(keyDescription))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 6) If successful, return implementation-specific values representing attestation type Basic and attestation trust path x5c.
        var result = new AttestationStatementVerificationResult(AttestationType.Basic, trustPath);
        return Result<AttestationStatementVerificationResult>.Success(result);
    }

    private bool IsAuthorizationListDataValid(Asn1Sequence keyDescription)
    {
        var keyDescriptionElements = keyDescription.Value;
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
        var shouldAcceptKeysOnlyFromTrustedExecutionEnvironment = _options.CurrentValue.RegistrationCeremony.AndroidKeyAttestation.AcceptKeysOnlyFromTrustedExecutionEnvironment;
        if (shouldAcceptKeysOnlyFromTrustedExecutionEnvironment)
        {
            if (!IsOriginAndPurposeCorrect(teeEnforced))
            {
                return false;
            }
        }
        else
        {
            if (!IsOriginAndPurposeCorrect(teeEnforced) && !IsOriginAndPurposeCorrect(softwareEnforced))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsOriginAndPurposeCorrect(Asn1Sequence authorizationList)
    {
        // https://android.googlesource.com/platform/hardware/libhardware/+/refs/heads/main/include_all/hardware/keymaster_defs.h
        // AuthorizationList.purpose == KM_PURPOSE_SIGN (Usable with RSA, EC and HMAC keys.)
        var kmPurposeSign = new BigInteger(2);
        // AuthorizationList.origin == KM_ORIGIN_GENERATED (Generated in keymaster. Should not exist outside the TEE.)
        var kmOriginGenerated = new BigInteger(0);

        if (!TryGetPurposeFromAuthorizationList(authorizationList, out var purpose))
        {
            return false;
        }

        if (!TryGetOriginFromAuthorizationList(authorizationList, out var origin))
        {
            return false;
        }

        return purpose.Value == kmPurposeSign && origin.Value == kmOriginGenerated;
    }

    private static bool TryGetPurposeFromAuthorizationList(Asn1Sequence authorizationList, [NotNullWhen(true)] out BigInteger? value)
    {
        // purpose  [1] EXPLICIT SET OF INTEGER OPTIONAL
        const int purposeTagId = 1;
        foreach (var element in authorizationList.Value)
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

    private static bool TryGetOriginFromAuthorizationList(Asn1Sequence authorizationList, [NotNullWhen(true)] out BigInteger? value)
    {
        // origin  [702] EXPLICIT INTEGER OPTIONAL
        const int originTagId = 702;
        foreach (var element in authorizationList.Value)
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

    private static bool IsAllApplicationsPresent(Asn1Sequence authorizationList)
    {
        const int allApplicationsTagId = 600;

        foreach (var element in authorizationList.Value)
        {
            if (element.Tag is { TagClass: TagClass.ContextSpecific, TagValue: allApplicationsTagId })
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsAttestationChallengeContainsClientDataHash(Asn1Sequence keyDescription, byte[] clientDataHash)
    {
        if (!TryGetAttestationChallenge(keyDescription, out var attestationChallenge))
        {
            return false;
        }

        return attestationChallenge.AsSpan().SequenceEqual(clientDataHash.AsSpan());
    }

    private static bool TryGetAttestationChallenge(Asn1Sequence keyDescription, [NotNullWhen(true)] out byte[]? attestationChallenge)
    {
        var keyDescriptionElements = keyDescription.Value;
        if (keyDescriptionElements.Length < 5)
        {
            attestationChallenge = null;
            return false;
        }

        if (keyDescriptionElements[4] is not Asn1OctetString attestationChallengeAsn1)
        {
            attestationChallenge = null;
            return false;
        }

        attestationChallenge = attestationChallengeAsn1.Value;
        return true;
    }

    private bool TryGetKeyDescriptionAsn1(byte[] extensionData, [NotNullWhen(true)] out Asn1Sequence? keyDescription)
    {
        var decodeResult = _asn1Decoder.TryDecode(extensionData, AsnEncodingRules.DER);
        if (decodeResult.HasError || !decodeResult.Ok.AsnRoot.HasValue)
        {
            keyDescription = null;
            return false;
        }

        // https://developer.android.com/training/articles/security-key-attestation#key_attestation_ext_schema
        if (decodeResult.Ok.AsnRoot.Value is not Asn1Sequence keyDescriptionAsn1)
        {
            keyDescription = null;
            return false;
        }

        keyDescription = keyDescriptionAsn1;
        return true;
    }

    private static bool TryGetExtensionData(X509Certificate2 credCert, [NotNullWhen(true)] out byte[]? asn1ExtensionData)
    {
        // https://www.w3.org/TR/webauthn-3/#sctn-key-attstn-cert-requirements
        // § 8.4.1. Android Key Attestation Statement Certificate Requirements
        // Android Key Attestation attestation certificate's android key attestation certificate extension data
        // is identified by the OID 1.3.6.1.4.1.11129.2.1.17, and its schema is defined in the Android developer documentation.
        foreach (var extension in credCert.Extensions)
        {
            if (extension.Oid?.Value == "1.3.6.1.4.1.11129.2.1.17")
            {
                asn1ExtensionData = extension.RawData;
                return true;
            }
        }

        asn1ExtensionData = null;
        return false;
    }


    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }
}
