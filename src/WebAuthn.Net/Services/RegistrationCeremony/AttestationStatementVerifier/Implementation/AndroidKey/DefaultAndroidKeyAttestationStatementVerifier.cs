using System;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Cryptography.Sign;
using WebAuthn.Net.Services.RegistrationCeremony.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.RegistrationCeremony.Verification;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;
using WebAuthn.Net.Services.TimeProvider;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation.Verification.AndroidKey;

public class DefaultAndroidKeyAttestationStatementVerifier : IAndroidKeyAttestationStatementVerifier
{
    private readonly IDigitalSignatureVerifier _signatureVerifier;
    private readonly ITimeProvider _timeProvider;

    public DefaultAndroidKeyAttestationStatementVerifier(
        ITimeProvider timeProvider,
        IDigitalSignatureVerifier signatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        _timeProvider = timeProvider;
        _signatureVerifier = signatureVerifier;
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
        if (!IsAttestationChallengeContainsClientDataHash(credCert, clientDataHash))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        throw new NotImplementedException();
    }

    private static bool IsAttestationChallengeContainsClientDataHash(X509Certificate2 credCert, byte[] clientDataHash)
    {
        if (!TryGetExtensionData(credCert, out var extensionData))
        {
            return false;
        }

        if (!TryGetAttestationChallenge(extensionData, out var attestationChallenge))
        {
            return false;
        }

        return attestationChallenge.AsSpan().SequenceEqual(clientDataHash.AsSpan());
    }

    private static bool TryGetAttestationChallenge(byte[] extensionData, [NotNullWhen(true)] out byte[]? attestationChallenge)
    {
        // https://developer.android.com/training/articles/security-key-attestation#key_attestation_ext_schema
        // Key attestation extension data schema
        // -------------
        // Version 1
        // KeyDescription ::= SEQUENCE {
        //     attestationVersion  1,
        //     attestationSecurityLevel  SecurityLevel,
        //     keymasterVersion  INTEGER,
        //     keymasterSecurityLevel  SecurityLevel,
        //     attestationChallenge  OCTET_STRING,
        //     ...
        // }
        // -------------
        // Version 2
        // KeyDescription ::= SEQUENCE {
        //     attestationVersion  2,
        //     attestationSecurityLevel  SecurityLevel,
        //     keymasterVersion  INTEGER,
        //     keymasterSecurityLevel  SecurityLevel,
        //     attestationChallenge  OCTET_STRING,
        //     ...
        // }
        // -------------
        // Version 3
        // KeyDescription ::= SEQUENCE {
        //     attestationVersion  3,
        //     attestationSecurityLevel  SecurityLevel,
        //     keymasterVersion  INTEGER,
        //     keymasterSecurityLevel  SecurityLevel,
        //     attestationChallenge  OCTET_STRING,
        //     ...
        // }
        // -------------
        // Version 4
        // KeyDescription ::= SEQUENCE {
        //     attestationVersion  4,
        //     attestationSecurityLevel  SecurityLevel,
        //     keymasterVersion  INTEGER,
        //     keymasterSecurityLevel  SecurityLevel,
        //     attestationChallenge  OCTET_STRING,
        //     ...
        // }
        // -------------
        // Version 100
        // KeyDescription ::= SEQUENCE {
        //     attestationVersion  100,
        //     attestationSecurityLevel  SecurityLevel,
        //     keyMintVersion  INTEGER,
        //     keyMintSecurityLevel  SecurityLevel,
        //     attestationChallenge  OCTET_STRING,
        //     ...
        // }
        // -------------
        // Version 200
        // KeyDescription ::= SEQUENCE {
        //     attestationVersion  200,
        //     attestationSecurityLevel  SecurityLevel,
        //     keyMintVersion  INTEGER,
        //     keyMintSecurityLevel  SecurityLevel,
        //     attestationChallenge  OCTET_STRING,
        //     ...
        // }
        var reader = new AsnReader(extensionData, AsnEncodingRules.DER);
        if (reader.PeekTag() != new Asn1Tag(TagClass.Universal, (int) UniversalTagNumber.SequenceOf, true))
        {
            attestationChallenge = null;
            return false;
        }

        if (!reader.HasData)
        {
            attestationChallenge = null;
            return false;
        }

        var sequenceReader = reader.ReadSequence();
        if (!sequenceReader.HasData)
        {
            attestationChallenge = null;
            return false;
        }

        // attestationVersion
        sequenceReader.ReadEncodedValue();
        if (!sequenceReader.HasData)
        {
            attestationChallenge = null;
            return false;
        }

        // attestationSecurityLevel
        sequenceReader.ReadEncodedValue();
        if (!sequenceReader.HasData)
        {
            attestationChallenge = null;
            return false;
        }

        // keymasterVersion | keyMintVersion
        sequenceReader.ReadEncodedValue();
        if (!sequenceReader.HasData)
        {
            attestationChallenge = null;
            return false;
        }

        // keymasterSecurityLevel | keyMintSecurityLevel
        sequenceReader.ReadEncodedValue();
        if (!sequenceReader.HasData)
        {
            attestationChallenge = null;
            return false;
        }

        // attestationChallenge
        var attestationChallengeTag = sequenceReader.PeekTag();
        if (attestationChallengeTag != new Asn1Tag(UniversalTagNumber.OctetString, true)
            && attestationChallengeTag != new Asn1Tag(UniversalTagNumber.OctetString))
        {
            attestationChallenge = null;
            return false;
        }

        attestationChallenge = sequenceReader.ReadOctetString();
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
