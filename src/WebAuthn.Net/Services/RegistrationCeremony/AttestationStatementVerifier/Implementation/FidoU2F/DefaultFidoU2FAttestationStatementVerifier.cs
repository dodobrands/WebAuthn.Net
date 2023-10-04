using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models;
using WebAuthn.Net.Services.Cryptography.Sign;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.FidoU2F;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Models;
using WebAuthn.Net.Services.TimeProvider;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.FidoU2F;

public class DefaultFidoU2FAttestationStatementVerifier : IFidoU2FAttestationStatementVerifier
{
    private readonly ITimeProvider _timeProvider;

    public DefaultFidoU2FAttestationStatementVerifier(ITimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        _timeProvider = timeProvider;
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope")]
    public Result<AttestationStatementVerificationResult> Verify(
        FidoU2FAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(authData);
        ArgumentNullException.ThrowIfNull(clientDataHash);
        // 1) Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // 2) Check that x5c has exactly one element and let attCert be that element. Let certificate public key be the public key conveyed by attCert.
        // If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error.
        if (!TryGetExactlyOneCertificate(attStmt, out var attCert))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        if (!IsValidPublicKeyParameters(attCert, out var attCertEcParameters))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 3) Extract the claimed rpIdHash from authenticatorData, and the claimed credentialId and credentialPublicKey from authenticatorData.attestedCredentialData.
        var rpIdHash = authData.RpIdHash;
        var credentialId = authData.AttestedCredentialData.CredentialId;
        if (authData.AttestedCredentialData.CredentialPublicKey is not CoseEc2Key credentialPublicKey)
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 4) Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of [RFC9052]) to Raw ANSI X9.62 public key format (see ALG_KEY_ECC_X962_RAW in Section 3.6.2 Public Key Representation Formats of [FIDO-Registry]).
        if (!TryConvertCoseKeyToPublicKeyU2F(credentialPublicKey, out var publicKeyU2F))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 5) Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F) (see Section 4.3 of [FIDO-U2F-Message-Formats]).
        var verificationData = Concat(stackalloc byte[1] { 0x00 }, rpIdHash, clientDataHash, credentialId, publicKeyU2F);

        // 6) Verify the sig using verificationData and the certificate public key per section 4.1.4 of [SEC1] with SHA-256 as the hash function used in step two.
        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new()
            {
                X = attCertEcParameters.Value.Q.X,
                Y = attCertEcParameters.Value.Q.Y
            }
        });
        if (!ecdsa.VerifyData(verificationData, attStmt.Sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 7) Optionally, inspect x5c and consult externally provided knowledge to determine whether attStmt conveys a Basic or AttCA attestation.
        // 8) If successful, return implementation-specific values representing attestation type Basic, AttCA or uncertainty, and attestation trust path x5c.
        var result = new AttestationStatementVerificationResult(AttestationType.Basic, new[] { attCert });
        return Result<AttestationStatementVerificationResult>.Success(result);
    }

    private bool TryGetExactlyOneCertificate(FidoU2FAttestationStatement attStmt, [NotNullWhen(true)] out X509Certificate2? attCert)
    {
        if (attStmt.X5C.Length != 1)
        {
            attCert = null;
            return false;
        }

        var certBytes = attStmt.X5C[0];
        var cert = new X509Certificate2(certBytes);
        var currentDate = _timeProvider.GetPreciseUtcDateTime();
        if (currentDate < cert.NotBefore || currentDate > cert.NotAfter)
        {
            attCert = null;
            return false;
        }

        attCert = cert;
        return true;
    }

    private static bool IsValidPublicKeyParameters(X509Certificate2 attCert, [NotNullWhen(true)] out ECParameters? attCertEcParameters)
    {
        //  If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error.
        var ecDsaPubKey = attCert.GetECDsaPublicKey();
        if (ecDsaPubKey is null)
        {
            attCertEcParameters = null;
            return false;
        }

        var parameters = ecDsaPubKey.ExportParameters(false);
        if (parameters.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
        {
            attCertEcParameters = null;
            return false;
        }

        attCertEcParameters = parameters;
        return true;
    }

    private static bool TryConvertCoseKeyToPublicKeyU2F(CoseEc2Key credentialPublicKey, [NotNullWhen(true)] out byte[]? publicKeyU2F)
    {
        // Let x be the value corresponding to the "-2" key (representing x coordinate) in credentialPublicKey,
        // and confirm its size to be of 32 bytes.
        // If size differs or "-2" key is not found, terminate this algorithm and return an appropriate error.
        if (credentialPublicKey.X.Length != 32)
        {
            publicKeyU2F = null;
            return false;
        }

        // Let y be the value corresponding to the "-3" key (representing y coordinate) in credentialPublicKey,
        // and confirm its size to be of 32 bytes.
        // If size differs or "-3" key is not found, terminate this algorithm and return an appropriate error.
        if (credentialPublicKey.Y.Length != 32)
        {
            publicKeyU2F = null;
            return false;
        }

        // Let publicKeyU2F be the concatenation 0x04 || x || y.
        publicKeyU2F = Concat(stackalloc byte[1] { 0x04 }, credentialPublicKey.X, credentialPublicKey.Y);
        return true;
    }

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c)
    {
        var result = new byte[a.Length + b.Length + c.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        c.CopyTo(result.AsSpan(a.Length + b.Length));
        return result;
    }

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d, ReadOnlySpan<byte> e)
    {
        var result = new byte[a.Length + b.Length + c.Length + d.Length + e.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        c.CopyTo(result.AsSpan(a.Length + b.Length));
        c.CopyTo(result.AsSpan(a.Length + b.Length));
        d.CopyTo(result.AsSpan(a.Length + b.Length + c.Length));
        e.CopyTo(result.AsSpan(a.Length + b.Length + c.Length + d.Length));
        return result;
    }
}
