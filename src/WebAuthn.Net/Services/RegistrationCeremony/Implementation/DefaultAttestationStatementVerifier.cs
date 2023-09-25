using System;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Extensions;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.Extensions;
using WebAuthn.Net.Services.RegistrationCeremony.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.Enums;
using WebAuthn.Net.Services.TimeProvider;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation;

public class DefaultAttestationStatementVerifier<TContext> : IAttestationStatementVerifier<TContext>
    where TContext : class, IWebAuthnContext
{
    private readonly ILogger<DefaultAttestationStatementVerifier<TContext>> _logger;
    private readonly ITimeProvider _timeProvider;

    public DefaultAttestationStatementVerifier(ITimeProvider timeProvider, ILogger<DefaultAttestationStatementVerifier<TContext>> logger)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(logger);
        _timeProvider = timeProvider;
        _logger = logger;
    }

    public async Task<bool> VerifyAttestationStatementAsync(
        TContext context,
        AttestationStatementVerificationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        await Task.Yield();
        var clientDataHash = request.ClientDataHash;
        switch (request.Fmt)
        {
            case AttestationStatementFormat.Packed:
                {
                    if (request.AttStmt is not PackedAttestationStatement packed)
                    {
                        _logger.AttStmtVerifierInvalidAttestationStatement(request.AttStmt.GetType().ToString(), AttestationStatementFormat.Packed);
                        return false;
                    }

                    return VerifyPacked(packed, request.AuthData, clientDataHash);
                }
            case AttestationStatementFormat.Tpm:
                {
                    if (request.AttStmt is not TpmAttestationStatement tpm)
                    {
                        _logger.AttStmtVerifierInvalidAttestationStatement(request.AttStmt.GetType().ToString(), AttestationStatementFormat.Tpm);
                        return false;
                    }

                    return VerifyTpm(tpm, request.AuthData, clientDataHash);
                }
            case AttestationStatementFormat.AndroidKey:
                {
                    if (request.AttStmt is not AndroidKeyAttestationStatement androidKey)
                    {
                        _logger.AttStmtVerifierInvalidAttestationStatement(request.AttStmt.GetType().ToString(), AttestationStatementFormat.AndroidKey);
                        return false;
                    }

                    return VerifyAndroidKey(androidKey, request.AuthData, clientDataHash);
                }
            case AttestationStatementFormat.AndroidSafetynet:
                {
                    if (request.AttStmt is not AndroidSafetyNetAttestationStatement androidSafetyNet)
                    {
                        _logger.AttStmtVerifierInvalidAttestationStatement(request.AttStmt.GetType().ToString(), AttestationStatementFormat.AndroidSafetynet);
                        return false;
                    }

                    return VerifyAndroidSafetyNet(androidSafetyNet, request.AuthData, clientDataHash);
                }
            case AttestationStatementFormat.FidoU2F:
                {
                    if (request.AttStmt is not FidoU2FAttestationStatement fidoU2F)
                    {
                        _logger.AttStmtVerifierInvalidAttestationStatement(request.AttStmt.GetType().ToString(), AttestationStatementFormat.FidoU2F);
                        return false;
                    }

                    return VerifyFidoU2F(fidoU2F, request.AuthData, clientDataHash);
                }
            case AttestationStatementFormat.None:
                {
                    if (request.AttStmt is not NoneAttestationStatement none)
                    {
                        _logger.AttStmtVerifierInvalidAttestationStatement(request.AttStmt.GetType().ToString(), AttestationStatementFormat.None);
                        return false;
                    }

                    return VerifyNone(none, request.AuthData, clientDataHash);
                }
            case AttestationStatementFormat.AppleAnonymous:
                {
                    if (request.AttStmt is not AppleAnonymousAttestationStatement apple)
                    {
                        _logger.AttStmtVerifierInvalidAttestationStatement(request.AttStmt.GetType().ToString(), AttestationStatementFormat.AppleAnonymous);
                        return false;
                    }

                    return VerifyAppleAnonymous(apple, request.AuthData, clientDataHash);
                }
            default:
                throw new ArgumentOutOfRangeException(nameof(request), request.Fmt, null);
        }
    }

    private bool VerifyPacked(
        PackedAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
        if (attStmt.X5C is not null)
        {
            var trustPath = new X509Certificate2[attStmt.X5C.Length];
            for (var i = 0; i < trustPath.Length; i++)
            {
                var x5CCert = new X509Certificate2(attStmt.X5C[i]);
                var currentDate = _timeProvider.GetUtcDateTime();
                if (currentDate < x5CCert.NotBefore || currentDate > x5CCert.NotAfter)
                {
                    return false;
                }

                trustPath[i] = x5CCert;
            }

            // The attestation certificate 'attestnCert' MUST be the first element in the array.
            var attestnCert = trustPath.First();
            var signatureArg = Concat(authData.RawAuthData, clientDataHash);
            if (!IsSignatureValid(attestnCert, attStmt.Alg, signatureArg, attStmt.Sig))
            {
                return false;
            }
        }

        return false;
    }

    private static bool IsSignatureValid(X509Certificate2 certificate, CoseAlgorithm alg, byte[] dataToVerify, byte[] signature)
    {
        if (!alg.TryGetCoseKeyType(out var kty))
        {
            return false;
        }

        switch (kty.Value)
        {
            case CoseKeyType.EC2:
                {
                    if (!alg.TryGetSupportedEllipticCurves(out var supportedCurves))
                    {
                        return false;
                    }

                    if (!alg.TryToHashAlgorithmName(out var hashAlgorithmName))
                    {
                        return false;
                    }

                    var ecDsaPubKey = certificate.GetECDsaPublicKey();
                    if (ecDsaPubKey is null)
                    {
                        return false;
                    }

                    var keyParams = ecDsaPubKey.ExportParameters(false);
                    var curve = keyParams.Curve;
                    if (!curve.TryToCoseCurve(out var coseCurve))
                    {
                        return false;
                    }

                    if (!supportedCurves.Contains(coseCurve.Value))
                    {
                        return false;
                    }

                    var x = keyParams.Q.X;
                    var y = keyParams.Q.Y;
                    if (x is null || y is null)
                    {
                        return false;
                    }

                    var point = new ECPoint
                    {
                        X = x,
                        Y = y
                    };

                    using var ecdsa = ECDsa.Create(new ECParameters
                    {
                        Q = point,
                        Curve = curve
                    });
                    return ecdsa.VerifyData(dataToVerify, signature, hashAlgorithmName.Value, DSASignatureFormat.Rfc3279DerSequence);
                }
            case CoseKeyType.RSA:
                {
                    if (!alg.TryToHashAlgorithmName(out var hashAlgorithmName))
                    {
                        return false;
                    }

                    if (!alg.TryGetRsaPadding(out var padding))
                    {
                        return false;
                    }

                    var rsaPublicKey = certificate.GetRSAPublicKey();
                    if (rsaPublicKey is null)
                    {
                        return false;
                    }

                    var keyParams = rsaPublicKey.ExportParameters(false);
                    var modulus = keyParams.Modulus;
                    var exponent = keyParams.Exponent;
                    if (modulus is null || exponent is null)
                    {
                        return false;
                    }

                    using var rsa = RSA.Create(new RSAParameters
                    {
                        Modulus = modulus,
                        Exponent = exponent
                    });
                    return rsa.VerifyData(dataToVerify, signature, hashAlgorithmName.Value, padding);
                }
            default:
                return false;
        }
    }

    private static bool VerifyTpm(
        TpmAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
        return false;
    }

    private static bool VerifyAndroidKey(
        AndroidKeyAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
        return false;
    }

    private static bool VerifyAndroidSafetyNet(
        AndroidSafetyNetAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
        return false;
    }

    private static bool VerifyFidoU2F(
        FidoU2FAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
        return false;
    }

    private static bool VerifyNone(
        NoneAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
        return false;
    }

    private static bool VerifyAppleAnonymous(
        AppleAnonymousAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
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

public static partial class DefaultAttestationStatementVerifierLoggingExtensions
{
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'attStmtVerificationRequest.AttStmt' type: {AttStmtType} does not match 'fmt': {Fmt}.")]
    public static partial void AttStmtVerifierInvalidAttestationStatement(this ILogger logger, string attStmtType, AttestationStatementFormat fmt);
}
