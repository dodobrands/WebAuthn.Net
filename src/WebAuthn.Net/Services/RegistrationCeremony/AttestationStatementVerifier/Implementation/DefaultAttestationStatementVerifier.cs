using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.AndroidKey;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.AndroidSafetyNet;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.Apple;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.FidoU2F;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.None;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.Packed;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.Tpm;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation;

public class DefaultAttestationStatementVerifier<TContext> : IAttestationStatementVerifier<TContext>
    where TContext : class, IWebAuthnContext
{
    private readonly IAndroidKeyAttestationStatementVerifier _androidKeyVerifier;
    private readonly IAndroidSafetyNetAttestationStatementVerifier _androidSafetyNetVerifier;
    private readonly IAppleAnonymousAttestationStatementVerifier _appleAnonymousVerifier;
    private readonly IFidoU2FAttestationStatementVerifier _fidoU2FVerifier;
    private readonly ILogger<DefaultAttestationStatementVerifier<TContext>> _logger;
    private readonly INoneAttestationStatementVerifier _noneVerifier;
    private readonly IPackedAttestationStatementVerifier _packedVerifier;
    private readonly ITpmAttestationStatementVerifier _tpmVerifier;

    public DefaultAttestationStatementVerifier(
        IPackedAttestationStatementVerifier packedVerifier,
        ITpmAttestationStatementVerifier tpmVerifier,
        IAndroidKeyAttestationStatementVerifier androidKeyVerifier,
        IAndroidSafetyNetAttestationStatementVerifier androidSafetyNetVerifier,
        IFidoU2FAttestationStatementVerifier fidoU2FVerifier,
        INoneAttestationStatementVerifier noneVerifier,
        IAppleAnonymousAttestationStatementVerifier appleAnonymousVerifier,
        ILogger<DefaultAttestationStatementVerifier<TContext>> logger)
    {
        ArgumentNullException.ThrowIfNull(packedVerifier);
        ArgumentNullException.ThrowIfNull(tpmVerifier);
        ArgumentNullException.ThrowIfNull(androidKeyVerifier);
        ArgumentNullException.ThrowIfNull(androidSafetyNetVerifier);
        ArgumentNullException.ThrowIfNull(fidoU2FVerifier);
        ArgumentNullException.ThrowIfNull(noneVerifier);
        ArgumentNullException.ThrowIfNull(appleAnonymousVerifier);
        ArgumentNullException.ThrowIfNull(logger);
        _packedVerifier = packedVerifier;
        _tpmVerifier = tpmVerifier;
        _androidKeyVerifier = androidKeyVerifier;
        _androidSafetyNetVerifier = androidSafetyNetVerifier;
        _fidoU2FVerifier = fidoU2FVerifier;
        _noneVerifier = noneVerifier;
        _appleAnonymousVerifier = appleAnonymousVerifier;
        _logger = logger;
    }


    public async Task<Result<AttestationStatementVerificationResult>> VerifyAttestationStatementAsync(
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
                        return Result<AttestationStatementVerificationResult>.Fail();
                    }

                    return _packedVerifier.Verify(packed, request.AuthData, clientDataHash);
                }
            case AttestationStatementFormat.Tpm:
                {
                    if (request.AttStmt is not TpmAttestationStatement tpm)
                    {
                        _logger.AttStmtVerifierInvalidAttestationStatement(request.AttStmt.GetType().ToString(), AttestationStatementFormat.Tpm);
                        return Result<AttestationStatementVerificationResult>.Fail();
                    }

                    return _tpmVerifier.Verify(tpm, request.AuthData, clientDataHash);
                }
            case AttestationStatementFormat.AndroidKey:
                {
                    if (request.AttStmt is not AndroidKeyAttestationStatement androidKey)
                    {
                        _logger.AttStmtVerifierInvalidAttestationStatement(request.AttStmt.GetType().ToString(), AttestationStatementFormat.AndroidKey);
                        return Result<AttestationStatementVerificationResult>.Fail();
                    }

                    return _androidKeyVerifier.Verify(androidKey, request.AuthData, clientDataHash);
                }
            case AttestationStatementFormat.AndroidSafetynet:
                {
                    if (request.AttStmt is not AndroidSafetyNetAttestationStatement androidSafetyNet)
                    {
                        _logger.AttStmtVerifierInvalidAttestationStatement(request.AttStmt.GetType().ToString(), AttestationStatementFormat.AndroidSafetynet);
                        return Result<AttestationStatementVerificationResult>.Fail();
                    }

                    return _androidSafetyNetVerifier.Verify(androidSafetyNet, request.AuthData, clientDataHash);
                }
            case AttestationStatementFormat.FidoU2F:
                {
                    if (request.AttStmt is not FidoU2FAttestationStatement fidoU2F)
                    {
                        _logger.AttStmtVerifierInvalidAttestationStatement(request.AttStmt.GetType().ToString(), AttestationStatementFormat.FidoU2F);
                        return Result<AttestationStatementVerificationResult>.Fail();
                    }

                    return _fidoU2FVerifier.Verify(fidoU2F, request.AuthData, clientDataHash);
                }
            case AttestationStatementFormat.None:
                {
                    if (request.AttStmt is not NoneAttestationStatement none)
                    {
                        _logger.AttStmtVerifierInvalidAttestationStatement(request.AttStmt.GetType().ToString(), AttestationStatementFormat.None);
                        return Result<AttestationStatementVerificationResult>.Fail();
                    }

                    return _noneVerifier.Verify(none, request.AuthData, clientDataHash);
                }
            case AttestationStatementFormat.AppleAnonymous:
                {
                    if (request.AttStmt is not AppleAnonymousAttestationStatement apple)
                    {
                        _logger.AttStmtVerifierInvalidAttestationStatement(request.AttStmt.GetType().ToString(), AttestationStatementFormat.AppleAnonymous);
                        return Result<AttestationStatementVerificationResult>.Fail();
                    }

                    return _appleAnonymousVerifier.Verify(apple, request.AuthData, clientDataHash);
                }
            default:
                {
                    _logger.UnknownFmt();
                    return Result<AttestationStatementVerificationResult>.Fail();
                }
        }
    }
}

public static partial class DefaultAttestationStatementVerifierLoggingExtensions
{
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'attStmtVerificationRequest.AttStmt' type: {AttStmtType} does not match 'fmt': {Fmt}.")]
    public static partial void AttStmtVerifierInvalidAttestationStatement(this ILogger logger, string attStmtType, AttestationStatementFormat fmt);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Unknown 'fmt'")]
    public static partial void UnknownFmt(this ILogger logger);
}
