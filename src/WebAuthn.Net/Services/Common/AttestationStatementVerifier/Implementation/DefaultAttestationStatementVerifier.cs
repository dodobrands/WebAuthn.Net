using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.AndroidKey;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.AndroidSafetyNet;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Apple;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.FidoU2F;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.None;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Packed;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultAttestationStatementVerifier<TContext> : IAttestationStatementVerifier<TContext>
    where TContext : class, IWebAuthnContext
{
    public DefaultAttestationStatementVerifier(
        IPackedAttestationStatementVerifier<TContext> packedVerifier,
        ITpmAttestationStatementVerifier<TContext> tpmVerifier,
        IAndroidKeyAttestationStatementVerifier<TContext> androidKeyVerifier,
        IAndroidSafetyNetAttestationStatementVerifier<TContext> androidSafetyNetVerifier,
        IFidoU2FAttestationStatementVerifier<TContext> fidoU2FVerifier,
        INoneAttestationStatementVerifier<TContext> noneVerifier,
        IAppleAnonymousAttestationStatementVerifier<TContext> appleAnonymousVerifier,
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
        PackedVerifier = packedVerifier;
        TpmVerifier = tpmVerifier;
        AndroidKeyVerifier = androidKeyVerifier;
        AndroidSafetyNetVerifier = androidSafetyNetVerifier;
        FidoU2FVerifier = fidoU2FVerifier;
        NoneVerifier = noneVerifier;
        AppleAnonymousVerifier = appleAnonymousVerifier;
        Logger = logger;
    }

    protected IPackedAttestationStatementVerifier<TContext> PackedVerifier { get; }
    protected ITpmAttestationStatementVerifier<TContext> TpmVerifier { get; }
    protected IAndroidKeyAttestationStatementVerifier<TContext> AndroidKeyVerifier { get; }
    protected IAndroidSafetyNetAttestationStatementVerifier<TContext> AndroidSafetyNetVerifier { get; }
    protected IFidoU2FAttestationStatementVerifier<TContext> FidoU2FVerifier { get; }
    protected INoneAttestationStatementVerifier<TContext> NoneVerifier { get; }
    protected IAppleAnonymousAttestationStatementVerifier<TContext> AppleAnonymousVerifier { get; }
    protected ILogger<DefaultAttestationStatementVerifier<TContext>> Logger { get; }

    public virtual async Task<Result<VerifiedAttestationStatement>> VerifyAttestationStatementAsync(
        TContext context,
        AttestationStatementFormat fmt,
        AbstractAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        cancellationToken.ThrowIfCancellationRequested();
        switch (fmt)
        {
            case AttestationStatementFormat.Packed:
                {
                    if (attStmt is not PackedAttestationStatement packed)
                    {
                        Logger.AttStmtVerifierInvalidAttestationStatement(attStmt.GetType().ToString(), AttestationStatementFormat.Packed);
                        return Result<VerifiedAttestationStatement>.Fail();
                    }

                    return await PackedVerifier.VerifyAsync(context, packed, authenticatorData, clientDataHash, cancellationToken);
                }
            case AttestationStatementFormat.Tpm:
                {
                    if (attStmt is not TpmAttestationStatement tpm)
                    {
                        Logger.AttStmtVerifierInvalidAttestationStatement(attStmt.GetType().ToString(), AttestationStatementFormat.Tpm);
                        return Result<VerifiedAttestationStatement>.Fail();
                    }

                    return await TpmVerifier.VerifyAsync(context, tpm, authenticatorData, clientDataHash, cancellationToken);
                }
            case AttestationStatementFormat.AndroidKey:
                {
                    if (attStmt is not AndroidKeyAttestationStatement androidKey)
                    {
                        Logger.AttStmtVerifierInvalidAttestationStatement(attStmt.GetType().ToString(), AttestationStatementFormat.AndroidKey);
                        return Result<VerifiedAttestationStatement>.Fail();
                    }

                    return await AndroidKeyVerifier.VerifyAsync(context, androidKey, authenticatorData, clientDataHash, cancellationToken);
                }
            case AttestationStatementFormat.AndroidSafetyNet:
                {
                    if (attStmt is not AndroidSafetyNetAttestationStatement androidSafetyNet)
                    {
                        Logger.AttStmtVerifierInvalidAttestationStatement(attStmt.GetType().ToString(), AttestationStatementFormat.AndroidSafetyNet);
                        return Result<VerifiedAttestationStatement>.Fail();
                    }

                    return await AndroidSafetyNetVerifier.VerifyAsync(context, androidSafetyNet, authenticatorData, clientDataHash, cancellationToken);
                }
            case AttestationStatementFormat.FidoU2F:
                {
                    if (attStmt is not FidoU2FAttestationStatement fidoU2F)
                    {
                        Logger.AttStmtVerifierInvalidAttestationStatement(attStmt.GetType().ToString(), AttestationStatementFormat.FidoU2F);
                        return Result<VerifiedAttestationStatement>.Fail();
                    }

                    return await FidoU2FVerifier.VerifyAsync(context, fidoU2F, authenticatorData, clientDataHash, cancellationToken);
                }
            case AttestationStatementFormat.AppleAnonymous:
                {
                    if (attStmt is not AppleAnonymousAttestationStatement apple)
                    {
                        Logger.AttStmtVerifierInvalidAttestationStatement(attStmt.GetType().ToString(), AttestationStatementFormat.AppleAnonymous);
                        return Result<VerifiedAttestationStatement>.Fail();
                    }

                    return await AppleAnonymousVerifier.VerifyAsync(context, apple, authenticatorData, clientDataHash, cancellationToken);
                }
            case AttestationStatementFormat.None:
                {
                    if (attStmt is not NoneAttestationStatement none)
                    {
                        Logger.AttStmtVerifierInvalidAttestationStatement(attStmt.GetType().ToString(), AttestationStatementFormat.None);
                        return Result<VerifiedAttestationStatement>.Fail();
                    }

                    return await NoneVerifier.VerifyAsync(context, none, authenticatorData, clientDataHash, cancellationToken);
                }
            default:
                {
                    Logger.UnknownFmt();
                    return Result<VerifiedAttestationStatement>.Fail();
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
