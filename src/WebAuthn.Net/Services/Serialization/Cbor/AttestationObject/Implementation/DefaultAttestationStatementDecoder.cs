using System;
using System.ComponentModel;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements.Abstractions;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Implementation;

public class DefaultAttestationStatementDecoder : IAttestationStatementDecoder
{
    private readonly IAndroidKeyAttestationStatementDecoder _androidKeyDecoder;
    private readonly IAndroidSafetyNetAttestationStatementDecoder _androidSafetyNetDecoder;
    private readonly IAppleAnonymousAttestationStatementDecoder _appleDecoder;
    private readonly IFidoU2FAttestationStatementDecoder _fidoU2FDecoder;
    private readonly INoneAttestationStatementDecoder _noneDecoder;
    private readonly IPackedAttestationStatementDecoder _packedDecoder;
    private readonly ITpmAttestationStatementDecoder _tpmDecoder;

    public DefaultAttestationStatementDecoder(
        IPackedAttestationStatementDecoder packedDecoder,
        INoneAttestationStatementDecoder noneDecoder,
        ITpmAttestationStatementDecoder tpmDecoder,
        IAndroidSafetyNetAttestationStatementDecoder androidSafetyNetDecoder,
        IAndroidKeyAttestationStatementDecoder androidKeyDecoder,
        IFidoU2FAttestationStatementDecoder fidoU2FDecoder,
        IAppleAnonymousAttestationStatementDecoder appleDecoder)
    {
        ArgumentNullException.ThrowIfNull(packedDecoder);
        _packedDecoder = packedDecoder;
        _noneDecoder = noneDecoder;
        _tpmDecoder = tpmDecoder;
        _androidSafetyNetDecoder = androidSafetyNetDecoder;
        _androidKeyDecoder = androidKeyDecoder;
        _fidoU2FDecoder = fidoU2FDecoder;
        _appleDecoder = appleDecoder;
    }

    public Result<AbstractAttestationStatement> Decode(
        CborMap attStmt,
        AttestationStatementFormat attestationStatementFormat)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        if (!Enum.IsDefined(typeof(AttestationStatementFormat), attestationStatementFormat))
        {
            throw new InvalidEnumArgumentException(nameof(attestationStatementFormat), (int) attestationStatementFormat, typeof(AttestationStatementFormat));
        }

        return attestationStatementFormat switch
        {
            AttestationStatementFormat.None => Transform(_noneDecoder.Decode(attStmt)),
            AttestationStatementFormat.Packed => Transform(_packedDecoder.Decode(attStmt)),
            AttestationStatementFormat.Tpm => Transform(_tpmDecoder.Decode(attStmt)),
            AttestationStatementFormat.AndroidKey => Transform(_androidKeyDecoder.Decode(attStmt)),
            AttestationStatementFormat.AndroidSafetynet => Transform(_androidSafetyNetDecoder.Decode(attStmt)),
            AttestationStatementFormat.FidoU2F => Transform(_fidoU2FDecoder.Decode(attStmt)),
            AttestationStatementFormat.Apple => Transform(_appleDecoder.Decode(attStmt)),
            _ => throw new ArgumentOutOfRangeException(nameof(attestationStatementFormat), attestationStatementFormat, null)
        };
    }

    private static Result<AbstractAttestationStatement> Transform<TSource>(Result<TSource> source)
        where TSource : AbstractAttestationStatement
    {
        return source.HasError
            ? Result<AbstractAttestationStatement>.Failed(source.Error)
            : Result<AbstractAttestationStatement>.Success(source.Ok);
    }
}
