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
    private readonly IPackedAttestationStatementDecoder _packedDecoder;
    private readonly ITpmAttestationStatementDecoder _tpmDecoder;
    private readonly IAndroidKeyAttestationStatementDecoder _androidKeyDecoder;
    private readonly IAndroidSafetyNetAttestationStatementDecoder _androidSafetyNetDecoder;
    private readonly IFidoU2FAttestationStatementDecoder _fidoU2FDecoder;
    private readonly INoneAttestationStatementDecoder _noneDecoder;
    private readonly IAppleAnonymousAttestationStatementDecoder _appleAnonymousDecoder;

    public DefaultAttestationStatementDecoder(
        IPackedAttestationStatementDecoder packedDecoder,
        ITpmAttestationStatementDecoder tpmDecoder,
        IAndroidKeyAttestationStatementDecoder androidKeyDecoder,
        IAndroidSafetyNetAttestationStatementDecoder androidSafetyNetDecoder,
        IFidoU2FAttestationStatementDecoder fidoU2FDecoder,
        INoneAttestationStatementDecoder noneDecoder,
        IAppleAnonymousAttestationStatementDecoder appleAnonymousDecoder)
    {
        ArgumentNullException.ThrowIfNull(packedDecoder);
        ArgumentNullException.ThrowIfNull(tpmDecoder);
        ArgumentNullException.ThrowIfNull(androidKeyDecoder);
        ArgumentNullException.ThrowIfNull(androidSafetyNetDecoder);
        ArgumentNullException.ThrowIfNull(fidoU2FDecoder);
        ArgumentNullException.ThrowIfNull(noneDecoder);
        ArgumentNullException.ThrowIfNull(appleAnonymousDecoder);
        _packedDecoder = packedDecoder;
        _tpmDecoder = tpmDecoder;
        _androidKeyDecoder = androidKeyDecoder;
        _androidSafetyNetDecoder = androidSafetyNetDecoder;
        _fidoU2FDecoder = fidoU2FDecoder;
        _noneDecoder = noneDecoder;
        _appleAnonymousDecoder = appleAnonymousDecoder;
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
            AttestationStatementFormat.Packed => Transform(_packedDecoder.Decode(attStmt)),
            AttestationStatementFormat.Tpm => Transform(_tpmDecoder.Decode(attStmt)),
            AttestationStatementFormat.AndroidKey => Transform(_androidKeyDecoder.Decode(attStmt)),
            AttestationStatementFormat.AndroidSafetynet => Transform(_androidSafetyNetDecoder.Decode(attStmt)),
            AttestationStatementFormat.FidoU2F => Transform(_fidoU2FDecoder.Decode(attStmt)),
            AttestationStatementFormat.None => Transform(_noneDecoder.Decode(attStmt)),
            AttestationStatementFormat.AppleAnonymous => Transform(_appleAnonymousDecoder.Decode(attStmt)),
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
