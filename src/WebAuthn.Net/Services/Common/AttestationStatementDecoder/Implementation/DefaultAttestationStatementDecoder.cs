using System;
using System.ComponentModel;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Abstractions.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation;

/// <summary>
///     Default implementation of <see cref="IAttestationStatementDecoder" />.
/// </summary>
public class DefaultAttestationStatementDecoder : IAttestationStatementDecoder
{
    /// <summary>
    ///     Constructs <see cref="DefaultAttestationStatementDecoder" />.
    /// </summary>
    /// <param name="androidKeyDecoder">
    ///     Decoder of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-key-attestation">Android Key attestation statement</a> into a typed representation.
    /// </param>
    /// <param name="androidSafetyNetDecoder">
    ///     Decoder of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-safetynet-attestation">Android SafetyNet attestation statement</a> into a typed representation.
    /// </param>
    /// <param name="appleAnonymousDecoder">
    ///     Decoder of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-apple-anonymous-attestation">Apple Anonymous attestation statement</a> into a typed representation.
    /// </param>
    /// <param name="fidoU2FDecoder">Decoder of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-fido-u2f-attestation">FIDO U2F attestation statement</a> into a typed representation.</param>
    /// <param name="noneDecoder">Decoder of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-none-attestation">None attestation statement</a> into a typed representation.</param>
    /// <param name="packedDecoder">Decoder of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-packed-attestation">Packed attestation statement</a> into a typed representation.</param>
    /// <param name="tpmDecoder">Decoder of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-tpm-attestation">TPM attestation statement</a> into a typed representation.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultAttestationStatementDecoder(
        IAndroidKeyAttestationStatementDecoder androidKeyDecoder,
        IAndroidSafetyNetAttestationStatementDecoder androidSafetyNetDecoder,
        IAppleAnonymousAttestationStatementDecoder appleAnonymousDecoder,
        IFidoU2FAttestationStatementDecoder fidoU2FDecoder,
        INoneAttestationStatementDecoder noneDecoder,
        IPackedAttestationStatementDecoder packedDecoder,
        ITpmAttestationStatementDecoder tpmDecoder)
    {
        ArgumentNullException.ThrowIfNull(androidKeyDecoder);
        ArgumentNullException.ThrowIfNull(androidSafetyNetDecoder);
        ArgumentNullException.ThrowIfNull(appleAnonymousDecoder);
        ArgumentNullException.ThrowIfNull(fidoU2FDecoder);
        ArgumentNullException.ThrowIfNull(noneDecoder);
        ArgumentNullException.ThrowIfNull(packedDecoder);
        ArgumentNullException.ThrowIfNull(tpmDecoder);
        AndroidKeyDecoder = androidKeyDecoder;
        AndroidSafetyNetDecoder = androidSafetyNetDecoder;
        AppleAnonymousDecoder = appleAnonymousDecoder;
        FidoU2FDecoder = fidoU2FDecoder;
        NoneDecoder = noneDecoder;
        PackedDecoder = packedDecoder;
        TpmDecoder = tpmDecoder;
    }

    /// <summary>
    ///     Decoder of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-key-attestation">Android Key attestation statement</a> into a typed representation.
    /// </summary>
    protected IAndroidKeyAttestationStatementDecoder AndroidKeyDecoder { get; }

    /// <summary>
    ///     Decoder of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-safetynet-attestation">Android SafetyNet attestation statement</a> into a typed representation.
    /// </summary>
    protected IAndroidSafetyNetAttestationStatementDecoder AndroidSafetyNetDecoder { get; }

    /// <summary>
    ///     Decoder of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-apple-anonymous-attestation">Apple Anonymous attestation statement</a> into a typed representation.
    /// </summary>
    protected IAppleAnonymousAttestationStatementDecoder AppleAnonymousDecoder { get; }

    /// <summary>
    ///     Decoder of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-fido-u2f-attestation">FIDO U2F attestation statement</a> into a typed representation.
    /// </summary>
    protected IFidoU2FAttestationStatementDecoder FidoU2FDecoder { get; }

    /// <summary>
    ///     Decoder of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-none-attestation">None attestation statement</a> into a typed representation.
    /// </summary>
    protected INoneAttestationStatementDecoder NoneDecoder { get; }

    /// <summary>
    ///     Decoder of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-packed-attestation">Packed attestation statement</a> into a typed representation.
    /// </summary>
    protected IPackedAttestationStatementDecoder PackedDecoder { get; }

    /// <summary>
    ///     Decoder of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-tpm-attestation">TPM attestation statement</a> into a typed representation.
    /// </summary>
    protected ITpmAttestationStatementDecoder TpmDecoder { get; }

    /// <inheritdoc />
    public virtual Result<AbstractAttestationStatement> Decode(
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
            AttestationStatementFormat.Packed => Transform(PackedDecoder.Decode(attStmt)),
            AttestationStatementFormat.Tpm => Transform(TpmDecoder.Decode(attStmt)),
            AttestationStatementFormat.AndroidKey => Transform(AndroidKeyDecoder.Decode(attStmt)),
            AttestationStatementFormat.AndroidSafetyNet => Transform(AndroidSafetyNetDecoder.Decode(attStmt)),
            AttestationStatementFormat.FidoU2F => Transform(FidoU2FDecoder.Decode(attStmt)),
            AttestationStatementFormat.None => Transform(NoneDecoder.Decode(attStmt)),
            AttestationStatementFormat.AppleAnonymous => Transform(AppleAnonymousDecoder.Decode(attStmt)),
            _ => throw new ArgumentOutOfRangeException(nameof(attestationStatementFormat), attestationStatementFormat, null)
        };
    }

    private static Result<AbstractAttestationStatement> Transform<TSource>(Result<TSource> source)
        where TSource : AbstractAttestationStatement
    {
        return source.HasError
            ? Result<AbstractAttestationStatement>.Fail()
            : Result<AbstractAttestationStatement>.Success(source.Ok);
    }
}
