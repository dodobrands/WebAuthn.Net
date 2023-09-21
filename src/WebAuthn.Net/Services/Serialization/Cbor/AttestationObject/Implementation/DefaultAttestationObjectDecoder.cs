using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements.Abstractions;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Format;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Implementation;

public class DefaultAttestationObjectDecoder : IAttestationObjectDecoder
{
    private readonly IAttestationStatementDecoder _attestationStatementDecoder;
    private readonly ICborDecoder _cborDecoder;

    public DefaultAttestationObjectDecoder(
        ICborDecoder cborDecoder,
        IAttestationStatementDecoder attestationStatementDecoder)
    {
        ArgumentNullException.ThrowIfNull(cborDecoder);
        ArgumentNullException.ThrowIfNull(attestationStatementDecoder);
        _cborDecoder = cborDecoder;
        _attestationStatementDecoder = attestationStatementDecoder;
    }

    public Result<DecodedAttestationObject> Decode(byte[] attestationObject)
    {
        var mapResult = TryDecodeMap(attestationObject);
        if (mapResult.HasError)
        {
            return Result<DecodedAttestationObject>.Failed(mapResult.Error);
        }

        var attestationObjectCbor = mapResult.Ok;

        if (!TryGetAttestationStatementFormat(attestationObjectCbor, out var fmt, out var fmtError))
        {
            return Result<DecodedAttestationObject>.Failed(fmtError);
        }

        if (!TryGetAttestationStatement(attestationObjectCbor, fmt.Value, out var attestationStatement, out var attStmtError))
        {
            return Result<DecodedAttestationObject>.Failed(attStmtError);
        }

        var result = new DecodedAttestationObject(fmt.Value, attestationStatement);
        return Result<DecodedAttestationObject>.Success(result);
    }

    private Result<CborMap> TryDecodeMap(byte[] attestationObject)
    {
        var attestationObjectCborDecode = _cborDecoder.TryDecode(attestationObject);
        if (attestationObjectCborDecode.HasError)
        {
            return Result<CborMap>.Failed(attestationObjectCborDecode.Error);
        }

        var attestationObjectCborRoot = attestationObjectCborDecode.Ok.Root;
        if (attestationObjectCborRoot is not CborMap attestationObjectCborMap)
        {
            return Result<CborMap>.Failed("While decoding the attestationObject, an incorrect type of CBOR format object was received.");
        }

        return Result<CborMap>.Success(attestationObjectCborMap);
    }

    private static bool TryGetAttestationStatementFormat(
        CborMap attestationObjectCborMap,
        [NotNullWhen(true)] out AttestationStatementFormat? value,
        [NotNullWhen(false)] out string? error)
    {
        var dict = attestationObjectCborMap.Value;
        if (!dict.TryGetValue(new CborTextString("fmt"), out var fmtCbor))
        {
            value = null;
            error = "Failed to find the 'fmt' key in attestationObject.";
            return false;
        }

        if (fmtCbor is not CborTextString fmtCborText)
        {
            value = null;
            error = "The value associated with the 'fmt' key in the attestationObject map contains an invalid data type.";
            return false;
        }

        switch (fmtCborText.Value)
        {
            case "none":
                value = AttestationStatementFormat.None;
                error = null;
                return true;
            case "packed":
                value = AttestationStatementFormat.Packed;
                error = null;
                return true;
            case "tpm":
                value = AttestationStatementFormat.Tpm;
                error = null;
                return true;
            case "android-key":
                value = AttestationStatementFormat.AndroidKey;
                error = null;
                return true;
            case "android-safetynet":
                value = AttestationStatementFormat.AndroidSafetynet;
                error = null;
                return true;
            case "fido-u2f":
                value = AttestationStatementFormat.FidoU2F;
                error = null;
                return true;
            case "apple":
                value = AttestationStatementFormat.Apple;
                error = null;
                return true;
            default:
                value = null;
                error = "The value associated with the 'fmt' key in the attestationObject map contains an unknown attestation statement format.";
                return false;
        }
    }

    private bool TryGetAttestationStatement(
        CborMap attestationObjectCborMap,
        AttestationStatementFormat format,
        [NotNullWhen(true)] out AbstractAttestationStatement? value,
        [NotNullWhen(false)] out string? error)
    {
        var dict = attestationObjectCborMap.Value;
        if (!dict.TryGetValue(new CborTextString("attStmt"), out var attStmtCbor))
        {
            value = null;
            error = "Failed to find the 'attStmt' key in attestationObject.";
            return false;
        }

        if (attStmtCbor is not CborMap attStmtCborMap)
        {
            value = null;
            error = "The value associated with the 'attStmt' key in the attestationObject map contains an invalid data type.";
            return false;
        }

        var decodeResult = _attestationStatementDecoder.Decode(attStmtCborMap, format);
        if (decodeResult.HasError)
        {
            value = null;
            error = decodeResult.Error;
            return false;
        }

        value = decodeResult.Ok;
        error = null;
        return true;
    }
}
