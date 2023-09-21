using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Binary.AuthenticatorData;
using WebAuthn.Net.Services.Serialization.Binary.AuthenticatorData.Models;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements.Abstractions;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Format;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Implementation;

public class DefaultAttestationObjectDecoder : IAttestationObjectDecoder
{
    private readonly ICborDecoder _cborDecoder;
    private readonly IAttestationStatementDecoder _attStmtDecoder;
    private readonly IAuthenticatorDataDecoder _authDataDecoder;

    public DefaultAttestationObjectDecoder(
        ICborDecoder cborDecoder,
        IAttestationStatementDecoder attStmtDecoder,
        IAuthenticatorDataDecoder authDataDecoder)
    {
        ArgumentNullException.ThrowIfNull(cborDecoder);
        ArgumentNullException.ThrowIfNull(attStmtDecoder);
        ArgumentNullException.ThrowIfNull(authDataDecoder);
        _cborDecoder = cborDecoder;
        _attStmtDecoder = attStmtDecoder;
        _authDataDecoder = authDataDecoder;
    }

    public Result<DecodedAttestationObject> Decode(byte[] attestationObject)
    {
        var mapResult = TryDecodeMap(attestationObject);
        if (mapResult.HasError)
        {
            return Result<DecodedAttestationObject>.Failed(mapResult.Error);
        }

        var attestationObjectCbor = mapResult.Ok;

        if (!TryDecodeAttestationStatementFormat(attestationObjectCbor, out var fmt, out var fmtError))
        {
            return Result<DecodedAttestationObject>.Failed(fmtError);
        }

        if (!TryDecodeAttestationStatement(attestationObjectCbor, fmt.Value, out var attStmt, out var attStmtError))
        {
            return Result<DecodedAttestationObject>.Failed(attStmtError);
        }

        if (!TryDecodeAuthData(attestationObjectCbor, out var authData, out var authDataError))
        {
            return Result<DecodedAttestationObject>.Failed(authDataError);
        }

        var result = new DecodedAttestationObject(fmt.Value, attStmt, authData);
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

    private static bool TryDecodeAttestationStatementFormat(
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
                value = AttestationStatementFormat.AppleAnonymous;
                error = null;
                return true;
            default:
                value = null;
                error = "The value associated with the 'fmt' key in the attestationObject map contains an unknown attestation statement format.";
                return false;
        }
    }

    private bool TryDecodeAttestationStatement(
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

        var decodeResult = _attStmtDecoder.Decode(attStmtCborMap, format);
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

    private bool TryDecodeAuthData(
        CborMap attStmt,
        [NotNullWhen(true)] out DecodedAuthenticatorData? value,
        [NotNullWhen(false)] out string? error)
    {
        var dict = attStmt.Value;
        if (!dict.TryGetValue(new CborTextString("authData"), out var sigCbor))
        {
            error = "Failed to find the 'authData' key in attestationObject.";
            value = null;
            return false;
        }

        if (sigCbor is not CborByteString sigCborByteString)
        {
            error = "The value associated with the 'authData' key in the attestationObject map contains an invalid data type.";
            value = null;
            return false;
        }

        var decodeResult = _authDataDecoder.Decode(sigCborByteString.Value);
        if (decodeResult.HasError)
        {
            value = null;
            error = decodeResult.Error;
            return false;
        }

        error = null;
        value = decodeResult.Ok;
        return true;
    }
}
