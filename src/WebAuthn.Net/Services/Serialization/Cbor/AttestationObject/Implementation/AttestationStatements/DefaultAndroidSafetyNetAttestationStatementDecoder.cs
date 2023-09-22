using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Implementation.AttestationStatements;

public class DefaultAndroidSafetyNetAttestationStatementDecoder : IAndroidSafetyNetAttestationStatementDecoder
{
    public Result<AndroidSafetyNetAttestationStatement> Decode(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);

        if (!TryDecodeVer(attStmt, out var ver, out var verError))
        {
            return Result<AndroidSafetyNetAttestationStatement>.Failed(verError);
        }

        if (!TryDecodeResponse(attStmt, out var response, out var responseError))
        {
            return Result<AndroidSafetyNetAttestationStatement>.Failed(responseError);
        }

        var result = new AndroidSafetyNetAttestationStatement(ver, response);
        return Result<AndroidSafetyNetAttestationStatement>.Success(result);
    }

    private static bool TryDecodeVer(
        CborMap attStmt,
        [NotNullWhen(true)] out string? value,
        [NotNullWhen(false)] out string? error)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("ver"), out var verCbor))
        {
            error = "Failed to find the 'ver' key in attStmt.";
            value = null;
            return false;
        }

        if (verCbor is not CborTextString verCborTextString)
        {
            error = "The value associated with the 'ver' key in the attStmt map contains an invalid data type.";
            value = null;
            return false;
        }

        error = null;
        value = verCborTextString.RawValue;
        return true;
    }

    private static bool TryDecodeResponse(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[]? value,
        [NotNullWhen(false)] out string? error)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("response"), out var responseCbor))
        {
            error = "Failed to find the 'response' key in attStmt.";
            value = null;
            return false;
        }

        if (responseCbor is not CborByteString responseCborByteString)
        {
            error = "The value associated with the 'response' key in the attStmt map contains an invalid data type.";
            value = null;
            return false;
        }

        error = null;
        value = responseCborByteString.RawValue;
        return true;
    }
}
