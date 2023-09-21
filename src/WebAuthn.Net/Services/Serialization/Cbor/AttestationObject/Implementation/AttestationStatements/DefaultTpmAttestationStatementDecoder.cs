using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Implementation.AttestationStatements;

public class DefaultTpmAttestationStatementDecoder : ITpmAttestationStatementDecoder
{
    public Result<TpmAttestationStatement> Decode(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        if (!TryDecodeAlg(attStmt, out var alg, out var algError))
        {
            return Result<TpmAttestationStatement>.Failed(algError);
        }

        if (!TryDecodeSig(attStmt, out var sig, out var sigError))
        {
            return Result<TpmAttestationStatement>.Failed(sigError);
        }

        if (!TryDecodeVer(attStmt, out var ver, out var verError))
        {
            return Result<TpmAttestationStatement>.Failed(verError);
        }

        if (!TryDecodeX5C(attStmt, out var x5C, out var x5CError))
        {
            return Result<TpmAttestationStatement>.Failed(x5CError);
        }

        if (!TryDecodePubArea(attStmt, out var pubArea, out var pubAreaError))
        {
            return Result<TpmAttestationStatement>.Failed(pubAreaError);
        }

        if (!TryDecodeCertInfo(attStmt, out var certInfo, out var certInfoError))
        {
            return Result<TpmAttestationStatement>.Failed(certInfoError);
        }

        var result = new TpmAttestationStatement(
            ver,
            alg.Value,
            x5C,
            sig,
            certInfo,
            pubArea);
        return Result<TpmAttestationStatement>.Success(result);
    }

    private static bool TryDecodeAlg(
        CborMap attStmt,
        [NotNullWhen(true)] out CoseAlgorithmIdentifier? value,
        [NotNullWhen(false)] out string? error)
    {
        var dict = attStmt.Value;
        if (!dict.TryGetValue(new CborTextString("alg"), out var algCbor))
        {
            error = "Failed to find the 'alg' key in attStmt.";
            value = null;
            return false;
        }

        int intAlg;
        if (algCbor is not CborNegativeInteger algCborNegativeInteger)
        {
            if (algCbor is not CborUnsignedInteger algCborUnsignedInteger)
            {
                error = "The value associated with the 'alg' key in the attStmt map contains an invalid data type.";
                value = null;
                return false;
            }

            if (algCborUnsignedInteger.Value > int.MaxValue)
            {
                error = "attStmt contains an unsupported 'alg'.";
                value = null;
                return false;
            }

            intAlg = (int) algCborUnsignedInteger.Value;
        }
        else
        {
            if (algCborNegativeInteger.Value > int.MaxValue)
            {
                error = "attStmt contains an unsupported 'alg'.";
                value = null;
                return false;
            }

            var negativeCborArg = (int) algCborNegativeInteger.Value;
            intAlg = -1 - negativeCborArg;
        }

        var alg = (CoseAlgorithmIdentifier) intAlg;
        if (!Enum.IsDefined(alg))
        {
            error = "attStmt contains an unsupported 'alg'.";
            value = null;
            return false;
        }

        error = null;
        value = alg;
        return true;
    }

    private static bool TryDecodeSig(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[]? value,
        [NotNullWhen(false)] out string? error)
    {
        return TryGetCborByteStringAsByteArray(attStmt, "sig", out value, out error);
    }

    private static bool TryDecodeVer(
        CborMap attStmt,
        [NotNullWhen(true)] out string? value,
        [NotNullWhen(false)] out string? error)
    {
        var dict = attStmt.Value;
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
        value = verCborTextString.Value;
        return true;
    }

    private static bool TryDecodeX5C(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[][]? value,
        [NotNullWhen(false)] out string? error)
    {
        var dict = attStmt.Value;
        if (!dict.TryGetValue(new CborTextString("x5c"), out var x5CCbor))
        {
            error = "Failed to find the 'x5c' key in attStmt.";
            value = null;
            return false;
        }

        if (x5CCbor is not CborArray x5CborArray)
        {
            error = "The value associated with the 'x5c' key in the attStmt map contains an invalid data type.";
            value = null;
            return false;
        }

        var cborArrayItems = x5CborArray.Value;
        var result = new byte[cborArrayItems.Length][];
        for (var i = 0; i < cborArrayItems.Length; i++)
        {
            if (cborArrayItems[i] is not CborByteString cborArrayItemByteString)
            {
                error = "One of the 'x5c' array elements in the attStmt map contains a CBOR element of an invalid type.";
                value = null;
                return false;
            }

            result[i] = cborArrayItemByteString.Value;
        }

        error = null;
        value = result;
        return true;
    }

    private static bool TryDecodePubArea(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[]? value,
        [NotNullWhen(false)] out string? error)
    {
        return TryGetCborByteStringAsByteArray(attStmt, "pubArea", out value, out error);
    }

    private static bool TryDecodeCertInfo(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[]? value,
        [NotNullWhen(false)] out string? error)
    {
        return TryGetCborByteStringAsByteArray(attStmt, "certInfo", out value, out error);
    }

    private static bool TryGetCborByteStringAsByteArray(
        CborMap attStmt,
        string keyName,
        [NotNullWhen(true)] out byte[]? value,
        [NotNullWhen(false)] out string? error)
    {
        var dict = attStmt.Value;
        if (!dict.TryGetValue(new CborTextString(keyName), out var cborValue))
        {
            error = $"Failed to find the '{keyName}' key in attStmt.";
            value = null;
            return false;
        }

        if (cborValue is not CborByteString cborByteString)
        {
            error = $"The value associated with the '{keyName}' key in the attStmt map contains an invalid data type.";
            value = null;
            return false;
        }

        error = null;
        value = cborByteString.Value;
        return true;
    }
}
