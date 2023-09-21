using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Implementation.AttestationStatements;

public class DefaultFidoU2FAttestationStatementDecoder : IFidoU2FAttestationStatementDecoder
{
    public Result<FidoU2FAttestationStatement> Decode(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        if (!TryDecodeSig(attStmt, out var sig, out var sigError))
        {
            return Result<FidoU2FAttestationStatement>.Failed(sigError);
        }

        if (!TryDecodeX5C(attStmt, out var x5C, out var x5CError))
        {
            return Result<FidoU2FAttestationStatement>.Failed(x5CError);
        }

        var result = new FidoU2FAttestationStatement(sig, x5C);
        return Result<FidoU2FAttestationStatement>.Success(result);
    }

    private static bool TryDecodeSig(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[]? value,
        [NotNullWhen(false)] out string? error)
    {
        var dict = attStmt.Value;
        if (!dict.TryGetValue(new CborTextString("sig"), out var sigCbor))
        {
            error = "Failed to find the 'sig' key in attStmt.";
            value = null;
            return false;
        }

        if (sigCbor is not CborByteString sigCborByteString)
        {
            error = "The value associated with the 'sig' key in the attStmt map contains an invalid data type.";
            value = null;
            return false;
        }

        error = null;
        value = sigCborByteString.Value;
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
}
