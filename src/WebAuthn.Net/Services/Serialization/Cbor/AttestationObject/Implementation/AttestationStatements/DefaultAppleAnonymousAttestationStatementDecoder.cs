using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Implementation.AttestationStatements;

public class DefaultAppleAnonymousAttestationStatementDecoder : IAppleAnonymousAttestationStatementDecoder
{
    public Result<AppleAnonymousAttestationStatement> Decode(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        if (!TryDecodeAlg(attStmt, out var alg, out var algError))
        {
            return Result<AppleAnonymousAttestationStatement>.Failed(algError);
        }

        if (!TryDecodeX5C(attStmt, out var x5C, out var x5CError))
        {
            return Result<AppleAnonymousAttestationStatement>.Failed(x5CError);
        }

        var result = new AppleAnonymousAttestationStatement(alg.Value, x5C);
        return Result<AppleAnonymousAttestationStatement>.Success(result);
    }

    private static bool TryDecodeAlg(
        CborMap attStmt,
        [NotNullWhen(true)] out CoseAlgorithm? value,
        [NotNullWhen(false)] out string? error)
    {
        var dict = attStmt.RawValue;
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

            if (algCborUnsignedInteger.RawValue > int.MaxValue)
            {
                error = "attStmt contains an unsupported 'alg'.";
                value = null;
                return false;
            }

            intAlg = (int) algCborUnsignedInteger.RawValue;
        }
        else
        {
            if (algCborNegativeInteger.RawValue > int.MaxValue)
            {
                error = "attStmt contains an unsupported 'alg'.";
                value = null;
                return false;
            }

            var negativeCborArg = (int) algCborNegativeInteger.RawValue;
            intAlg = -1 - negativeCborArg;
        }

        var alg = (CoseAlgorithm) intAlg;
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

    private static bool TryDecodeX5C(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[][]? value,
        [NotNullWhen(false)] out string? error)
    {
        var dict = attStmt.RawValue;
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

        var cborArrayItems = x5CborArray.RawValue;
        var result = new byte[cborArrayItems.Length][];
        for (var i = 0; i < cborArrayItems.Length; i++)
        {
            if (cborArrayItems[i] is not CborByteString cborArrayItemByteString)
            {
                error = "One of the 'x5c' array elements in the attStmt map contains a CBOR element of an invalid type.";
                value = null;
                return false;
            }

            result[i] = cborArrayItemByteString.RawValue;
        }

        error = null;
        value = result;
        return true;
    }
}
