using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.EC2;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.Extensions;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.RSA;
using WebAuthn.Net.Services.Serialization.Cbor.Format;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Cryptography.Cose.Implementation;

public class DefaultCoseKeyDecoder : ICoseKeyDecoder
{
    private readonly ICborDecoder _cborDecoder;

    public DefaultCoseKeyDecoder(ICborDecoder cborDecoder)
    {
        ArgumentNullException.ThrowIfNull(cborDecoder);
        _cborDecoder = cborDecoder;
    }

    public Result<CoseKeyDecodeResult> Decode(byte[] encodedCoseKey)
    {
        var cborResult = _cborDecoder.TryDecode(encodedCoseKey);
        if (cborResult.HasError)
        {
            return Result<CoseKeyDecodeResult>.Failed(cborResult.Error);
        }

        if (!TryVerifyCoseKeyRoot(cborResult.Ok, out var cborCoseKey, out var cborCoseKeyError))
        {
            return Result<CoseKeyDecodeResult>.Failed(cborCoseKeyError);
        }

        if (!TryGetKty(cborCoseKey, out var kty, out var ktyKey, out var ktyError))
        {
            return Result<CoseKeyDecodeResult>.Failed(ktyError);
        }

        if (!cborCoseKey.Remove(ktyKey))
        {
            return Result<CoseKeyDecodeResult>.Failed("Failed to remove the 'kty' key from the object representing COSE_Key.");
        }

        if (!TryGetAlg(cborCoseKey, kty.Value, out var alg, out var algKey, out var algError))
        {
            return Result<CoseKeyDecodeResult>.Failed(algError);
        }

        if (!cborCoseKey.Remove(algKey))
        {
            return Result<CoseKeyDecodeResult>.Failed("Failed to remove the 'alg' key from the object representing COSE_Key.");
        }

        switch (kty.Value)
        {
            case CoseKeyType.EC2:
                {
                    var ec2Result = TryGetEc2Key(alg.Value, cborCoseKey);
                    if (ec2Result.HasError)
                    {
                        return Result<CoseKeyDecodeResult>.Failed(ec2Result.Error);
                    }

                    var result = new CoseKeyDecodeResult(ec2Result.Ok, cborResult.Ok.ConsumedBytes);
                    return Result<CoseKeyDecodeResult>.Success(result);
                }
            case CoseKeyType.RSA:
                {
                    var rsaResult = TryGetRsaKey(alg.Value, cborCoseKey);
                    if (rsaResult.HasError)
                    {
                        return Result<CoseKeyDecodeResult>.Failed(rsaResult.Error);
                    }

                    var result = new CoseKeyDecodeResult(rsaResult.Ok, cborResult.Ok.ConsumedBytes);
                    return Result<CoseKeyDecodeResult>.Success(result);
                }
            default:
                return Result<CoseKeyDecodeResult>.Failed("An unknown 'kty' value has been encountered.");
        }
    }

    private static bool TryVerifyCoseKeyRoot(
        CborRoot root,
        [NotNullWhen(true)] out Dictionary<AbstractCborObject, AbstractCborObject>? cborCoseKey,
        [NotNullWhen(false)] out string? error)
    {
        // https://www.rfc-editor.org/rfc/rfc9052#section-7
        if (root.Root is not CborMap map)
        {
            error = "COSE Key must be represented as a CBOR map.";
            cborCoseKey = null;
            return false;
        }

        var result = new Dictionary<AbstractCborObject, AbstractCborObject>();
        foreach (var (mapKey, mapValue) in map.RawValue)
        {
            // https://www.rfc-editor.org/rfc/rfc9052#section-1.5
            // In a CBOR map defined by this specification, the presence a label that is neither a text string nor an integer is an error.
            var keyType = mapKey.Type;
            if (keyType != CborType.TextString && keyType != CborType.NegativeInteger && keyType != CborType.UnsignedInteger)
            {
                error = "Encountered a label that is neither a string nor an integer";
                cborCoseKey = null;
                return false;
            }

            if (!result.TryAdd(mapKey, mapValue))
            {
                error = "Keys in the map representing the COSE Key in CBOR format must only appear once.";
                cborCoseKey = null;
                return false;
            }
        }

        error = null;
        cborCoseKey = result;
        return true;
    }


    private static bool TryGetKty(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        [NotNullWhen(true)] out CoseKeyType? kty,
        [NotNullWhen(true)] out AbstractCborObject? ktyKey,
        [NotNullWhen(false)] out string? error)
    {
        // https://www.rfc-editor.org/rfc/rfc9052#section-1.5
        // label = int / tstr
        // https://www.rfc-editor.org/rfc/rfc9052#section-7
        // The element "kty" is a required element in a COSE_Key map.
        // COSE_Key = {
        //     1 => tstr / int,          ; kty
        //     ? 2 => bstr,              ; kid
        //     ? 3 => tstr / int,        ; alg
        //     ? 4 => [+ (tstr / int) ], ; key_ops
        //     ? 5 => bstr,              ; Base IV
        //     * label => values
        // }
        // https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
        // Name: kty
        // Label: 1
        // CBOR Type: tstr / int
        // https://www.rfc-editor.org/rfc/rfc9052#section-1.4
        // tstr: A UTF-8 text string (major type 3).
        // int: An unsigned integer or a negative integer.
        // --------------------
        var key = new CborUnsignedInteger((uint) CoseKeyCommonParameter.kty);
        if (!TryGetEnumFromInt(cborCoseKey, "kty", key, out kty, out error))
        {
            ktyKey = null;
            return false;
        }

        ktyKey = key;
        return true;
    }

    private static bool TryGetAlg(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        CoseKeyType kty,
        [NotNullWhen(true)] out CoseAlgorithm? alg,
        [NotNullWhen(true)] out AbstractCborObject? algKey,
        [NotNullWhen(false)] out string? error)
    {
        // https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data
        // The COSE_Key-encoded credential public key MUST contain the "alg" parameter
        // and MUST NOT contain any other OPTIONAL parameters.
        // The "alg" parameter MUST contain a COSEAlgorithmIdentifier value.
        // The encoded credential public key MUST also contain any additional REQUIRED parameters stipulated by the relevant key type specification,
        // i.e., REQUIRED for the key type "kty" and algorithm "alg" (see Section 8 of [RFC8152]).
        // https://www.rfc-editor.org/rfc/rfc9052#section-1.5
        // label = int / tstr
        // https://www.rfc-editor.org/rfc/rfc9052#section-7
        // COSE_Key = {
        //     1 => tstr / int,          ; kty
        //     ? 2 => bstr,              ; kid
        //     ? 3 => tstr / int,        ; alg
        //     ? 4 => [+ (tstr / int) ], ; key_ops
        //     ? 5 => bstr,              ; Base IV
        //     * label => values
        // }
        // https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
        // Name: alg
        // Label: 3
        // CBOR Type: tstr / int
        // https://www.rfc-editor.org/rfc/rfc9052#section-1.4
        // tstr: A UTF-8 text string (major type 3).
        // int: An unsigned integer or a negative integer.
        // --------------------
        // In the current implementation, each kty has its own set of supported algorithms.
        var supportedAlg = kty.GetSupportedAlgorithms();
        var key = new CborUnsignedInteger((uint) CoseKeyCommonParameter.alg);
        if (!TryGetEnumFromInt(cborCoseKey, "alg", key, out alg, out error))
        {
            algKey = null;
            return false;
        }

        if (!supportedAlg.Contains(alg.Value))
        {
            error = "'alg' in COSE_Key was recognized, but is not in the set of valid options for 'kty'.";
            alg = null;
            algKey = null;
            return false;
        }

        algKey = key;
        return true;
    }

    private static Result<CoseEc2Key> TryGetEc2Key(
        CoseAlgorithm alg,
        Dictionary<AbstractCborObject, AbstractCborObject> cborCoseKey)
    {
        if (!TryGetCrv(cborCoseKey, alg, out var crv, out var crvKey, out var crvError))
        {
            return Result<CoseEc2Key>.Failed(crvError);
        }

        if (!cborCoseKey.Remove(crvKey))
        {
            return Result<CoseEc2Key>.Failed("Failed to remove the 'crv' key from the object representing COSE_Key.");
        }

        if (!TryGetEc2XCoordinate(cborCoseKey, out var x, out var xKey, out var xError))
        {
            return Result<CoseEc2Key>.Failed(xError);
        }

        if (!cborCoseKey.Remove(xKey))
        {
            return Result<CoseEc2Key>.Failed("Failed to remove the 'x' key from the object representing COSE_Key.");
        }

        if (!TryGetEc2YCoordinate(cborCoseKey, out var y, out var yKey, out var yError))
        {
            return Result<CoseEc2Key>.Failed(yError);
        }

        if (!cborCoseKey.Remove(yKey))
        {
            return Result<CoseEc2Key>.Failed("Failed to remove the 'y' key from the object representing COSE_Key.");
        }

        if (cborCoseKey.Count > 0)
        {
            return Result<CoseEc2Key>.Failed("The COSE_Key was not properly encoded in the EC2 format, as the map still contains unrecognized keys after the necessary values have been extracted.");
        }

        var result = new CoseEc2Key(alg, crv.Value, x, y);
        return Result<CoseEc2Key>.Success(result);
    }

    private static bool TryGetCrv(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        CoseAlgorithm alg,
        [NotNullWhen(true)] out CoseEllipticCurve? crv,
        [NotNullWhen(true)] out AbstractCborObject? crvKey,
        [NotNullWhen(false)] out string? error)
    {
        // https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1
        // This document defines ECDSA as working only with the curves P-256, P-384, and P-521.
        // This document requires that the curves be encoded using the "EC2" (two coordinate elliptic curve) key type.
        // Implementations need to check that the key type and curve are correct when creating and verifying a signature.
        // In order to promote interoperability, it is suggested that
        // SHA-256 be used only with curve P-256,
        // SHA-384 be used only with curve P-384,
        // and SHA-512 be used only with curve P-521.
        // This is aligned with the recommendation in Section 4 of [RFC5480].
        // https://www.rfc-editor.org/rfc/rfc9052#section-1.5
        // label = int / tstr
        // https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
        // Key Type: 2 (EC2)
        // Name: crv
        // Label: -1
        // CBOR Type: int / tstr
        // https://www.rfc-editor.org/rfc/rfc9052#section-1.4
        // tstr: A UTF-8 text string (major type 3).
        // int: An unsigned integer or a negative integer.
        // --------------------
        // In the current implementation, each kty has its own set of supported algorithms.

        if (!alg.TryGetSupportedEllipticCurves(out var supportedCrv))
        {
            error = "Failed to determine the set of supported 'crv' values for the specified 'alg'.";
            crv = null;
            crvKey = null;
            return false;
        }

        var key = new CborNegativeInteger((int) CoseEc2KeyParameter.crv);
        if (!TryGetEnumFromInt(cborCoseKey, "crv", key, out crv, out error))
        {
            crvKey = null;
            return false;
        }

        if (!supportedCrv.Contains(crv.Value))
        {
            error = "'crv' in COSE_Key was recognized, but is not in the set of valid options for 'alg'.";
            crv = null;
            crvKey = null;
            return false;
        }

        crvKey = key;
        return true;
    }

    private static bool TryGetEc2XCoordinate(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        [NotNullWhen(true)] out byte[]? x,
        [NotNullWhen(true)] out AbstractCborObject? xKey,
        [NotNullWhen(false)] out string? error)
    {
        // https://www.rfc-editor.org/rfc/rfc9052#section-1.5
        // label = int / tstr
        // https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
        // Key Type: 2 (EC2)
        // Name: x
        // Label: -2
        // CBOR Type: bstr
        // https://www.rfc-editor.org/rfc/rfc9052#section-1.4
        // bstr: Byte string (major type 2).
        var key = new CborNegativeInteger((int) CoseEc2KeyParameter.x);
        if (!TryGetBytesFromByteString(cborCoseKey, "x", key, out x, out error))
        {
            xKey = null;
            return false;
        }

        xKey = key;
        return true;
    }

    private static bool TryGetEc2YCoordinate(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        [NotNullWhen(true)] out byte[]? y,
        [NotNullWhen(true)] out AbstractCborObject? yKey,
        [NotNullWhen(false)] out string? error)
    {
        // https://www.rfc-editor.org/rfc/rfc9052#section-1.5
        // label = int / tstr
        // https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
        // Key Type: 2 (EC2)
        // Name: y
        // Label: -3
        // CBOR Type: bstr / bool
        // https://www.rfc-editor.org/rfc/rfc9052#section-1.4
        // bstr: Byte string (major type 2).
        // bool: A boolean value (true: major type 7, value 21; false: major type 7, value 20).
        var key = new CborNegativeInteger((int) CoseEc2KeyParameter.y);
        if (!TryGetBytesFromByteString(cborCoseKey, "y", key, out y, out error))
        {
            yKey = null;
            return false;
        }

        yKey = key;
        return true;
    }

    private static Result<CoseRsaKey> TryGetRsaKey(
        CoseAlgorithm alg,
        Dictionary<AbstractCborObject, AbstractCborObject> cborCoseKey)
    {
        if (!TryGetRsaModulusN(cborCoseKey, out var n, out var nKey, out var nError))
        {
            return Result<CoseRsaKey>.Failed(nError);
        }

        if (!cborCoseKey.Remove(nKey))
        {
            return Result<CoseRsaKey>.Failed("Failed to remove the 'n' key from the object representing COSE_Key.");
        }

        if (!TryGetRsaPublicExponentE(cborCoseKey, out var e, out var eKey, out var eError))
        {
            return Result<CoseRsaKey>.Failed(eError);
        }

        if (!cborCoseKey.Remove(eKey))
        {
            return Result<CoseRsaKey>.Failed("Failed to remove the 'e' key from the object representing COSE_Key.");
        }

        if (cborCoseKey.Count > 0)
        {
            return Result<CoseRsaKey>.Failed("The COSE_Key was not properly encoded in the RSA format, as the map still contains unrecognized keys after the necessary values have been extracted.");
        }

        var result = new CoseRsaKey(alg, n, e);
        return Result<CoseRsaKey>.Success(result);
    }

    private static bool TryGetRsaModulusN(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        [NotNullWhen(true)] out byte[]? n,
        [NotNullWhen(true)] out AbstractCborObject? nKey,
        [NotNullWhen(false)] out string? error)
    {
        // https://www.rfc-editor.org/rfc/rfc9052#section-1.5
        // label = int / tstr
        // https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
        // Key Type: 3 (RSA)
        // Name: n
        // Label: -1
        // CBOR Type: bstr
        // https://www.rfc-editor.org/rfc/rfc9052#section-1.4
        // bstr: Byte string (major type 2).
        var key = new CborNegativeInteger((int) CoseRsaKeyParameter.n);
        if (!TryGetBytesFromByteString(cborCoseKey, "n", key, out n, out error))
        {
            nKey = null;
            return false;
        }

        nKey = key;
        return true;
    }

    private static bool TryGetRsaPublicExponentE(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        [NotNullWhen(true)] out byte[]? e,
        [NotNullWhen(true)] out AbstractCborObject? eKey,
        [NotNullWhen(false)] out string? error)
    {
        // https://www.rfc-editor.org/rfc/rfc9052#section-1.5
        // label = int / tstr
        // https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
        // Key Type: 3 (RSA)
        // Name: e
        // Label: -2
        // CBOR Type: bstr
        // https://www.rfc-editor.org/rfc/rfc9052#section-1.4
        // bstr: Byte string (major type 2).
        var key = new CborNegativeInteger((int) CoseRsaKeyParameter.e);
        if (!TryGetBytesFromByteString(cborCoseKey, "e", key, out e, out error))
        {
            eKey = null;
            return false;
        }

        eKey = key;
        return true;
    }

    private static bool TryGetEnumFromInt<TEnum>(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        string fieldName,
        AbstractCborObject key,
        [NotNullWhen(true)] out TEnum? value,
        [NotNullWhen(false)] out string? error) where TEnum : struct, Enum
    {
        if (!cborCoseKey.TryGetValue(key, out var cborValue))
        {
            error = $"Failed to find the '{fieldName}' key in COSE_Key.";
            value = null;
            return false;
        }

        if (cborValue is not AbstractCborInteger intCborValue)
        {
            error = $"An invalid data type is used for the '{fieldName}' value in COSE_Key.";
            value = null;
            return false;
        }

        if (!intCborValue.TryReadAsInt32(out var ktyInt))
        {
            error = $"A value out of the acceptable range is specified for the '{fieldName}' in COSE_Key.";
            value = null;
            return false;
        }

        if (Enum.IsDefined(typeof(TEnum), ktyInt.Value))
        {
            error = null;
            value = (TEnum) Enum.ToObject(typeof(TEnum), ktyInt.Value);
            return true;
        }

        error = $"An invalid value is specified for the '{fieldName}' in COSE_Key.";
        value = null;
        return false;
    }

    private static bool TryGetBytesFromByteString(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        string fieldName,
        AbstractCborObject key,
        [NotNullWhen(true)] out byte[]? value,
        [NotNullWhen(false)] out string? error)
    {
        if (!cborCoseKey.TryGetValue(key, out var cborValue))
        {
            error = $"Failed to find the '{fieldName}' key in COSE_Key.";
            value = null;
            return false;
        }

        if (cborValue is not CborByteString byteStringCborValue)
        {
            error = $"An invalid data type is used for the '{fieldName}' value in COSE_Key.";
            value = null;
            return false;
        }

        error = null;
        value = byteStringCborValue.RawValue;
        return true;
    }
}
