using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.EC2;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.Extensions;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.RSA;
using WebAuthn.Net.Services.Serialization.Cbor;
using WebAuthn.Net.Services.Serialization.Cbor.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Cryptography.Cose.Implementation;

public class DefaultCoseKeyDecoder : ICoseKeyDecoder
{
    private readonly ICborDecoder _cborDecoder;
    private readonly ILogger<DefaultCoseKeyDecoder> _logger;

    public DefaultCoseKeyDecoder(ICborDecoder cborDecoder, ILogger<DefaultCoseKeyDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(cborDecoder);
        ArgumentNullException.ThrowIfNull(logger);
        _cborDecoder = cborDecoder;
        _logger = logger;
    }

    public Result<CoseKeyDecodeResult> Decode(byte[] encodedCoseKey)
    {
        var cborResult = _cborDecoder.Decode(encodedCoseKey);
        if (cborResult.HasError)
        {
            _logger.DecodeFailure();
            return Result<CoseKeyDecodeResult>.Fail();
        }

        if (!TryGetCoseKeyRoot(cborResult.Ok, out var cborCoseKey))
        {
            _logger.CborMapObtainingFailure();
            return Result<CoseKeyDecodeResult>.Fail();
        }

        if (!TryGetKty(cborCoseKey, out var kty, out var ktyKey))
        {
            _logger.KtyObtainingFailure();
            return Result<CoseKeyDecodeResult>.Fail();
        }

        if (!cborCoseKey.Remove(ktyKey))
        {
            _logger.KtyRemoveFailure();
            return Result<CoseKeyDecodeResult>.Fail();
        }

        if (!TryGetAlg(cborCoseKey, kty.Value, out var alg, out var algKey))
        {
            _logger.AlgObtainingFailure();
            return Result<CoseKeyDecodeResult>.Fail();
        }

        if (!cborCoseKey.Remove(algKey))
        {
            _logger.AlgRemoveFailure();
            return Result<CoseKeyDecodeResult>.Fail();
        }

        switch (kty.Value)
        {
            case CoseKeyType.EC2:
                {
                    var ec2Result = TryGetEc2Key(alg.Value, cborCoseKey);
                    if (ec2Result.HasError)
                    {
                        _logger.Ec2KeyObtainingFailure(kty.Value);
                        return Result<CoseKeyDecodeResult>.Fail();
                    }

                    var result = new CoseKeyDecodeResult(ec2Result.Ok, cborResult.Ok.BytesConsumed);
                    return Result<CoseKeyDecodeResult>.Success(result);
                }
            case CoseKeyType.RSA:
                {
                    var rsaResult = TryGetRsaKey(alg.Value, cborCoseKey);
                    if (rsaResult.HasError)
                    {
                        _logger.RsaKeyObtainingFailure(kty.Value);
                        return Result<CoseKeyDecodeResult>.Fail();
                    }

                    var result = new CoseKeyDecodeResult(rsaResult.Ok, cborResult.Ok.BytesConsumed);
                    return Result<CoseKeyDecodeResult>.Success(result);
                }
            default:
                {
                    _logger.UnknownKty();
                    return Result<CoseKeyDecodeResult>.Fail();
                }
        }
    }

    private bool TryGetCoseKeyRoot(
        CborRoot root,
        [NotNullWhen(true)] out Dictionary<AbstractCborObject, AbstractCborObject>? cborCoseKey)
    {
        // https://www.rfc-editor.org/rfc/rfc9052#section-7
        if (root.Root is not CborMap map)
        {
            _logger.CoseKeyMustBeCborMap();
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
                _logger.InvalidLabel();
                cborCoseKey = null;
                return false;
            }

            if (!result.TryAdd(mapKey, mapValue))
            {
                _logger.DuplicateKey();
                cborCoseKey = null;
                return false;
            }
        }

        cborCoseKey = result;
        return true;
    }

    private bool TryGetKty(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        [NotNullWhen(true)] out CoseKeyType? kty,
        [NotNullWhen(true)] out AbstractCborObject? ktyKey)
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
        if (!TryGetEnumFromInt(cborCoseKey, "kty", key, out kty))
        {
            ktyKey = null;
            return false;
        }

        ktyKey = key;
        return true;
    }

    private bool TryGetAlg(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        CoseKeyType kty,
        [NotNullWhen(true)] out CoseAlgorithm? alg,
        [NotNullWhen(true)] out AbstractCborObject? algKey)
    {
        // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attested-credential-data
        // The COSE_Key-encoded credential public key MUST contain the "alg" parameter and MUST NOT contain any other OPTIONAL parameters.
        // The "alg" parameter MUST contain a COSEAlgorithmIdentifier value.
        // The encoded credential public key MUST also contain any additional REQUIRED parameters stipulated by the relevant key type specification,
        // i.e., REQUIRED for the key type "kty" and algorithm "alg" (see Section 2 of [RFC9053]).
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
        if (!TryGetEnumFromInt(cborCoseKey, "alg", key, out alg))
        {
            algKey = null;
            return false;
        }

        if (!supportedAlg.Contains(alg.Value))
        {
            _logger.AlgOutOfRangeForKty(alg.Value, kty);
            alg = null;
            algKey = null;
            return false;
        }

        algKey = key;
        return true;
    }

    private Result<CoseEc2Key> TryGetEc2Key(
        CoseAlgorithm alg,
        Dictionary<AbstractCborObject, AbstractCborObject> cborCoseKey)
    {
        if (!TryGetCrv(cborCoseKey, alg, out var crv, out var crvKey))
        {
            _logger.CrvObtainingFailure();
            return Result<CoseEc2Key>.Fail();
        }

        if (!cborCoseKey.Remove(crvKey))
        {
            _logger.CrvRemoveFailure();
            return Result<CoseEc2Key>.Fail();
        }

        if (!TryGetEc2XCoordinate(cborCoseKey, out var x, out var xKey))
        {
            _logger.XCoordinateObtainingFailure();
            return Result<CoseEc2Key>.Fail();
        }

        if (!cborCoseKey.Remove(xKey))
        {
            _logger.XCoordinateRemoveFailure();
            return Result<CoseEc2Key>.Fail();
        }

        if (!TryGetEc2YCoordinate(cborCoseKey, out var y, out var yKey))
        {
            _logger.YCoordinateObtainingFailure();
            return Result<CoseEc2Key>.Fail();
        }

        if (!cborCoseKey.Remove(yKey))
        {
            _logger.YCoordinateRemoveFailure();
            return Result<CoseEc2Key>.Fail();
        }

        if (cborCoseKey.Count > 0)
        {
            _logger.Ec2UnrecognizedKeysRemainFailure();
            return Result<CoseEc2Key>.Fail();
        }

        var result = new CoseEc2Key(alg, crv.Value, x, y);
        return Result<CoseEc2Key>.Success(result);
    }

    private bool TryGetCrv(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        CoseAlgorithm alg,
        [NotNullWhen(true)] out CoseEllipticCurve? crv,
        [NotNullWhen(true)] out AbstractCborObject? crvKey)
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
            _logger.NoEllipticCurvesForAlg(alg);
            crv = null;
            crvKey = null;
            return false;
        }

        var key = new CborNegativeInteger((int) CoseEc2KeyParameter.crv);
        if (!TryGetEnumFromInt(cborCoseKey, "crv", key, out crv))
        {
            crvKey = null;
            return false;
        }

        if (!supportedCrv.Contains(crv.Value))
        {
            _logger.DisallowedEllipticCurveForAlg(alg, crv.Value);
            crv = null;
            crvKey = null;
            return false;
        }

        crvKey = key;
        return true;
    }

    private bool TryGetEc2XCoordinate(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        [NotNullWhen(true)] out byte[]? x,
        [NotNullWhen(true)] out AbstractCborObject? xKey)
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
        if (!TryGetBytesFromByteString(cborCoseKey, "x", key, out x))
        {
            xKey = null;
            return false;
        }

        xKey = key;
        return true;
    }

    private bool TryGetEc2YCoordinate(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        [NotNullWhen(true)] out byte[]? y,
        [NotNullWhen(true)] out AbstractCborObject? yKey)
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
        if (!TryGetBytesFromByteString(cborCoseKey, "y", key, out y))
        {
            yKey = null;
            return false;
        }

        yKey = key;
        return true;
    }

    private Result<CoseRsaKey> TryGetRsaKey(
        CoseAlgorithm alg,
        Dictionary<AbstractCborObject, AbstractCborObject> cborCoseKey)
    {
        if (!TryGetRsaModulusN(cborCoseKey, out var modulusN, out var nKey))
        {
            _logger.RsaModulusNObtainingFailure();
            return Result<CoseRsaKey>.Fail();
        }

        if (!cborCoseKey.Remove(nKey))
        {
            _logger.RsaModulusNRemoveFailure();
            return Result<CoseRsaKey>.Fail();
        }

        if (!TryGetRsaPublicExponentE(cborCoseKey, out var publicExponentE, out var eKey))
        {
            _logger.RsaPublicExponentEObtainingFailure();
            return Result<CoseRsaKey>.Fail();
        }

        if (!cborCoseKey.Remove(eKey))
        {
            _logger.RsaPublicExponentERemoveFailure();
            return Result<CoseRsaKey>.Fail();
        }

        if (cborCoseKey.Count > 0)
        {
            _logger.RsaUnrecognizedKeysRemainFailure();
            return Result<CoseRsaKey>.Fail();
        }

        var result = new CoseRsaKey(alg, modulusN, publicExponentE);
        return Result<CoseRsaKey>.Success(result);
    }

    private bool TryGetRsaModulusN(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        [NotNullWhen(true)] out byte[]? modulusN,
        [NotNullWhen(true)] out AbstractCborObject? nKey)
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
        if (!TryGetBytesFromByteString(cborCoseKey, "n", key, out modulusN))
        {
            nKey = null;
            return false;
        }

        nKey = key;
        return true;
    }

    private bool TryGetRsaPublicExponentE(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        [NotNullWhen(true)] out byte[]? publicExponentE,
        [NotNullWhen(true)] out AbstractCborObject? eKey)
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
        if (!TryGetBytesFromByteString(cborCoseKey, "e", key, out publicExponentE))
        {
            eKey = null;
            return false;
        }

        eKey = key;
        return true;
    }

    private bool TryGetEnumFromInt<TEnum>(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        string cborMapKey,
        AbstractCborObject key,
        [NotNullWhen(true)] out TEnum? value) where TEnum : struct, Enum
    {
        if (!cborCoseKey.TryGetValue(key, out var cborValue))
        {
            _logger.CantFindCborMapKey(cborMapKey);
            value = null;
            return false;
        }

        if (cborValue is not AbstractCborInteger intCborValue)
        {
            _logger.CborMapKeyInvalidDataType(cborMapKey);
            value = null;
            return false;
        }

        if (!intCborValue.TryReadAsInt32(out var intValue))
        {
            _logger.CborMapValueOutOfRange(cborMapKey);
            value = null;
            return false;
        }

        if (!Enum.IsDefined(typeof(TEnum), intValue.Value))
        {
            _logger.CborMapInvalidValue(cborMapKey);
            value = null;
            return false;
        }

        value = (TEnum) Enum.ToObject(typeof(TEnum), intValue.Value);
        return true;
    }

    private bool TryGetBytesFromByteString(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        string cborMapKey,
        AbstractCborObject key,
        [NotNullWhen(true)] out byte[]? value)
    {
        if (!cborCoseKey.TryGetValue(key, out var cborValue))
        {
            _logger.CantFindCborMapKey(cborMapKey);
            value = null;
            return false;
        }

        if (cborValue is not CborByteString byteStringCborValue)
        {
            _logger.CborMapKeyInvalidDataType(cborMapKey);
            value = null;
            return false;
        }

        value = byteStringCborValue.RawValue;
        return true;
    }
}

public static partial class DefaultCoseKeyDecoderLoggingExtensions
{
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode COSE Key from CBOR")]
    public static partial void DecodeFailure(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "COSE Key must be represented as a CBOR map")]
    public static partial void CoseKeyMustBeCborMap(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Encountered a label that is neither a string nor an integer")]
    public static partial void InvalidLabel(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Keys in the map representing the COSE_Key in CBOR format must only appear once")]
    public static partial void DuplicateKey(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to obtain a CBOR map representing a COSE_Key")]
    public static partial void CborMapObtainingFailure(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to obtain the value of 'kty'")]
    public static partial void KtyObtainingFailure(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to remove the 'kty' key from the object representing COSE_Key")]
    public static partial void KtyRemoveFailure(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to obtain the value of 'alg'")]
    public static partial void AlgObtainingFailure(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to remove the 'alg' key from the object representing COSE_Key")]
    public static partial void AlgRemoveFailure(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the key '{CborMapKey}' in the COSE_Key")]
    public static partial void CantFindCborMapKey(this ILogger logger, string cborMapKey);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "An invalid data type is used for the '{CborMapKey}' value in COSE_Key")]
    public static partial void CborMapKeyInvalidDataType(this ILogger logger, string cborMapKey);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "A value out of the acceptable range is specified for the '{CborMapKey}' in COSE_Key")]
    public static partial void CborMapValueOutOfRange(this ILogger logger, string cborMapKey);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "An invalid value is specified for the '{CborMapKey}' in COSE_Key")]
    public static partial void CborMapInvalidValue(this ILogger logger, string cborMapKey);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'alg': {alg} in COSE_Key was recognized, but is not in the set of valid options for 'kty': {kty}")]
    public static partial void AlgOutOfRangeForKty(this ILogger logger, CoseAlgorithm alg, CoseKeyType kty);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The COSE_Key, based on 'kty': {kty}, was recognized as an EC2-formatted key but encountered an error during reading")]
    public static partial void Ec2KeyObtainingFailure(this ILogger logger, CoseKeyType kty);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The COSE_Key, based on 'kty': {kty}, was recognized as an RSA-formatted key but encountered an error during reading")]
    public static partial void RsaKeyObtainingFailure(this ILogger logger, CoseKeyType kty);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "An unknown 'kty' value has been encountered")]
    public static partial void UnknownKty(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "No set of supported elliptic curve formats is specified for 'alg': {alg}")]
    public static partial void NoEllipticCurvesForAlg(this ILogger logger, CoseAlgorithm alg);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'crv': {crv} is not included in the set of supported elliptic curve formats for 'alg': {alg}")]
    public static partial void DisallowedEllipticCurveForAlg(this ILogger logger, CoseAlgorithm alg, CoseEllipticCurve crv);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to obtain the value of 'crv'")]
    public static partial void CrvObtainingFailure(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to remove the 'crv' key from the object representing COSE_Key")]
    public static partial void CrvRemoveFailure(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to obtain the value of 'x'")]
    public static partial void XCoordinateObtainingFailure(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to remove the 'x' key from the object representing COSE_Key")]
    public static partial void XCoordinateRemoveFailure(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to obtain the value of 'y'")]
    public static partial void YCoordinateObtainingFailure(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to remove the 'y' key from the object representing COSE_Key")]
    public static partial void YCoordinateRemoveFailure(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to obtain the value of 'n'")]
    public static partial void RsaModulusNObtainingFailure(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to remove the 'n' key from the object representing COSE_Key")]
    public static partial void RsaModulusNRemoveFailure(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to obtain the value of 'e'")]
    public static partial void RsaPublicExponentEObtainingFailure(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to remove the 'e' key from the object representing COSE_Key")]
    public static partial void RsaPublicExponentERemoveFailure(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The COSE_Key was not properly encoded in the EC2 format, as the map still contains unrecognized keys after the necessary values have been extracted")]
    public static partial void Ec2UnrecognizedKeysRemainFailure(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The COSE_Key was not properly encoded in the RSA format, as the map still contains unrecognized keys after the necessary values have been extracted")]
    public static partial void RsaUnrecognizedKeysRemainFailure(this ILogger logger);
}
