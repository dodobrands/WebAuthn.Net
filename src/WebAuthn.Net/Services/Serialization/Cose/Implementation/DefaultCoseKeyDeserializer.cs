using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor;
using WebAuthn.Net.Services.Serialization.Cbor.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.EC2;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.Extensions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.OKP;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.RSA;

namespace WebAuthn.Net.Services.Serialization.Cose.Implementation;

/// <summary>
///     Default implementation of <see cref="ICoseKeyDeserializer" />.
/// </summary>
public class DefaultCoseKeyDeserializer : ICoseKeyDeserializer
{
    /// <summary>
    ///     Constructs <see cref="DefaultCoseKeyDeserializer" />.
    /// </summary>
    /// <param name="cborDeserializer">CBOR format deserializer.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultCoseKeyDeserializer(ICborDeserializer cborDeserializer, ILogger<DefaultCoseKeyDeserializer> logger)
    {
        ArgumentNullException.ThrowIfNull(cborDeserializer);
        ArgumentNullException.ThrowIfNull(logger);
        CborDeserializer = cborDeserializer;
        Logger = logger;
    }

    /// <summary>
    ///     CBOR format deserializer.
    /// </summary>
    protected ICborDeserializer CborDeserializer { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultCoseKeyDeserializer> Logger { get; }

    /// <inheritdoc />
    public virtual Result<SuccessfulCoseKeyDeserializeResult> Deserialize(byte[] encodedCoseKey)
    {
        var cborResult = CborDeserializer.Deserialize(encodedCoseKey);
        if (cborResult.HasError)
        {
            Logger.DecodeFailure();
            return Result<SuccessfulCoseKeyDeserializeResult>.Fail();
        }

        if (!TryGetCoseKeyRoot(cborResult.Ok, out var cborCoseKey))
        {
            Logger.CborMapObtainingFailure();
            return Result<SuccessfulCoseKeyDeserializeResult>.Fail();
        }

        if (!TryGetKty(cborCoseKey, out var kty, out var ktyKey))
        {
            Logger.KtyObtainingFailure();
            return Result<SuccessfulCoseKeyDeserializeResult>.Fail();
        }

        if (!cborCoseKey.Remove(ktyKey))
        {
            Logger.KtyRemoveFailure();
            return Result<SuccessfulCoseKeyDeserializeResult>.Fail();
        }

        if (!TryGetAlg(cborCoseKey, kty.Value, out var alg, out var algKey))
        {
            Logger.AlgObtainingFailure();
            return Result<SuccessfulCoseKeyDeserializeResult>.Fail();
        }

        if (!cborCoseKey.Remove(algKey))
        {
            Logger.AlgRemoveFailure();
            return Result<SuccessfulCoseKeyDeserializeResult>.Fail();
        }

        switch (kty.Value)
        {
            case CoseKeyType.EC2:
                {
                    var ec2Result = TryGetEc2Key(alg.Value, cborCoseKey);
                    if (ec2Result.HasError)
                    {
                        Logger.Ec2KeyObtainingFailure(kty.Value);
                        return Result<SuccessfulCoseKeyDeserializeResult>.Fail();
                    }

                    var result = new SuccessfulCoseKeyDeserializeResult(ec2Result.Ok, cborResult.Ok.BytesConsumed);
                    return Result<SuccessfulCoseKeyDeserializeResult>.Success(result);
                }
            case CoseKeyType.RSA:
                {
                    var rsaResult = TryGetRsaKey(alg.Value, cborCoseKey);
                    if (rsaResult.HasError)
                    {
                        Logger.RsaKeyObtainingFailure(kty.Value);
                        return Result<SuccessfulCoseKeyDeserializeResult>.Fail();
                    }

                    var result = new SuccessfulCoseKeyDeserializeResult(rsaResult.Ok, cborResult.Ok.BytesConsumed);
                    return Result<SuccessfulCoseKeyDeserializeResult>.Success(result);
                }
            case CoseKeyType.OKP:
                {
                    var okpResult = TryGetOkpKey(alg.Value, cborCoseKey);
                    if (okpResult.HasError)
                    {
                        Logger.OkpKeyObtainingFailure(kty.Value);
                        return Result<SuccessfulCoseKeyDeserializeResult>.Fail();
                    }

                    var result = new SuccessfulCoseKeyDeserializeResult(okpResult.Ok, cborResult.Ok.BytesConsumed);
                    return Result<SuccessfulCoseKeyDeserializeResult>.Success(result);
                }
            default:
                {
                    Logger.UnknownKty();
                    return Result<SuccessfulCoseKeyDeserializeResult>.Fail();
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
            Logger.CoseKeyMustBeCborMap();
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
                Logger.InvalidLabel();
                cborCoseKey = null;
                return false;
            }

            if (!result.TryAdd(mapKey, mapValue))
            {
                Logger.DuplicateKey();
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
            Logger.AlgOutOfRangeForKty(alg.Value, kty);
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
        if (!TryGetEc2Crv(cborCoseKey, alg, out var crv, out var crvKey))
        {
            Logger.CrvObtainingFailure();
            return Result<CoseEc2Key>.Fail();
        }

        if (!cborCoseKey.Remove(crvKey))
        {
            Logger.CrvRemoveFailure();
            return Result<CoseEc2Key>.Fail();
        }

        if (!TryGetEc2XCoordinate(cborCoseKey, out var x, out var xKey))
        {
            Logger.XCoordinateObtainingFailure();
            return Result<CoseEc2Key>.Fail();
        }

        if (!cborCoseKey.Remove(xKey))
        {
            Logger.XCoordinateRemoveFailure();
            return Result<CoseEc2Key>.Fail();
        }

        if (!TryGetEc2YCoordinate(cborCoseKey, out var y, out var yKey))
        {
            Logger.YCoordinateObtainingFailure();
            return Result<CoseEc2Key>.Fail();
        }

        if (!cborCoseKey.Remove(yKey))
        {
            Logger.YCoordinateRemoveFailure();
            return Result<CoseEc2Key>.Fail();
        }

        if (cborCoseKey.Count > 0)
        {
            Logger.Ec2UnrecognizedKeysRemainFailure();
            return Result<CoseEc2Key>.Fail();
        }

        var result = new CoseEc2Key(alg, crv.Value, x, y);
        return Result<CoseEc2Key>.Success(result);
    }

    private bool TryGetEc2Crv(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        CoseAlgorithm alg,
        [NotNullWhen(true)] out CoseEc2EllipticCurve? crv,
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

        if (!alg.TryGetEc2SupportedEllipticCurves(out var supportedCrv))
        {
            Logger.NoEllipticCurvesForAlg(alg);
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
            Logger.DisallowedEc2EllipticCurveForAlg(alg, crv.Value);
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
            Logger.RsaModulusNObtainingFailure();
            return Result<CoseRsaKey>.Fail();
        }

        if (!cborCoseKey.Remove(nKey))
        {
            Logger.RsaModulusNRemoveFailure();
            return Result<CoseRsaKey>.Fail();
        }

        if (!TryGetRsaPublicExponentE(cborCoseKey, out var publicExponentE, out var eKey))
        {
            Logger.RsaPublicExponentEObtainingFailure();
            return Result<CoseRsaKey>.Fail();
        }

        if (!cborCoseKey.Remove(eKey))
        {
            Logger.RsaPublicExponentERemoveFailure();
            return Result<CoseRsaKey>.Fail();
        }

        if (cborCoseKey.Count > 0)
        {
            Logger.RsaUnrecognizedKeysRemainFailure();
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

    private Result<CoseOkpKey> TryGetOkpKey(
        CoseAlgorithm alg,
        Dictionary<AbstractCborObject, AbstractCborObject> cborCoseKey)
    {
        if (!TryGetOkpCrv(cborCoseKey, alg, out var crv, out var crvKey))
        {
            Logger.CrvObtainingFailure();
            return Result<CoseOkpKey>.Fail();
        }

        if (!cborCoseKey.Remove(crvKey))
        {
            Logger.CrvRemoveFailure();
            return Result<CoseOkpKey>.Fail();
        }

        if (!TryGetOkpXCoordinate(cborCoseKey, out var x, out var xKey))
        {
            Logger.XCoordinateObtainingFailure();
            return Result<CoseOkpKey>.Fail();
        }

        if (!cborCoseKey.Remove(xKey))
        {
            Logger.XCoordinateRemoveFailure();
            return Result<CoseOkpKey>.Fail();
        }

        if (cborCoseKey.Count > 0)
        {
            Logger.OkpUnrecognizedKeysRemainFailure();
            return Result<CoseOkpKey>.Fail();
        }

        var result = new CoseOkpKey(alg, crv.Value, x);
        return Result<CoseOkpKey>.Success(result);
    }

    private bool TryGetOkpCrv(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        CoseAlgorithm alg,
        [NotNullWhen(true)] out CoseOkpEllipticCurve? crv,
        [NotNullWhen(true)] out AbstractCborObject? crvKey)
    {
        // https://www.rfc-editor.org/rfc/rfc9053.html#section-2.2
        // In that document, the signature algorithm is instantiated using parameters for the edwards25519 and edwards448 curves
        // For use with COSE, only the pure EdDSA version is used.
        // https://www.rfc-editor.org/rfc/rfc9052#section-1.5
        // label = int / tstr
        // https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
        // Key Type: 1 (OKP)
        // Name: crv
        // Label: -1
        // CBOR Type: int / tstr
        // https://www.rfc-editor.org/rfc/rfc9052#section-1.4
        // tstr: A UTF-8 text string (major type 3).
        // int: An unsigned integer or a negative integer.
        // --------------------
        // In the current implementation, each kty has its own set of supported algorithms.
        if (!alg.TryGetOkpSupportedEllipticCurves(out var supportedCrv))
        {
            Logger.NoEllipticCurvesForAlg(alg);
            crv = null;
            crvKey = null;
            return false;
        }

        var key = new CborNegativeInteger((int) CoseOkpKeyParameter.crv);
        if (!TryGetEnumFromInt(cborCoseKey, "crv", key, out crv))
        {
            crvKey = null;
            return false;
        }

        if (!supportedCrv.Contains(crv.Value))
        {
            Logger.DisallowedOkpEllipticCurveForAlg(alg, crv.Value);
            crv = null;
            crvKey = null;
            return false;
        }

        crvKey = key;
        return true;
    }

    private bool TryGetOkpXCoordinate(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        [NotNullWhen(true)] out byte[]? x,
        [NotNullWhen(true)] out AbstractCborObject? xKey)
    {
        // https://www.rfc-editor.org/rfc/rfc9052#section-1.5
        // label = int / tstr
        // https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
        // Key Type: 1 (OKP)
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

    private bool TryGetEnumFromInt<TEnum>(
        IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> cborCoseKey,
        string cborMapKey,
        AbstractCborObject key,
        [NotNullWhen(true)] out TEnum? value) where TEnum : struct, Enum
    {
        if (!cborCoseKey.TryGetValue(key, out var cborValue))
        {
            Logger.CantFindCborMapKey(cborMapKey);
            value = null;
            return false;
        }

        if (cborValue is not AbstractCborInteger intCborValue)
        {
            Logger.CborMapKeyInvalidDataType(cborMapKey);
            value = null;
            return false;
        }

        if (!intCborValue.TryReadAsInt32(out var intValue))
        {
            Logger.CborMapValueOutOfRange(cborMapKey);
            value = null;
            return false;
        }

        if (!Enum.IsDefined(typeof(TEnum), intValue.Value))
        {
            Logger.CborMapInvalidValue(cborMapKey);
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
            Logger.CantFindCborMapKey(cborMapKey);
            value = null;
            return false;
        }

        if (cborValue is not CborByteString byteStringCborValue)
        {
            Logger.CborMapKeyInvalidDataType(cborMapKey);
            value = null;
            return false;
        }

        value = byteStringCborValue.RawValue;
        return true;
    }
}

/// <summary>
///     Extension methods for logging the deserializer of public keys in COSE format.
/// </summary>
public static partial class DefaultCoseKeyDeserializerLoggingExtensions
{
    /// <summary>
    ///     Failed to decode COSE Key from CBOR
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode COSE Key from CBOR")]
    public static partial void DecodeFailure(this ILogger logger);

    /// <summary>
    ///     COSE Key must be represented as a CBOR map
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "COSE Key must be represented as a CBOR map")]
    public static partial void CoseKeyMustBeCborMap(this ILogger logger);

    /// <summary>
    ///     Encountered a label that is neither a string nor an integer
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Encountered a label that is neither a string nor an integer")]
    public static partial void InvalidLabel(this ILogger logger);

    /// <summary>
    ///     Keys in the map representing the COSE_Key in CBOR format must only appear once
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Keys in the map representing the COSE_Key in CBOR format must only appear once")]
    public static partial void DuplicateKey(this ILogger logger);

    /// <summary>
    ///     Failed to obtain a CBOR map representing a COSE_Key
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to obtain a CBOR map representing a COSE_Key")]
    public static partial void CborMapObtainingFailure(this ILogger logger);

    /// <summary>
    ///     Failed to obtain the value of 'kty'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to obtain the value of 'kty'")]
    public static partial void KtyObtainingFailure(this ILogger logger);

    /// <summary>
    ///     Failed to remove the 'kty' key from the object representing COSE_Key
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to remove the 'kty' key from the object representing COSE_Key")]
    public static partial void KtyRemoveFailure(this ILogger logger);

    /// <summary>
    ///     Failed to obtain the value of 'alg'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to obtain the value of 'alg'")]
    public static partial void AlgObtainingFailure(this ILogger logger);

    /// <summary>
    ///     Failed to remove the 'alg' key from the object representing COSE_Key
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to remove the 'alg' key from the object representing COSE_Key")]
    public static partial void AlgRemoveFailure(this ILogger logger);

    /// <summary>
    ///     Failed to find the key '{CborMapKey}' in the COSE_Key
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="cborMapKey">The name of the property that could not be found in the CBOR object describing the COSE key.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the key '{CborMapKey}' in the COSE_Key")]
    public static partial void CantFindCborMapKey(this ILogger logger, string cborMapKey);

    /// <summary>
    ///     An invalid data type is used for the '{CborMapKey}' value in COSE_Key
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="cborMapKey">The name of the property for which an invalid data type is used in the CBOR object describing the COSE key.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "An invalid data type is used for the '{CborMapKey}' value in COSE_Key")]
    public static partial void CborMapKeyInvalidDataType(this ILogger logger, string cborMapKey);

    /// <summary>
    ///     A value out of the acceptable range is specified for the '{CborMapKey}' in COSE_Key
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="cborMapKey">The name of the property that contains a value exceeding the allowable limits in the CBOR object describing the COSE key.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "A value out of the acceptable range is specified for the '{CborMapKey}' in COSE_Key")]
    public static partial void CborMapValueOutOfRange(this ILogger logger, string cborMapKey);

    /// <summary>
    ///     An invalid value is specified for the '{CborMapKey}' in COSE_Key
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="cborMapKey">The name of the property that contains an invalid value in the CBOR object describing the COSE key.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "An invalid value is specified for the '{CborMapKey}' in COSE_Key")]
    public static partial void CborMapInvalidValue(this ILogger logger, string cborMapKey);

    /// <summary>
    ///     'alg': {alg} in COSE_Key was recognized, but is not in the set of valid options for 'kty': {kty}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="alg">
    ///     Recognized <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#typedefdef-cosealgorithmidentifier">COSEAlgorithmIdentifier</a> describing the algorithm used in the COSE key, but not corresponding to the COSE key type in the <paramref name="kty" />
    ///     parameter.
    /// </param>
    /// <param name="kty">
    ///     <a href="https://datatracker.ietf.org/doc/html/rfc9053#section-7">COSE Key type</a>
    /// </param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'alg': {alg} in COSE_Key was recognized, but is not in the set of valid options for 'kty': {kty}")]
    public static partial void AlgOutOfRangeForKty(this ILogger logger, CoseAlgorithm alg, CoseKeyType kty);

    /// <summary>
    ///     The COSE_Key, based on 'kty': {kty}, was recognized as an EC2-formatted key but encountered an error during reading
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="kty">
    ///     <a href="https://datatracker.ietf.org/doc/html/rfc9053#section-7">COSE Key type</a>
    /// </param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The COSE_Key, based on 'kty': {kty}, was recognized as an EC2-formatted key but encountered an error during reading")]
    public static partial void Ec2KeyObtainingFailure(this ILogger logger, CoseKeyType kty);

    /// <summary>
    ///     The COSE_Key, based on 'kty': {kty}, was recognized as an RSA-formatted key but encountered an error during reading
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="kty">
    ///     <a href="https://datatracker.ietf.org/doc/html/rfc9053#section-7">COSE Key type</a>
    /// </param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The COSE_Key, based on 'kty': {kty}, was recognized as an RSA-formatted key but encountered an error during reading")]
    public static partial void RsaKeyObtainingFailure(this ILogger logger, CoseKeyType kty);

    /// <summary>
    ///     The COSE_Key, based on 'kty': {kty}, was recognized as an OKP-formatted key but encountered an error during reading
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="kty">
    ///     <a href="https://datatracker.ietf.org/doc/html/rfc9053#section-7">COSE Key type</a>
    /// </param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The COSE_Key, based on 'kty': {kty}, was recognized as an OKP-formatted key but encountered an error during reading")]
    public static partial void OkpKeyObtainingFailure(this ILogger logger, CoseKeyType kty);

    /// <summary>
    ///     An unknown 'kty' value has been encountered
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "An unknown 'kty' value has been encountered")]
    public static partial void UnknownKty(this ILogger logger);

    /// <summary>
    ///     No set of supported elliptic curve formats is specified for 'alg': {alg}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="alg"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#typedefdef-cosealgorithmidentifier">COSEAlgorithmIdentifier</a> for which supported elliptic curves could not be found.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "No set of supported elliptic curve formats is specified for 'alg': {alg}")]
    public static partial void NoEllipticCurvesForAlg(this ILogger logger, CoseAlgorithm alg);

    /// <summary>
    ///     The 'crv': {crv} is not included in the set of supported elliptic curve formats for 'alg': {alg} for the key in EC2 format.
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="alg">
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#typedefdef-cosealgorithmidentifier">COSEAlgorithmIdentifier</a>
    /// </param>
    /// <param name="crv">The elliptic curve, which is not included in the list of supported ones for the specified <paramref name="alg" /> (for a key in EC2 format).</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'crv': {crv} is not included in the set of supported elliptic curve formats for 'alg': {alg} for the key in EC2 format")]
    public static partial void DisallowedEc2EllipticCurveForAlg(this ILogger logger, CoseAlgorithm alg, CoseEc2EllipticCurve crv);

    /// <summary>
    ///     The 'crv': {crv} is not included in the set of supported elliptic curve formats for 'alg': {alg} for the key in OKP format
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="alg">
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#typedefdef-cosealgorithmidentifier">COSEAlgorithmIdentifier</a>
    /// </param>
    /// <param name="crv">The elliptic curve, which is not included in the list of supported ones for the specified <paramref name="alg" /> (for a key in OKP format).</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'crv': {crv} is not included in the set of supported elliptic curve formats for 'alg': {alg} for the key in OKP format")]
    public static partial void DisallowedOkpEllipticCurveForAlg(this ILogger logger, CoseAlgorithm alg, CoseOkpEllipticCurve crv);

    /// <summary>
    ///     Failed to obtain the value of 'crv'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to obtain the value of 'crv'")]
    public static partial void CrvObtainingFailure(this ILogger logger);

    /// <summary>
    ///     Failed to remove the 'crv' key from the object representing COSE_Key
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to remove the 'crv' key from the object representing COSE_Key")]
    public static partial void CrvRemoveFailure(this ILogger logger);

    /// <summary>
    ///     Failed to obtain the value of 'x'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to obtain the value of 'x'")]
    public static partial void XCoordinateObtainingFailure(this ILogger logger);

    /// <summary>
    ///     Failed to remove the 'x' key from the object representing COSE_Key
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to remove the 'x' key from the object representing COSE_Key")]
    public static partial void XCoordinateRemoveFailure(this ILogger logger);

    /// <summary>
    ///     Failed to obtain the value of 'y'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to obtain the value of 'y'")]
    public static partial void YCoordinateObtainingFailure(this ILogger logger);

    /// <summary>
    ///     Failed to remove the 'y' key from the object representing COSE_Key
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to remove the 'y' key from the object representing COSE_Key")]
    public static partial void YCoordinateRemoveFailure(this ILogger logger);

    /// <summary>
    ///     Failed to obtain the value of 'n'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to obtain the value of 'n'")]
    public static partial void RsaModulusNObtainingFailure(this ILogger logger);

    /// <summary>
    ///     Failed to remove the 'n' key from the object representing COSE_Key
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to remove the 'n' key from the object representing COSE_Key")]
    public static partial void RsaModulusNRemoveFailure(this ILogger logger);

    /// <summary>
    ///     Failed to obtain the value of 'e'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to obtain the value of 'e'")]
    public static partial void RsaPublicExponentEObtainingFailure(this ILogger logger);

    /// <summary>
    ///     Failed to remove the 'e' key from the object representing COSE_Key
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to remove the 'e' key from the object representing COSE_Key")]
    public static partial void RsaPublicExponentERemoveFailure(this ILogger logger);

    /// <summary>
    ///     The COSE_Key was not properly encoded in the EC2 format, as the map still contains unrecognized keys after the necessary values have been extracted
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The COSE_Key was not properly encoded in the EC2 format, as the map still contains unrecognized keys after the necessary values have been extracted")]
    public static partial void Ec2UnrecognizedKeysRemainFailure(this ILogger logger);

    /// <summary>
    ///     The COSE_Key was not properly encoded in the RSA format, as the map still contains unrecognized keys after the necessary values have been extracted
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The COSE_Key was not properly encoded in the RSA format, as the map still contains unrecognized keys after the necessary values have been extracted")]
    public static partial void RsaUnrecognizedKeysRemainFailure(this ILogger logger);

    /// <summary>
    ///     The COSE_Key was not properly encoded in the OKP format, as the map still contains unrecognized keys after the necessary values have been extracted
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The COSE_Key was not properly encoded in the OKP format, as the map still contains unrecognized keys after the necessary values have been extracted")]
    public static partial void OkpUnrecognizedKeysRemainFailure(this ILogger logger);
}
