using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Abstractions.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;

/// <summary>
///     Default implementation of <see cref="ITpmAttestationStatementDecoder" />.
/// </summary>
public class DefaultTpmAttestationStatementDecoder : ITpmAttestationStatementDecoder
{
    // The syntax does not bound the certificate chain in 'x5c', but every element is later loaded as an X.509 certificate and handed to the chain builder, which is costly for attacker-controlled bytes
    // (the X509Certificate2 constructor used on .NET 8 also recognizes PKCS#7 and PKCS#12 blobs, and decrypting a PKCS#12 blob involves a deliberately slow key derivation), so the length is bounded here.
    // Real chains are short: Windows Hello sends the AIK certificate and one intermediate CA certificate.
    private const int MaxX5CLength = 16;

    // untrusted values are truncated to this length in log messages (see LogValue.Sanitize)
    private const int MaxLoggedValueLength = 64;

    /// <summary>
    ///     Constructs <see cref="DefaultTpmAttestationStatementDecoder" />.
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultTpmAttestationStatementDecoder(ILogger<DefaultTpmAttestationStatementDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        Logger = logger;
    }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultTpmAttestationStatementDecoder> Logger { get; }

    /// <inheritdoc />
    public virtual Result<TpmAttestationStatement> Decode(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        if (!TryDecodeAlg(attStmt, out var alg))
        {
            Logger.TpmDecodeFailureAlg();
            return Result<TpmAttestationStatement>.Fail();
        }

        if (!TryDecodeSig(attStmt, out var sig))
        {
            Logger.TpmDecodeFailureSig();
            return Result<TpmAttestationStatement>.Fail();
        }

        if (!TryDecodeVer(attStmt, out var ver))
        {
            Logger.TpmDecodeFailureVer();
            return Result<TpmAttestationStatement>.Fail();
        }

        if (!TryDecodeX5C(attStmt, out var x5C))
        {
            Logger.TpmDecodeFailureX5C();
            return Result<TpmAttestationStatement>.Fail();
        }

        if (!TryDecodePubArea(attStmt, out var pubArea))
        {
            Logger.TpmDecodeFailurePubArea();
            return Result<TpmAttestationStatement>.Fail();
        }

        if (!TryDecodeCertInfo(attStmt, out var certInfo))
        {
            Logger.TpmDecodeFailureCertInfo();
            return Result<TpmAttestationStatement>.Fail();
        }

        ReportMembersOutsideSyntax(attStmt);

        var result = new TpmAttestationStatement(
            ver,
            alg.Value,
            x5C,
            sig,
            certInfo,
            pubArea);
        return Result<TpmAttestationStatement>.Success(result);
    }

    private bool TryDecodeAlg(
        CborMap attStmt,
        [NotNullWhen(true)] out CoseAlgorithm? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("alg"), out var algCbor))
        {
            Logger.TpmAlgKeyNotFound();
            value = null;
            return false;
        }

        if (algCbor is not AbstractCborInteger intCborValue)
        {
            Logger.TpmAlgValueInvalidDataType();
            value = null;
            return false;
        }

        if (!intCborValue.TryReadAsInt32(out var intAlg))
        {
            Logger.TpmAlgValueOutOfRange();
            value = null;
            return false;
        }

        var alg = (CoseAlgorithm) intAlg.Value;
        if (!Enum.IsDefined(alg))
        {
            Logger.TpmAlgValueUnknown(intAlg.Value);
            value = null;
            return false;
        }

        value = alg;
        return true;
    }

    private bool TryDecodeSig(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[]? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("sig"), out var sigCbor))
        {
            Logger.TpmSigKeyNotFound();
            value = null;
            return false;
        }

        if (sigCbor is not CborByteString sigCborByteString)
        {
            Logger.TpmSigValueInvalidDataType();
            value = null;
            return false;
        }

        value = sigCborByteString.RawValue;
        return true;
    }

    private bool TryDecodeVer(
        CborMap attStmt,
        [NotNullWhen(true)] out string? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("ver"), out var verCbor))
        {
            Logger.TpmVerKeyNotFound();
            value = null;
            return false;
        }

        if (verCbor is not CborTextString verCborTextString)
        {
            Logger.TpmVerValueInvalidDataType();
            value = null;
            return false;
        }

        // https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation
        // tpmStmtFormat = { ver: "2.0", ... }
        // The CDDL fixes 'ver' ("The version of the TPM specification to which the signature conforms.") to the literal "2.0",
        // and the first step of the verification procedure requires attStmt to conform to that syntax - any other value (e.g. "1.2") is rejected here.
        var ver = verCborTextString.RawValue;
        if (!string.Equals(ver, "2.0", StringComparison.Ordinal))
        {
            // the value is untrusted input: only its beginning is logged, with control characters neutralized
            Logger.TpmVerValueUnsupported(LogValue.Sanitize(ver, MaxLoggedValueLength));
            value = null;
            return false;
        }

        value = ver;
        return true;
    }

    private bool TryDecodeX5C(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[][]? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("x5c"), out var x5CCbor))
        {
            Logger.TpmX5CKeyNotFound();
            value = null;
            return false;
        }

        if (x5CCbor is not CborArray x5CborArray)
        {
            Logger.TpmX5CValueInvalidDataType();
            value = null;
            return false;
        }

        var cborArrayItems = x5CborArray.RawValue;
        // https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation
        // x5c: [ aikCert: bytes, * (caCert: bytes) ] - aikCert followed by its certificate chain; the number of elements is bounded (see MaxX5CLength), only the count is logged.
        if (cborArrayItems.Length > MaxX5CLength)
        {
            Logger.TpmX5CTooManyElements(cborArrayItems.Length, MaxX5CLength);
            value = null;
            return false;
        }

        var result = new byte[cborArrayItems.Length][];
        for (var i = 0; i < cborArrayItems.Length; i++)
        {
            if (cborArrayItems[i] is not CborByteString cborArrayItemByteString)
            {
                Logger.TpmX5CValueInvalidElementDataType();
                value = null;
                return false;
            }

            result[i] = cborArrayItemByteString.RawValue;
        }

        value = result;
        return true;
    }

    private bool TryDecodePubArea(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[]? value)
    {
        return TryGetBytesFromByteString(attStmt, "pubArea", out value);
    }

    private bool TryDecodeCertInfo(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[]? value)
    {
        return TryGetBytesFromByteString(attStmt, "certInfo", out value);
    }

    private bool TryGetBytesFromByteString(
        CborMap attStmt,
        string cborMapKey,
        [NotNullWhen(true)] out byte[]? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString(cborMapKey), out var cborValue))
        {
            Logger.TpmCantFindCborMapKey(cborMapKey);
            value = null;
            return false;
        }

        if (cborValue is not CborByteString byteStringCborValue)
        {
            Logger.TpmCborMapKeyInvalidDataType(cborMapKey);
            value = null;
            return false;
        }

        value = byteStringCborValue.RawValue;
        return true;
    }

    /// <summary>
    ///     Reports every member of 'attStmt' whose key is not one of the six defined by the tpmStmtFormat syntax with a Warning log entry; such members are ignored.
    /// </summary>
    /// <param name="attStmt">The CBOR map of the attestation statement.</param>
    private void ReportMembersOutsideSyntax(CborMap attStmt)
    {
        // https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation
        // tpmStmtFormat = { ver: "2.0", ( alg: COSEAlgorithmIdentifier, x5c: [ aikCert: bytes, * (caCert: bytes) ] ) sig: bytes, certInfo: bytes, pubArea: bytes }
        // The map is closed: any other member (for example the ecdaaKeyId of WebAuthn Level 2, whose ECDAA attestation Level 3 removed) is not part of the syntax
        // that the first step of the verification procedure requires. Nothing in the procedure uses such a member, so it is ignored - but reported, so that the deviation is visible.
        foreach (var key in attStmt.RawValue.Keys)
        {
            if (key is CborTextString { RawValue: "ver" or "alg" or "x5c" or "sig" or "certInfo" or "pubArea" })
            {
                continue;
            }

            // the key is untrusted input: a text string is neutralized and truncated, a key of any other data type is described by its type only
            var member = key is CborTextString textKey
                ? "'" + LogValue.Sanitize(textKey.RawValue, MaxLoggedValueLength) + "'"
                : "<" + key.Type + ">";
            Logger.TpmMemberOutsideSyntaxIgnored(member);
        }
    }
}

/// <summary>
///     Extension methods for logging the TPM attestation statement decoder.
/// </summary>
public static partial class DefaultTpmAttestationStatementDecoderLoggingExtensions
{
    /// <summary>
    ///     Failed to decode the 'alg' value from 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'alg' value from 'attStmt'")]
    public static partial void TpmDecodeFailureAlg(this ILogger logger);

    /// <summary>
    ///     Failed to decode the 'sig' value from 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'sig' value from 'attStmt'")]
    public static partial void TpmDecodeFailureSig(this ILogger logger);

    /// <summary>
    ///     Failed to decode the 'ver' value from 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'ver' value from 'attStmt'")]
    public static partial void TpmDecodeFailureVer(this ILogger logger);

    /// <summary>
    ///     Failed to decode the 'x5c' value from 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'x5c' value from 'attStmt'")]
    public static partial void TpmDecodeFailureX5C(this ILogger logger);

    /// <summary>
    ///     Failed to decode the 'pubArea' value from 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'pubArea' value from 'attStmt'")]
    public static partial void TpmDecodeFailurePubArea(this ILogger logger);

    /// <summary>
    ///     Failed to decode the 'certInfo' value from 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'certInfo' value from 'attStmt'")]
    public static partial void TpmDecodeFailureCertInfo(this ILogger logger);

    /// <summary>
    ///     Failed to find the 'alg' key in 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to find the 'alg' key in 'attStmt'")]
    public static partial void TpmAlgKeyNotFound(this ILogger logger);

    /// <summary>
    ///     The 'alg' value in the 'attStmt' map contains an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'alg' value in the 'attStmt' map contains an invalid data type")]
    public static partial void TpmAlgValueInvalidDataType(this ILogger logger);

    /// <summary>
    ///     The 'alg' value in the 'attStmt' map is out of range
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'alg' value in the 'attStmt' map is out of range")]
    public static partial void TpmAlgValueOutOfRange(this ILogger logger);

    /// <summary>
    ///     The 'attStmt' contains an unknown 'alg': {UnknownAlg}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="unknownAlg">Unknown 'alg' value.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'attStmt' contains an unknown 'alg': {UnknownAlg}")]
    public static partial void TpmAlgValueUnknown(this ILogger logger, int unknownAlg);

    /// <summary>
    ///     Failed to find the 'sig' key in 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to find the 'sig' key in 'attStmt'")]
    public static partial void TpmSigKeyNotFound(this ILogger logger);

    /// <summary>
    ///     Failed to find the 'ver' key in 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to find the 'ver' key in 'attStmt'")]
    public static partial void TpmVerKeyNotFound(this ILogger logger);

    /// <summary>
    ///     The 'sig' value in the 'attStmt' map contains an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'sig' value in the 'attStmt' map contains an invalid data type")]
    public static partial void TpmSigValueInvalidDataType(this ILogger logger);

    /// <summary>
    ///     The 'ver' value in the 'attStmt' map contains an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'ver' value in the 'attStmt' map contains an invalid data type")]
    public static partial void TpmVerValueInvalidDataType(this ILogger logger);

    /// <summary>
    ///     The 'ver' value in the 'attStmt' map is not supported: {Ver}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="ver">The 'ver' value that was received (only "2.0" is supported), truncated to 64 characters, with every control character replaced by '?'.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'ver' value in the 'attStmt' map is not supported: {Ver}")]
    public static partial void TpmVerValueUnsupported(this ILogger logger, string ver);

    /// <summary>
    ///     Failed to find the 'x5c' key in 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to find the 'x5c' key in 'attStmt'")]
    public static partial void TpmX5CKeyNotFound(this ILogger logger);

    /// <summary>
    ///     The 'x5c' value in the 'attStmt' map contains an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'x5c' value in the 'attStmt' map contains an invalid data type")]
    public static partial void TpmX5CValueInvalidDataType(this ILogger logger);

    /// <summary>
    ///     One of the 'x5c' array elements in the 'attStmt' contains a CBOR element with an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "One of the 'x5c' array elements in the 'attStmt' contains a CBOR element with an invalid data type")]
    public static partial void TpmX5CValueInvalidElementDataType(this ILogger logger);

    /// <summary>
    ///     The 'x5c' array in the 'attStmt' map has {Count} elements, more than the {Max} that are accepted
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="count">The number of elements of the 'x5c' array.</param>
    /// <param name="max">The maximum number of elements that are accepted.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'x5c' array in the 'attStmt' map has {Count} elements, more than the {Max} that are accepted")]
    public static partial void TpmX5CTooManyElements(this ILogger logger, int count, int max);

    /// <summary>
    ///     The 'attStmt' map contains a member that is not defined by the tpmStmtFormat syntax: {Member}; ignored
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="member">The key of the member: a text string in quotes (truncated to 64 characters, with every control character replaced by '?'), or the CBOR data type of a key of any other type in angle brackets.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'attStmt' map contains a member that is not defined by the tpmStmtFormat syntax: {Member}; ignored")]
    public static partial void TpmMemberOutsideSyntaxIgnored(this ILogger logger, string member);

    /// <summary>
    ///     Failed to find the key '{CborMapKey}' in 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="cborMapKey"></param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to find the key '{CborMapKey}' in 'attStmt'")]
    public static partial void TpmCantFindCborMapKey(this ILogger logger, string cborMapKey);

    /// <summary>
    ///     An invalid data type is used for the '{CborMapKey}' value in 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="cborMapKey">The key that failed to be found in <see cref="CborMap" />. </param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "An invalid data type is used for the '{CborMapKey}' value in 'attStmt'")]
    public static partial void TpmCborMapKeyInvalidDataType(this ILogger logger, string cborMapKey);
}
