using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models.Abstractions;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose;
using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;

namespace WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Implementation;

/// <summary>
///     Default implementation of the service for working with the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> structure.
/// </summary>
public class DefaultAuthenticatorDataDecoder : IAuthenticatorDataDecoder
{
    public DefaultAuthenticatorDataDecoder(
        ICoseKeyDeserializer coseKeyDeserializer,
        ICborDeserializer cborDeserializer,
        ILogger<DefaultAuthenticatorDataDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(coseKeyDeserializer);
        ArgumentNullException.ThrowIfNull(cborDeserializer);
        ArgumentNullException.ThrowIfNull(logger);
        CoseKeyDeserializer = coseKeyDeserializer;
        CborDeserializer = cborDeserializer;
        Logger = logger;
    }

    protected ICoseKeyDeserializer CoseKeyDeserializer { get; }
    protected ICborDeserializer CborDeserializer { get; }
    protected ILogger<DefaultAuthenticatorDataDecoder> Logger { get; }

    public virtual Result<AbstractAuthenticatorData> Decode(byte[] rawAuthData)
    {
        ArgumentNullException.ThrowIfNull(rawAuthData);
        if (rawAuthData.Length < 37)
        {
            Logger.AuthDataTooSmall();
            return Result<AbstractAuthenticatorData>.Fail();
        }

        var buffer = new ReadOnlySpan<byte>(rawAuthData);

        if (!TryConsumeRpIdHash(ref buffer, out var rpIdHash))
        {
            Logger.AuthDataReadFailureRpIdHash();
            return Result<AbstractAuthenticatorData>.Fail();
        }

        if (!TryConsumeAuthenticatorDataFlags(ref buffer, out var flags))
        {
            Logger.AuthDataReadFailureFlags();
            return Result<AbstractAuthenticatorData>.Fail();
        }

        if (!TryConsumeSignCount(ref buffer, out var signCount))
        {
            Logger.AuthDataReadFailureSignCount();
            return Result<AbstractAuthenticatorData>.Fail();
        }

        AttestedCredentialData? attestedCredentialData = null;
        // Bit 6: Attested credential data included (AT)
        if ((flags.Value & AuthenticatorDataFlags.AttestedCredentialData) is AuthenticatorDataFlags.AttestedCredentialData)
        {
            var attestedCredentialDataResult = TryConsumeAttestedCredentialData(ref buffer);
            if (attestedCredentialDataResult.HasError)
            {
                Logger.AuthDataReadFailureAttestedCredentialData();
                return Result<AbstractAuthenticatorData>.Fail();
            }

            attestedCredentialData = attestedCredentialDataResult.Ok;
        }

        if ((flags.Value & AuthenticatorDataFlags.ExtensionDataIncluded) is AuthenticatorDataFlags.ExtensionDataIncluded)
        {
            var extensions = ConsumeExtensions(ref buffer);
            if (extensions.HasError)
            {
                Logger.AuthDataReadFailureExtensions();
                return Result<AbstractAuthenticatorData>.Fail();
            }
        }

        if (buffer.Length > 0)
        {
            Logger.RemainingDataFailure();
            return Result<AbstractAuthenticatorData>.Fail();
        }

        AbstractAuthenticatorData result;
        if (attestedCredentialData is not null)
        {
            result = new AttestedAuthenticatorData(
                rawAuthData,
                rpIdHash,
                flags.Value,
                signCount.Value,
                attestedCredentialData);
        }
        else
        {
            result = new NotAttestedAuthenticatorData(
                rawAuthData,
                rpIdHash,
                flags.Value,
                signCount.Value);
        }

        return Result<AbstractAuthenticatorData>.Success(result);
    }

    protected static bool TryConsumeRpIdHash(ref ReadOnlySpan<byte> input, [NotNullWhen(true)] out byte[]? rpIdHash)
    {
        if (!TryRead(ref input, 32, out var consumedBuffer))
        {
            rpIdHash = null;
            return false;
        }

        rpIdHash = consumedBuffer.ToArray();
        return true;
    }

    protected static bool TryConsumeAuthenticatorDataFlags(ref ReadOnlySpan<byte> input, [NotNullWhen(true)] out AuthenticatorDataFlags? flags)
    {
        if (!TryRead(ref input, 1, out var consumedBuffer))
        {
            flags = null;
            return false;
        }

        var flagsByte = consumedBuffer[0];
        flags = (AuthenticatorDataFlags) flagsByte;
        return true;
    }

    protected static bool TryConsumeSignCount(ref ReadOnlySpan<byte> input, [NotNullWhen(true)] out uint? signCount)
    {
        if (!TryRead(ref input, 4, out var consumedBuffer))
        {
            signCount = null;
            return false;
        }

        signCount = BinaryPrimitives.ReadUInt32BigEndian(consumedBuffer);
        return true;
    }

    [SuppressMessage("ReSharper", "IdentifierTypo")]
    [SuppressMessage("ReSharper", "UnusedVariable")]
    protected virtual Result<AttestedCredentialData> TryConsumeAttestedCredentialData(ref ReadOnlySpan<byte> input)
    {
        if (!TryConsumeAaguid(ref input, out var aaguid))
        {
            Logger.AuthDataReadFailureAttestedCredentialDataAaguid();
            return Result<AttestedCredentialData>.Fail();
        }

        if (!TryConsumeCredentialIdLength(ref input, out var credentialIdLength))
        {
            Logger.AuthDataReadFailureAttestedCredentialDataCredentialIdLength();
            return Result<AttestedCredentialData>.Fail();
        }

        if (credentialIdLength.Value > 1023)
        {
            Logger.AuthDataReadFailureAttestedCredentialDataCredentialIdLengthTooBig(credentialIdLength.Value);
            return Result<AttestedCredentialData>.Fail();
        }

        if (!TryConsumeCredentialId(ref input, credentialIdLength.Value, out var credentialId))
        {
            Logger.AuthDataReadFailureAttestedCredentialDataCredentialId();
            return Result<AttestedCredentialData>.Fail();
        }

        var credentialPublicKeyResult = ConsumeCredentialPublicKey(ref input);
        if (credentialPublicKeyResult.HasError)
        {
            Logger.AuthDataReadFailureAttestedCredentialDataCredentialPublicKey();
            return Result<AttestedCredentialData>.Fail();
        }

        var hexAaguid = Convert.ToHexString(aaguid);
        var typedAaguid = new Guid(hexAaguid);
        var result = new AttestedCredentialData(typedAaguid, credentialId, credentialPublicKeyResult.Ok);
        return Result<AttestedCredentialData>.Success(result);
    }

    [SuppressMessage("ReSharper", "IdentifierTypo")]
    protected static bool TryConsumeAaguid(ref ReadOnlySpan<byte> input, [NotNullWhen(true)] out byte[]? aaguid)
    {
        if (!TryRead(ref input, 16, out var consumedBuffer))
        {
            aaguid = null;
            return false;
        }

        aaguid = consumedBuffer.ToArray();
        return true;
    }

    protected static bool TryConsumeCredentialIdLength(ref ReadOnlySpan<byte> input, [NotNullWhen(true)] out ushort? credentialIdLength)
    {
        if (!TryRead(ref input, 2, out var consumedBuffer))
        {
            credentialIdLength = null;
            return false;
        }

        credentialIdLength = BinaryPrimitives.ReadUInt16BigEndian(consumedBuffer);
        return true;
    }

    protected static bool TryConsumeCredentialId(ref ReadOnlySpan<byte> input, ushort credentialIdLength, [NotNullWhen(true)] out byte[]? credentialId)
    {
        if (!TryRead(ref input, credentialIdLength, out var consumedBuffer))
        {
            credentialId = null;
            return false;
        }

        credentialId = consumedBuffer.ToArray();
        return true;
    }

    protected virtual Result<AbstractCoseKey> ConsumeCredentialPublicKey(ref ReadOnlySpan<byte> input)
    {
        var bufferToConsume = input.ToArray();
        var deserializeResult = CoseKeyDeserializer.Deserialize(bufferToConsume);
        if (deserializeResult.HasError)
        {
            return Result<AbstractCoseKey>.Fail();
        }

        var credentialPublicKey = deserializeResult.Ok.CoseKey;
        var bytesConsumed = deserializeResult.Ok.BytesConsumed;
        input = input[bytesConsumed..];
        return Result<AbstractCoseKey>.Success(credentialPublicKey);
    }

    protected virtual Result<AbstractCborObject> ConsumeExtensions(ref ReadOnlySpan<byte> input)
    {
        var bufferToConsume = input.ToArray();
        var deserializeResult = CborDeserializer.Deserialize(bufferToConsume);
        if (deserializeResult.HasError)
        {
            return Result<AbstractCborObject>.Fail();
        }

        var extensionsRoot = deserializeResult.Ok.Root;
        var bytesConsumed = deserializeResult.Ok.BytesConsumed;
        input = input[bytesConsumed..];
        return Result<AbstractCborObject>.Success(extensionsRoot);
    }

    protected static bool TryRead(ref ReadOnlySpan<byte> input, int length, out ReadOnlySpan<byte> consumedBuffer)
    {
        if (input.Length < length)
        {
            consumedBuffer = ReadOnlySpan<byte>.Empty;
            return false;
        }

        consumedBuffer = input[..length];
        input = input[length..];
        return true;
    }
}

public static partial class DefaultAuthenticatorDataDecoderLoggingExtensions
{
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The minimum size of the encoded authenticator data structure is 37 bytes")]
    public static partial void AuthDataTooSmall(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to read 'rpIdHash'")]
    public static partial void AuthDataReadFailureRpIdHash(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to read 'flags'")]
    public static partial void AuthDataReadFailureFlags(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The presence of attested credential data is required for the registration ceremony")]
    public static partial void AttestedCredentialDataRequiredForRegistration(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to read 'signCount'")]
    public static partial void AuthDataReadFailureSignCount(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to read 'attestedCredentialData'")]
    public static partial void AuthDataReadFailureAttestedCredentialData(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to read 'attestedCredentialData.aaguid'")]
    public static partial void AuthDataReadFailureAttestedCredentialDataAaguid(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'attestedCredentialData.credentialIdLength' is {CredentialIdLength}, which is greater than the maximum limit of 1023")]
    public static partial void AuthDataReadFailureAttestedCredentialDataCredentialIdLengthTooBig(this ILogger logger, int credentialIdLength);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to read 'attestedCredentialData.credentialIdLength'")]
    public static partial void AuthDataReadFailureAttestedCredentialDataCredentialIdLength(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to read 'attestedCredentialData.credentialId'")]
    public static partial void AuthDataReadFailureAttestedCredentialDataCredentialId(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to read 'attestedCredentialData.credentialPublicKey'")]
    public static partial void AuthDataReadFailureAttestedCredentialDataCredentialPublicKey(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to read 'extensions'")]
    public static partial void AuthDataReadFailureExtensions(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "After decoding 'authData' in accordance with its structure, some data has been found to still remain within it")]
    public static partial void RemainingDataFailure(this ILogger logger);
}
