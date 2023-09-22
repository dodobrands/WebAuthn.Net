using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Extensions;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Cryptography.Cose;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AuthenticatorData;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.Enums;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Implementation;

/// <summary>
///     Default implementation of the service for working with the <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> structure.
/// </summary>
public class DefaultAuthenticatorDataDecoder : IAuthenticatorDataDecoder
{
    private const int EncodedAuthenticatorDataMinLength = 37;

    private readonly ICoseKeyDecoder _coseKeyDecoder;

    public DefaultAuthenticatorDataDecoder(ICoseKeyDecoder coseKeyDecoder)
    {
        ArgumentNullException.ThrowIfNull(coseKeyDecoder);
        _coseKeyDecoder = coseKeyDecoder;
    }

    /// <inheritdoc />
    public Result<DecodedAuthenticatorData> Decode(ReadOnlySpan<byte> authenticatorData)
    {
        if (authenticatorData.Length < EncodedAuthenticatorDataMinLength)
        {
            return Result<DecodedAuthenticatorData>.Failed($"The minimum size of the encoded authenticator data structure is {EncodedAuthenticatorDataMinLength} bytes.");
        }

        var buffer = authenticatorData;

        if (!TryConsumeRpIdHash(ref buffer, out var rpIdHash))
        {
            return Result<DecodedAuthenticatorData>.Failed("Can't read rpIdHash");
        }

        if (!TryConsumeAuthenticatorDataFlags(ref buffer, out var flags))
        {
            return Result<DecodedAuthenticatorData>.Failed("Can't read flags");
        }

        if (!TryConsumeSignCount(ref buffer, out var signCount))
        {
            return Result<DecodedAuthenticatorData>.Failed("Can't read signCount");
        }

        DecodedAttestedCredentialData? attestedCredentialData = null;
        // Bit 6: Attested credential data included (AT)
        if (flags.Contains(AuthenticatorDataFlags.AttestedCredentialData))
        {
            var attestedCredentialDataResult = TryConsumeAttestedCredentialData(ref buffer);
            if (attestedCredentialDataResult.HasError)
            {
                return Result<DecodedAuthenticatorData>.Failed(attestedCredentialDataResult.Error);
            }

            attestedCredentialData = attestedCredentialDataResult.Ok;
        }

        var result = new DecodedAuthenticatorData(
            rpIdHash,
            flags,
            signCount.Value,
            attestedCredentialData);
        return Result<DecodedAuthenticatorData>.Success(result);
    }

    private static bool TryConsumeRpIdHash(ref ReadOnlySpan<byte> input, [NotNullWhen(true)] out byte[]? rpIdHash)
    {
        if (!TryRead(ref input, 32, out var consumedBuffer))
        {
            rpIdHash = null;
            return false;
        }

        rpIdHash = consumedBuffer.ToArray();
        return true;
    }

    private static bool TryConsumeAuthenticatorDataFlags(ref ReadOnlySpan<byte> input, [NotNullWhen(true)] out IReadOnlySet<AuthenticatorDataFlags>? flags)
    {
        if (!TryRead(ref input, 1, out var consumedBuffer))
        {
            flags = null;
            return false;
        }

        var flagsByte = consumedBuffer[0];
        var enumFlags = (AuthenticatorDataFlags) flagsByte;
        flags = enumFlags.FlagsToSet();
        return true;
    }

    private static bool TryConsumeSignCount(ref ReadOnlySpan<byte> input, [NotNullWhen(true)] out uint? signCount)
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
    private Result<DecodedAttestedCredentialData> TryConsumeAttestedCredentialData(ref ReadOnlySpan<byte> input)
    {
        if (!TryConsumeAaguid(ref input, out var aaguid))
        {
            return Result<DecodedAttestedCredentialData>.Failed("Can't read signCount");
        }

        if (!TryConsumeCredentialIdLength(ref input, out var credentialIdLength))
        {
            return Result<DecodedAttestedCredentialData>.Failed("Can't read credentialIdLength");
        }

        if (!TryConsumeCredentialId(ref input, credentialIdLength.Value, out var credentialId))
        {
            return Result<DecodedAttestedCredentialData>.Failed("Can't read credentialId");
        }

        var credentialPublicKeyResult = ConsumeCredentialPublicKey(ref input);
        if (credentialPublicKeyResult.HasError)
        {
            return Result<DecodedAttestedCredentialData>.Failed(credentialPublicKeyResult.Error);
        }

        var result = new DecodedAttestedCredentialData(aaguid, credentialId, credentialPublicKeyResult.Ok);
        return Result<DecodedAttestedCredentialData>.Success(result);
    }

    [SuppressMessage("ReSharper", "IdentifierTypo")]
    private static bool TryConsumeAaguid(ref ReadOnlySpan<byte> input, [NotNullWhen(true)] out byte[]? aaguid)
    {
        if (!TryRead(ref input, 16, out var consumedBuffer))
        {
            aaguid = null;
            return false;
        }

        aaguid = consumedBuffer.ToArray();
        return true;
    }

    private static bool TryConsumeCredentialIdLength(ref ReadOnlySpan<byte> input, [NotNullWhen(true)] out ushort? credentialIdLength)
    {
        if (!TryRead(ref input, 2, out var consumedBuffer))
        {
            credentialIdLength = null;
            return false;
        }

        credentialIdLength = BinaryPrimitives.ReadUInt16BigEndian(consumedBuffer);
        return true;
    }

    private static bool TryConsumeCredentialId(ref ReadOnlySpan<byte> input, ushort credentialIdLength, [NotNullWhen(true)] out byte[]? credentialId)
    {
        if (!TryRead(ref input, credentialIdLength, out var consumedBuffer))
        {
            credentialId = null;
            return false;
        }

        credentialId = consumedBuffer.ToArray();
        return true;
    }

    private Result<AbstractCoseKey> ConsumeCredentialPublicKey(ref ReadOnlySpan<byte> input)
    {
        var bufferToConsume = input.ToArray();
        var decodeResult = _coseKeyDecoder.Decode(bufferToConsume);
        if (decodeResult.HasError)
        {
            return Result<AbstractCoseKey>.Failed(decodeResult.Error);
        }

        var credentialPublicKey = decodeResult.Ok.CoseKey;
        var bytesConsumed = decodeResult.Ok.BytesConsumed;
        input = input[bytesConsumed..];
        return Result<AbstractCoseKey>.Success(credentialPublicKey);
    }

    private static bool TryRead(ref ReadOnlySpan<byte> input, int length, out ReadOnlySpan<byte> consumedBuffer)
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
