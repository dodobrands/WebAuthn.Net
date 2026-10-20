using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.VerifyAssertion;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateCredential;

namespace WebAuthn.Net.DSL;

// An ES256 software authenticator that produces "none" attestations and assertions over client data built by a test.
// It covers client data, flags and identifiers that the recorded test vectors don't contain.
public sealed class SoftwareAuthenticator : IDisposable
{
    public const byte UserPresent = 0x01;
    public const byte UserVerified = 0x04;
    public const byte BackupEligibility = 0x08;
    public const byte BackupState = 0x10;
    private const byte AttestedCredentialData = 0x40;

    private readonly ECDsa _key;

    public SoftwareAuthenticator()
    {
        _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CredentialId = RandomNumberGenerator.GetBytes(32);
    }

    public byte[] CredentialId { get; }

    public void Dispose()
    {
        _key.Dispose();
    }

    public static string CreateClientDataJson(
        string type,
        string challenge,
        string origin,
        bool? crossOrigin = null,
        string? topOrigin = null)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("type", type);
            writer.WriteString("challenge", challenge);
            writer.WriteString("origin", origin);
            if (crossOrigin.HasValue)
            {
                writer.WriteBoolean("crossOrigin", crossOrigin.Value);
            }

            if (topOrigin is not null)
            {
                writer.WriteString("topOrigin", topOrigin);
            }

            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    public RegistrationResponseJSON CreateRegistrationResponse(
        string rpId,
        string clientDataJson,
        byte flags = UserPresent | UserVerified,
        uint signCount = 0,
        byte[]? id = null,
        byte[]? rawId = null,
        string[]? transports = null)
    {
        var authData = new List<byte>();
        authData.AddRange(CreateAuthenticatorData(rpId, (byte) (flags | AttestedCredentialData), signCount));
        authData.AddRange(new byte[16]); // aaguid
        var credentialIdLength = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(credentialIdLength, (ushort) CredentialId.Length);
        authData.AddRange(credentialIdLength);
        authData.AddRange(CredentialId);
        authData.AddRange(EncodeCredentialPublicKey());

        var attestationObject = new CborWriter(CborConformanceMode.Ctap2Canonical);
        attestationObject.WriteStartMap(3);
        attestationObject.WriteTextString("fmt");
        attestationObject.WriteTextString("none");
        attestationObject.WriteTextString("attStmt");
        attestationObject.WriteStartMap(0);
        attestationObject.WriteEndMap();
        attestationObject.WriteTextString("authData");
        attestationObject.WriteByteString(authData.ToArray());
        attestationObject.WriteEndMap();

        return new(
            WebEncoders.Base64UrlEncode(id ?? CredentialId),
            WebEncoders.Base64UrlEncode(rawId ?? CredentialId),
            new(
                WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(clientDataJson)),
                null,
                transports,
                null,
                null,
                WebEncoders.Base64UrlEncode(attestationObject.Encode())),
            null,
            new(),
            "public-key");
    }

    public AuthenticationResponseJSON CreateAuthenticationResponse(
        string rpId,
        string clientDataJson,
        byte[] userHandle,
        byte flags = UserPresent | UserVerified,
        uint signCount = 0,
        byte[]? id = null,
        byte[]? rawId = null)
    {
        var authData = CreateAuthenticatorData(rpId, flags, signCount);
        var clientData = Encoding.UTF8.GetBytes(clientDataJson);
        var dataToSign = new byte[authData.Length + SHA256.HashSizeInBytes];
        authData.CopyTo(dataToSign, 0);
        SHA256.HashData(clientData).CopyTo(dataToSign, authData.Length);
        var signature = _key.SignData(dataToSign, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        return new(
            WebEncoders.Base64UrlEncode(id ?? CredentialId),
            WebEncoders.Base64UrlEncode(rawId ?? CredentialId),
            new(
                WebEncoders.Base64UrlEncode(clientData),
                WebEncoders.Base64UrlEncode(authData),
                WebEncoders.Base64UrlEncode(signature),
                WebEncoders.Base64UrlEncode(userHandle)),
            null,
            new(),
            "public-key");
    }

    private static byte[] CreateAuthenticatorData(string rpId, byte flags, uint signCount)
    {
        var authData = new byte[37];
        SHA256.HashData(Encoding.UTF8.GetBytes(rpId)).CopyTo(authData, 0);
        authData[32] = flags;
        BinaryPrimitives.WriteUInt32BigEndian(authData.AsSpan(33), signCount);
        return authData;
    }

    private byte[] EncodeCredentialPublicKey()
    {
        var parameters = _key.ExportParameters(false);
        var x = parameters.Q.X ?? throw new InvalidOperationException("The public key has no x coordinate");
        var y = parameters.Q.Y ?? throw new InvalidOperationException("The public key has no y coordinate");
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(5);
        writer.WriteInt32(1); // kty
        writer.WriteInt32(2); // EC2
        writer.WriteInt32(3); // alg
        writer.WriteInt32(-7); // ES256
        writer.WriteInt32(-1); // crv
        writer.WriteInt32(1); // P-256
        writer.WriteInt32(-2); // x
        writer.WriteByteString(x);
        writer.WriteInt32(-3); // y
        writer.WriteByteString(y);
        writer.WriteEndMap();
        return writer.Encode();
    }
}
