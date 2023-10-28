using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Apple;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Apple.Constants;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Apple;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultAppleAnonymousAttestationStatementVerifier<TContext>
    : IAppleAnonymousAttestationStatementVerifier<TContext> where TContext : class, IWebAuthnContext
{
    public DefaultAppleAnonymousAttestationStatementVerifier(ITimeProvider timeProvider, IAsn1Decoder asn1Decoder)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(asn1Decoder);
        TimeProvider = timeProvider;
        Asn1Decoder = asn1Decoder;
    }

    protected ITimeProvider TimeProvider { get; }
    protected IAsn1Decoder Asn1Decoder { get; }

    public virtual async Task<Result<AttestationStatementVerificationResult>> VerifyAsync(
        TContext context,
        AppleAnonymousAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken)
    {
        // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-apple-anonymous-attestation
        // §8.8. Apple Anonymous Attestation Statement Format

        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(authenticatorData);
        cancellationToken.ThrowIfCancellationRequested();

        // 1) Verify that 'attStmt' is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        var certificatesToDispose = new List<X509Certificate2?>(attStmt.X5C.Length);
        try
        {
            var currentDate = TimeProvider.GetPreciseUtcDateTime();
            if (attStmt.X5C.Length < 2)
            {
                return Result<AttestationStatementVerificationResult>.Fail();
            }

            var x5CCertificates = new List<X509Certificate2>(attStmt.X5C.Length);
            foreach (var x5CBytes in attStmt.X5C)
            {
                if (!X509CertificateInMemoryLoader.TryLoad(x5CBytes, out var x5CCert))
                {
                    x5CCert?.Dispose();
                    return Result<AttestationStatementVerificationResult>.Fail();
                }

                certificatesToDispose.Add(x5CCert);
                x5CCertificates.Add(x5CCert);
                if (currentDate < x5CCert.NotBefore || currentDate > x5CCert.NotAfter)
                {
                    return Result<AttestationStatementVerificationResult>.Fail();
                }
            }

            var credCert = x5CCertificates.First();
            // 2) Concatenate 'authenticatorData' and 'clientDataHash' to form 'nonceToHash'.
            var nonceToHash = Concat(authenticatorData.Raw, clientDataHash);
            // 3) Perform SHA-256 hash of nonceToHash to produce nonce.
            var nonce = SHA256.HashData(nonceToHash);
            // 4) Verify that nonce equals the value of the extension with OID 1.2.840.113635.100.8.2 in credCert.
            if (!TryGetNonce(credCert, out var certificateNonce))
            {
                return Result<AttestationStatementVerificationResult>.Fail();
            }

            if (!nonce.AsSpan().SequenceEqual(certificateNonce.AsSpan()))
            {
                return Result<AttestationStatementVerificationResult>.Fail();
            }

            // 5) Verify that the credential public key equals the Subject Public Key of 'credCert'.
            if (!authenticatorData.AttestedCredentialData.CredentialPublicKey.Matches(credCert))
            {
                return Result<AttestationStatementVerificationResult>.Fail();
            }

            // 6) If successful, return implementation-specific values representing attestation type Anonymization CA and attestation trust path x5c.
            var acceptableTrustAnchors = await GetAcceptableTrustAnchorsAsync(context, authenticatorData, cancellationToken);
            var result = new AttestationStatementVerificationResult(
                AttestationStatementFormat.AppleAnonymous,
                AttestationType.AnonCa,
                attStmt.X5C,
                acceptableTrustAnchors);
            return Result<AttestationStatementVerificationResult>.Success(result);
        }
        finally
        {
            foreach (var certificateToDispose in certificatesToDispose)
            {
                certificateToDispose?.Dispose();
            }
        }
    }

    protected virtual Task<AcceptableTrustAnchors> GetAcceptableTrustAnchorsAsync(
        TContext context,
        AttestedAuthenticatorData authenticatorData,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var rootCertificates = GetEmbeddedRootCertificates();
        var result = new AcceptableTrustAnchors(rootCertificates, null);
        return Task.FromResult(result);
    }

    protected virtual byte[][] GetEmbeddedRootCertificates()
    {
        return AppleRoots.Certificates;
    }

    protected virtual bool TryGetNonce(X509Certificate2 credCert, [NotNullWhen(true)] out byte[]? certificateNonce)
    {
        if (!TryGetExtensionData(credCert, out var extensionData))
        {
            certificateNonce = null;
            return false;
        }

        var decodeResult = Asn1Decoder.Decode(extensionData, AsnEncodingRules.DER);
        if (decodeResult.HasError)
        {
            certificateNonce = null;
            return false;
        }

        if (!decodeResult.Ok.HasValue)
        {
            certificateNonce = null;
            return false;
        }

        // Certificate SEQUENCE (1 elem)
        // //   tbsCertificate TBSCertificate [?] [1] (1 elem)
        // //     serialNumber CertificateSerialNumber [?] OCTET STRING (32 byte) 2A2C4080A1705F7408A8FE78D211FF68871AEE73EF59EF8EE3C4DF3915A30484
        var root = decodeResult.Ok.Value;
        if (root is not Asn1Sequence certificate)
        {
            certificateNonce = null;
            return false;
        }

        var tbsCertificateItem = certificate.Items[0];
        if (tbsCertificateItem is not Asn1RawElement rawTbsCertificateItem || rawTbsCertificateItem.Tag.TagClass != TagClass.ContextSpecific)
        {
            certificateNonce = null;
            return false;
        }

        var rawTbsCertificate = rawTbsCertificateItem.RawValue;
        var asnReader = new AsnReader(rawTbsCertificate, AsnEncodingRules.DER);
        if (!asnReader.HasData)
        {
            certificateNonce = null;
            return false;
        }

        var tbsCertificateReader = asnReader.ReadSetOf(asnReader.PeekTag());
        if (!tbsCertificateReader.HasData)
        {
            certificateNonce = null;
            return false;
        }

        var tbsCertificateResult = Asn1Decoder.Decode(tbsCertificateReader.ReadEncodedValue().ToArray(), AsnEncodingRules.DER);
        if (tbsCertificateResult.HasError)
        {
            certificateNonce = null;
            return false;
        }

        if (!tbsCertificateResult.Ok.HasValue)
        {
            certificateNonce = null;
            return false;
        }

        if (tbsCertificateResult.Ok.Value is not Asn1OctetString serialNumber)
        {
            certificateNonce = null;
            return false;
        }

        certificateNonce = serialNumber.Value;
        return true;
    }

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool TryGetExtensionData(X509Certificate2 credCert, [NotNullWhen(true)] out byte[]? extensionData)
    {
        if (credCert is null)
        {
            extensionData = null;
            return false;
        }

        // Verify that nonce equals the value of the extension with OID 1.2.840.113635.100.8.2 in credCert.
        foreach (var extension in credCert.Extensions)
        {
            if (extension.Oid?.Value == "1.2.840.113635.100.8.2")
            {
                extensionData = extension.RawData;
                return true;
            }
        }

        extensionData = null;
        return false;
    }

    protected virtual byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }
}
