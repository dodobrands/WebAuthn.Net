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

/// <summary>
///     Default implementation of <see cref="IAppleAnonymousAttestationStatementVerifier{TContext}" />.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public class DefaultAppleAnonymousAttestationStatementVerifier<TContext>
    : IAppleAnonymousAttestationStatementVerifier<TContext> where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     Constructs <see cref="DefaultAppleAnonymousAttestationStatementVerifier{TContext}" />.
    /// </summary>
    /// <param name="timeProvider">Current time provider.</param>
    /// <param name="asn1Deserializer">ASN.1 format deserializer.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultAppleAnonymousAttestationStatementVerifier(ITimeProvider timeProvider, IAsn1Deserializer asn1Deserializer)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(asn1Deserializer);
        TimeProvider = timeProvider;
        Asn1Deserializer = asn1Deserializer;
    }

    /// <summary>
    ///     Current time provider.
    /// </summary>
    protected ITimeProvider TimeProvider { get; }

    /// <summary>
    ///     ASN.1 format deserializer.
    /// </summary>
    protected IAsn1Deserializer Asn1Deserializer { get; }

    /// <inheritdoc />
    public virtual async Task<Result<VerifiedAttestationStatement>> VerifyAsync(
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
                return Result<VerifiedAttestationStatement>.Fail();
            }

            var x5CCertificates = new List<X509Certificate2>(attStmt.X5C.Length);
            foreach (var x5CBytes in attStmt.X5C)
            {
                if (!X509CertificateInMemoryLoader.TryLoad(x5CBytes, out var x5CCert))
                {
                    x5CCert?.Dispose();
                    return Result<VerifiedAttestationStatement>.Fail();
                }

                certificatesToDispose.Add(x5CCert);
                x5CCertificates.Add(x5CCert);
                if (currentDate < x5CCert.NotBefore || currentDate > x5CCert.NotAfter)
                {
                    return Result<VerifiedAttestationStatement>.Fail();
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
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (!nonce.AsSpan().SequenceEqual(certificateNonce.AsSpan()))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 5) Verify that the credential public key equals the Subject Public Key of 'credCert'.
            if (!authenticatorData.AttestedCredentialData.CredentialPublicKey.Matches(credCert))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 6) If successful, return implementation-specific values representing attestation type Anonymization CA and attestation trust path x5c.
            var acceptableTrustAnchors = await GetAcceptableTrustAnchorsAsync(context, credCert, authenticatorData, cancellationToken);
            var result = new VerifiedAttestationStatement(
                AttestationStatementFormat.AppleAnonymous,
                AttestationType.AnonCa,
                attStmt.X5C,
                acceptableTrustAnchors);
            return Result<VerifiedAttestationStatement>.Success(result);
        }
        finally
        {
            foreach (var certificateToDispose in certificatesToDispose)
            {
                certificateToDispose?.Dispose();
            }
        }
    }


    /// <summary>
    ///     Returns a collection of valid root X509v3 certificates.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="credCert">X509v3 certificate for the credential public key, which includes "nonce" as a certificate extension.</param>
    /// <param name="authenticatorData"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-authenticator-data">Authenticator data</a> that has <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-attestedcredentialdata">attestedCredentialData</a>.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>If the collection of root certificates was successfully formed, the result contains <see cref="UniqueByteArraysCollection" />, otherwise the result indicates that there was an error during the collection formation process.</returns>
    protected virtual Task<UniqueByteArraysCollection> GetAcceptableTrustAnchorsAsync(
        TContext context,
        X509Certificate2 credCert,
        AttestedAuthenticatorData authenticatorData,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = new UniqueByteArraysCollection();
        result.AddRange(GetEmbeddedRootCertificates());
        return Task.FromResult(result);
    }

    /// <summary>
    ///     Returns a collection of root certificates embedded in the library.
    /// </summary>
    /// <returns>An instance of <see cref="UniqueByteArraysCollection" />. It may return an empty collection, but it never returns <see langword="null" />.</returns>
    protected virtual UniqueByteArraysCollection GetEmbeddedRootCertificates()
    {
        return new(AppleRoots.Certificates);
    }

    /// <summary>
    ///     Returns the "nonce" value if it is present and properly encoded in the certificate.
    /// </summary>
    /// <param name="credCert">X509v3 certificate for the credential public key, which includes "nonce" as a certificate extension.</param>
    /// <param name="certificateNonce">Output parameter. If the method returns <see langword="true" /> - contains the "nonce", otherwise - <see langword="null" />.</param>
    /// <returns>If the nonce value is successfully retrieved from the certificate - <see langword="true" />, otherwise - <see langword="false" />.</returns>
    protected virtual bool TryGetNonce(X509Certificate2 credCert, [NotNullWhen(true)] out byte[]? certificateNonce)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (credCert is null)
        {
            certificateNonce = null;
            return false;
        }

        // Verify that nonce equals the value of the extension with OID 1.2.840.113635.100.8.2 in credCert.
        var extensionData = credCert.Extensions.FirstOrDefault(x => x.Oid?.Value == "1.2.840.113635.100.8.2");
        if (extensionData is null)
        {
            certificateNonce = null;
            return false;
        }

        var deserializeResult = Asn1Deserializer.Deserialize(extensionData.RawData, AsnEncodingRules.DER);
        if (deserializeResult.HasError)
        {
            certificateNonce = null;
            return false;
        }

        if (deserializeResult.Ok is null)
        {
            certificateNonce = null;
            return false;
        }

        // Certificate SEQUENCE (1 elem)
        // //   tbsCertificate TBSCertificate [?] [1] (1 elem)
        // //     serialNumber CertificateSerialNumber [?] OCTET STRING (32 byte) 2A2C4080A1705F7408A8FE78D211FF68871AEE73EF59EF8EE3C4DF3915A30484
        var root = deserializeResult.Ok;
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

        var tbsCertificateResult = Asn1Deserializer.Deserialize(tbsCertificateReader.ReadEncodedValue().ToArray(), AsnEncodingRules.DER);
        if (tbsCertificateResult.HasError)
        {
            certificateNonce = null;
            return false;
        }

        if (tbsCertificateResult.Ok is null)
        {
            certificateNonce = null;
            return false;
        }

        if (tbsCertificateResult.Ok is not Asn1OctetString serialNumber)
        {
            certificateNonce = null;
            return false;
        }

        certificateNonce = serialNumber.Value;
        return true;
    }

    /// <summary>
    ///     Concatenates two ReadOnlySpan of bytes into one array.
    /// </summary>
    /// <param name="a">First ReadOnlySpan of bytes.</param>
    /// <param name="b">Second ReadOnlySpan of bytes.</param>
    /// <returns>An array of bytes, filled with the content of the passed ReadOnlySpans.</returns>
    protected virtual byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }
}
