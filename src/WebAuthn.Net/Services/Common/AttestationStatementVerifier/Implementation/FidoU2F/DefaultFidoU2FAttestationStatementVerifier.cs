using System;
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
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.FidoU2F;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.FidoU2F.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cose.Models;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.FidoU2F;

/// <summary>
///     Default implementation of <see cref="IFidoU2FAttestationStatementVerifier{TContext}" />.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public class DefaultFidoU2FAttestationStatementVerifier<TContext>
    : IFidoU2FAttestationStatementVerifier<TContext> where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     Constructs <see cref="DefaultFidoU2FAttestationStatementVerifier{TContext}" />.
    /// </summary>
    /// <param name="timeProvider">Current time provider.</param>
    /// <param name="asn1Deserializer">ASN.1 format deserializer.</param>
    /// <param name="fidoMetadataSearchService">A service for searching in the data provided by the FIDO Metadata Service.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultFidoU2FAttestationStatementVerifier(
        ITimeProvider timeProvider,
        IAsn1Deserializer asn1Deserializer,
        IFidoMetadataSearchService<TContext> fidoMetadataSearchService)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(asn1Deserializer);
        ArgumentNullException.ThrowIfNull(fidoMetadataSearchService);
        TimeProvider = timeProvider;
        Asn1Deserializer = asn1Deserializer;
        FidoMetadataSearchService = fidoMetadataSearchService;
    }

    /// <summary>
    ///     Current time provider.
    /// </summary>
    protected ITimeProvider TimeProvider { get; }

    /// <summary>
    ///     ASN.1 format deserializer.
    /// </summary>
    protected IAsn1Deserializer Asn1Deserializer { get; }

    /// <summary>
    ///     A service for searching in the data provided by the FIDO Metadata Service.
    /// </summary>
    protected IFidoMetadataSearchService<TContext> FidoMetadataSearchService { get; }

    /// <inheritdoc />
    public virtual async Task<Result<VerifiedAttestationStatement>> VerifyAsync(
        TContext context,
        FidoU2FAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken)
    {
        // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-fido-u2f-attestation
        // §8.6. FIDO U2F Attestation Statement Format

        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(authenticatorData);
        cancellationToken.ThrowIfCancellationRequested();

        // 1) Verify that 'attStmt' is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // 2) Check that 'x5c' has exactly one element and let 'attCert' be that element.
        // Let certificate public key be the public key conveyed by 'attCert'.
        // If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error.

        if (attStmt.X5C.Length != 1)
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        X509Certificate2? attCert = null;
        try
        {
            var rawAttCert = attStmt.X5C[0];

            if (!X509CertificateInMemoryLoader.TryLoad(rawAttCert, out attCert))
            {
                attCert?.Dispose();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            var currentDate = TimeProvider.GetPreciseUtcDateTime();
            if (currentDate < attCert.NotBefore || currentDate > attCert.NotAfter)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (!IsValidPublicKeyParameters(attCert, out var attCertEcParameters))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 3) Extract the claimed 'rpIdHash' from 'authenticatorData', and the claimed 'credentialId' and 'credentialPublicKey'
            // from 'authenticatorData.attestedCredentialData'.
            var rpIdHash = authenticatorData.RpIdHash;
            var credentialId = authenticatorData.AttestedCredentialData.CredentialId;
            if (authenticatorData.AttestedCredentialData.CredentialPublicKey is not CoseEc2Key credentialPublicKey)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 4) Convert the COSE_KEY formatted 'credentialPublicKey' (see Section 7 of [RFC9052])
            // to Raw ANSI X9.62 public key format (see ALG_KEY_ECC_X962_RAW in Section 3.6.2 Public Key Representation Formats of [FIDO-Registry]).
            if (!TryConvertCoseKeyToPublicKeyU2F(credentialPublicKey, out var publicKeyU2F))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 5) Let 'verificationData' be the concatenation of
            // (0x00 || 'rpIdHash' || 'clientDataHash' || 'credentialId' || 'publicKeyU2F') (see Section 4.3 of [FIDO-U2F-Message-Formats]).
            var verificationData = Concat(stackalloc byte[1] { 0x00 }, rpIdHash, clientDataHash, credentialId, publicKeyU2F);

            // 6) Verify the 'sig' using 'verificationData' and the certificate public key per section 4.1.4 of [SEC1]
            // with SHA-256 as the hash function used in step two.
            using var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new()
                {
                    X = attCertEcParameters.Value.Q.X,
                    Y = attCertEcParameters.Value.Q.Y
                }
            });
            if (!ecdsa.VerifyData(verificationData, attStmt.Sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 7) Optionally, inspect 'x5c' and consult externally provided knowledge to determine whether 'attStmt' conveys a Basic or AttCA attestation.
            var attestationTypeResult = await GetAttestationTypeAsync(
                context,
                attCert,
                authenticatorData,
                cancellationToken);
            if (attestationTypeResult.HasError)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 8) If successful, return implementation-specific values representing attestation type Basic, AttCA or uncertainty, and attestation trust path x5c.
            var result = new VerifiedAttestationStatement(
                AttestationStatementFormat.FidoU2F,
                attestationTypeResult.Ok.AttestationType,
                new[] { rawAttCert },
                new(attestationTypeResult.Ok.AttestationRootCertificates));
            return Result<VerifiedAttestationStatement>.Success(result);
        }
        finally
        {
            attCert?.Dispose();
        }
    }

    /// <summary>
    ///     Returns the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attestation-types">attestation type</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-fido-u2f-attestation">FIDO U2F attestation statement</a>.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="attCert">Attestation certificate in the x509v3 format.</param>
    /// <param name="authenticatorData"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-authenticator-data">Authenticator data</a> that has <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-attestedcredentialdata">attestedCredentialData</a>.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>
    ///     If the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attestation-types">attestation type</a> was successfully determined and a list of Root CA certificates was obtained, the result contains a <see cref="FidoU2FAttestationTypeResult" />. Otherwise, the
    ///     result indicates that an error occurred during the execution of this operation.
    /// </returns>
    protected virtual async Task<Result<FidoU2FAttestationTypeResult>> GetAttestationTypeAsync(
        TContext context,
        X509Certificate2 attCert,
        AttestedAuthenticatorData authenticatorData,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authenticatorData);
        cancellationToken.ThrowIfCancellationRequested();
        var metadataResult = await FindFidoMetadataAsync(context, attCert, authenticatorData, cancellationToken);
        if (metadataResult.HasError)
        {
            return Result<FidoU2FAttestationTypeResult>.Fail();
        }

        var metadata = metadataResult.Ok;
        if (metadata.AttestationTypes.Contains(AuthenticatorAttestationType.ATTESTATION_ATTCA))
        {
            var rootCertificates = new UniqueByteArraysCollection();
            rootCertificates.AddRange(metadata.RootCertificates);
            return Result<FidoU2FAttestationTypeResult>.Success(new(AttestationType.AttCa, rootCertificates));
        }

        if (metadata.AttestationTypes.Contains(AuthenticatorAttestationType.ATTESTATION_BASIC_FULL))
        {
            var rootCertificates = new UniqueByteArraysCollection();
            rootCertificates.AddRange(metadata.RootCertificates);
            return Result<FidoU2FAttestationTypeResult>.Success(new(AttestationType.Basic, rootCertificates));
        }

        return Result<FidoU2FAttestationTypeResult>.Fail();
    }

    /// <summary>
    ///     Searches for data in the FIDO Metadata Service.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="attCert">Attestation certificate in the x509v3 format.</param>
    /// <param name="authenticatorData"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-authenticator-data">Authenticator data</a> that has <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-attestedcredentialdata">attestedCredentialData</a>.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>If data was found, the result contains a <see cref="FidoMetadataResult" />. Otherwise, the result indicates that the data was not found or an error occurred during the process.</returns>
    protected virtual async Task<Result<FidoMetadataResult>> FindFidoMetadataAsync(
        TContext context,
        X509Certificate2 attCert,
        AttestedAuthenticatorData authenticatorData,
        CancellationToken cancellationToken)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (authenticatorData is null)
        {
            return Result<FidoMetadataResult>.Fail();
        }

        if (authenticatorData.AttestedCredentialData.Aaguid != Guid.Empty)
        {
            var aaguidResult = await FidoMetadataSearchService.FindMetadataByAaguidAsync(
                context,
                authenticatorData.AttestedCredentialData.Aaguid,
                cancellationToken);
            if (aaguidResult is not null)
            {
                return Result<FidoMetadataResult>.Success(aaguidResult);
            }
        }
        else
        {
            var embeddedAaguidResult = GetAaguidIfExists(attCert);
            if (embeddedAaguidResult.HasError)
            {
                return Result<FidoMetadataResult>.Fail();
            }

            var embeddedAaguid = embeddedAaguidResult.Ok;
            if (embeddedAaguid.HasValue)
            {
                var embeddedAaguidMetadata = await FidoMetadataSearchService.FindMetadataByAaguidAsync(
                    context,
                    embeddedAaguid.Value,
                    cancellationToken);
                if (embeddedAaguidMetadata is not null)
                {
                    return Result<FidoMetadataResult>.Success(embeddedAaguidMetadata);
                }

                return Result<FidoMetadataResult>.Fail();
            }

            var embeddedSkiResult = GetSubjectKeyIdentifierIfExists(attCert);
            if (embeddedSkiResult.HasError)
            {
                return Result<FidoMetadataResult>.Fail();
            }

            var embeddedSki = embeddedSkiResult.Ok;
            if (embeddedSki is not null)
            {
                var embeddedSkiMetadata = await FidoMetadataSearchService.FindMetadataBySubjectKeyIdentifierAsync(
                    context,
                    embeddedSki,
                    cancellationToken);
                if (embeddedSkiMetadata is not null)
                {
                    return Result<FidoMetadataResult>.Success(embeddedSkiMetadata);
                }

                return Result<FidoMetadataResult>.Fail();
            }
        }

        return Result<FidoMetadataResult>.Fail();
    }

    /// <summary>
    ///     Retrieves the certificate's subject key identifier (SKI) if it is present.
    /// </summary>
    /// <param name="attCert">Attestation certificate in the x509v3 format.</param>
    /// <returns>
    ///     If the certificate has a subject key identifier - the result will contain a byte array, if the certificate does not have a subject key identifier, the result will contain <see langword="null" />. Otherwise, it will indicate that an error occurred during the retrieval of
    ///     the subject key identifier.
    /// </returns>
    protected virtual Result<byte[]?> GetSubjectKeyIdentifierIfExists(X509Certificate2 attCert)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (attCert is null)
        {
            return Result<byte[]?>.Fail();
        }

        var subjectKeyIdentifierExtension = attCert.Extensions.FirstOrDefault(x => x is X509SubjectKeyIdentifierExtension);
        if (subjectKeyIdentifierExtension is X509SubjectKeyIdentifierExtension skiExtension)
        {
            var hexSki = skiExtension.SubjectKeyIdentifier;
            if (!string.IsNullOrEmpty(hexSki))
            {
                var binarySki = Convert.FromHexString(hexSki);
                return Result<byte[]?>.Success(binarySki);
            }
        }

        return Result<byte[]?>.Success(null);
    }

    /// <summary>
    ///     Retrieves the aaguid from the certificate if it is present.
    /// </summary>
    /// <param name="attCert">Attestation certificate in the x509v3 format.</param>
    /// <returns>If the certificate has an aaguid - the result will contain a <see cref="Guid" />, if the certificate doesn't have an aaguid, the result will contain <see langword="null" />. Otherwise, it will indicate that an error occurred during the retrieval of the aaguid.</returns>
    protected virtual Result<Guid?> GetAaguidIfExists(X509Certificate2 attCert)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (attCert is null)
        {
            return Result<Guid?>.Fail();
        }

        // If the related attestation root certificate is used for multiple authenticator models,
        // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present,
        // containing the AAGUID as a 16-byte OCTET STRING. The extension MUST NOT be marked as critical.
        // Note that an X.509 Extension encodes the DER-encoding of the value in an OCTET STRING.
        // Thus, the AAGUID MUST be wrapped in two OCTET STRINGS to be valid.
        var extension = attCert.Extensions.FirstOrDefault(static x => x.Oid?.Value is "1.3.6.1.4.1.45724.1.1.4"); // id-fido-gen-ce-aaguid
        if (extension is not null)
        {
            if (extension.Critical)
            {
                return Result<Guid?>.Fail();
            }

            var deserializeResult = Asn1Deserializer.Deserialize(extension.RawData, AsnEncodingRules.BER);
            if (deserializeResult.HasError)
            {
                return Result<Guid?>.Fail();
            }

            if (deserializeResult.Ok is null)
            {
                return Result<Guid?>.Fail();
            }

            if (deserializeResult.Ok is not Asn1OctetString aaguidOctetString)
            {
                return Result<Guid?>.Fail();
            }

            if (aaguidOctetString.Value.Length != 16)
            {
                return Result<Guid?>.Fail();
            }

            var hexAaguid = Convert.ToHexString(aaguidOctetString.Value);
            var typedAaguid = new Guid(hexAaguid);
            return Result<Guid?>.Success(typedAaguid);
        }

        return Result<Guid?>.Success(null);
    }

    /// <summary>
    ///     Verifies the public key parameters and returns its out parameter ><paramref name="attCertEcParameters" /> as the .NET built-in type <see cref="ECParameters" />, if they contain correct values.
    /// </summary>
    /// <param name="attCert">Attestation certificate in the x509v3 format.</param>
    /// <param name="attCertEcParameters">Output parameter. If the method returns true, it contains public key parameters; otherwise - <see langword="null" />.</param>
    /// <returns>If the public key parameters are correct - returns <see langword="true" />, otherwise - <see langword="false" />.</returns>
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool IsValidPublicKeyParameters(X509Certificate2 attCert, [NotNullWhen(true)] out ECParameters? attCertEcParameters)
    {
        //  If certificate public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate this algorithm and return an appropriate error.
        if (attCert is null)
        {
            attCertEcParameters = null;
            return false;
        }

        var ecDsaPubKey = attCert.GetECDsaPublicKey();
        if (ecDsaPubKey is null)
        {
            attCertEcParameters = null;
            return false;
        }

        var parameters = ecDsaPubKey.ExportParameters(false);
        if (parameters.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
        {
            attCertEcParameters = null;
            return false;
        }

        attCertEcParameters = parameters;
        return true;
    }

    /// <summary>
    ///     Converts the public key from COSE format to Raw ANSI X9.62 public key format.
    /// </summary>
    /// <param name="credentialPublicKey">Public key in COSE format.</param>
    /// <param name="publicKeyU2F">Output parameter. If conversion was successful - contains a key in Raw ANSI X9.62 format as a byte array, otherwise - <see langword="null" />.</param>
    /// <returns>If the conversion was successful - returns <see langword="true" />, otherwise - <see langword="false" />.</returns>
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool TryConvertCoseKeyToPublicKeyU2F(CoseEc2Key credentialPublicKey, [NotNullWhen(true)] out byte[]? publicKeyU2F)
    {
        if (credentialPublicKey is null)
        {
            publicKeyU2F = null;
            return false;
        }

        // Let 'x' be the value corresponding to the "-2" key (representing x coordinate) in 'credentialPublicKey',
        // and confirm its size to be of 32 bytes.
        // If size differs or "-2" key is not found, terminate this algorithm and return an appropriate error.
        if (credentialPublicKey.X.Length != 32)
        {
            publicKeyU2F = null;
            return false;
        }

        // Let 'y' be the value corresponding to the "-3" key (representing y coordinate) in 'credentialPublicKey',
        // and confirm its size to be of 32 bytes.
        // If size differs or "-3" key is not found, terminate this algorithm and return an appropriate error.
        if (credentialPublicKey.Y.Length != 32)
        {
            publicKeyU2F = null;
            return false;
        }

        // Let 'publicKeyU2F' be the concatenation 0x04 || 'x' || 'y'.
        publicKeyU2F = Concat(stackalloc byte[1] { 0x04 }, credentialPublicKey.X, credentialPublicKey.Y);
        return true;
    }

    /// <summary>
    ///     Concatenates three ReadOnlySpan of bytes into one array.
    /// </summary>
    /// <param name="a">First ReadOnlySpan of bytes.</param>
    /// <param name="b">Second ReadOnlySpan of bytes.</param>
    /// <param name="c">Third ReadOnlySpan of bytes.</param>
    /// <returns>An array of bytes, filled with the content of the passed ReadOnlySpans.</returns>
    protected virtual byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c)
    {
        var result = new byte[a.Length + b.Length + c.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        c.CopyTo(result.AsSpan(a.Length + b.Length));
        return result;
    }

    /// <summary>
    ///     Concatenates five ReadOnlySpan of bytes into one array.
    /// </summary>
    /// <param name="a">First ReadOnlySpan of bytes.</param>
    /// <param name="b">Second ReadOnlySpan of bytes.</param>
    /// <param name="c">Third ReadOnlySpan of bytes.</param>
    /// <param name="d">Fourth ReadOnlySpan of bytes.</param>
    /// <param name="e">Fifth ReadOnlySpan of bytes.</param>
    /// <returns>An array of bytes, filled with the content of the passed ReadOnlySpans.</returns>
    protected virtual byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, ReadOnlySpan<byte> c, ReadOnlySpan<byte> d, ReadOnlySpan<byte> e)
    {
        var result = new byte[a.Length + b.Length + c.Length + d.Length + e.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        c.CopyTo(result.AsSpan(a.Length + b.Length));
        c.CopyTo(result.AsSpan(a.Length + b.Length));
        d.CopyTo(result.AsSpan(a.Length + b.Length + c.Length));
        e.CopyTo(result.AsSpan(a.Length + b.Length + c.Length + d.Length));
        return result;
    }
}
