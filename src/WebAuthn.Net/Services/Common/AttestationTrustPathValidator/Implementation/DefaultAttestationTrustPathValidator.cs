using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AttestationTrustPathValidator.Implementation.Constants;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Static;
using WebAuthn.Net.Storage.AndroidKeyAttestationStatus;

namespace WebAuthn.Net.Services.Common.AttestationTrustPathValidator.Implementation;

/// <summary>
///     Default implementation of <see cref="IAttestationTrustPathValidator" />.
/// </summary>
public class DefaultAttestationTrustPathValidator : IAttestationTrustPathValidator
{
    /// <summary>
    ///     Constructs <see cref="DefaultAttestationTrustPathValidator" />.
    /// </summary>
    /// <param name="options">Accessor for getting the current value of global options.</param>
    /// <param name="statusStorage">Storage of the certificate revocation status list of the Android attestation keys that is in use.</param>
    /// <param name="serialNumberFormatter">Formatter of the serial numbers in the form of the keys of the certificate revocation status list of the Android attestation keys, used to look the certificates up in it.</param>
    /// <param name="statusCounters">Counters for the metrics of the certificate revocation status list of the Android attestation keys, used to count the attestation statements that it rejects.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultAttestationTrustPathValidator(
        IOptionsMonitor<WebAuthnOptions> options,
        IAndroidKeyAttestationStatusStorage statusStorage,
        IAndroidKeyAttestationStatusSerialNumberFormatter serialNumberFormatter,
        IAndroidKeyAttestationStatusCounters statusCounters,
        ILogger<DefaultAttestationTrustPathValidator> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(statusStorage);
        ArgumentNullException.ThrowIfNull(serialNumberFormatter);
        ArgumentNullException.ThrowIfNull(statusCounters);
        ArgumentNullException.ThrowIfNull(logger);
        Options = options;
        StatusStorage = statusStorage;
        SerialNumberFormatter = serialNumberFormatter;
        StatusCounters = statusCounters;
        Logger = logger;
    }

    /// <summary>
    ///     Accessor for getting the current value of global options.
    /// </summary>
    protected IOptionsMonitor<WebAuthnOptions> Options { get; }

    /// <summary>
    ///     Storage of the certificate revocation status list of the Android attestation keys that is in use.
    /// </summary>
    protected IAndroidKeyAttestationStatusStorage StatusStorage { get; }

    /// <summary>
    ///     Formatter of the serial numbers in the form of the keys of the certificate revocation status list of the Android attestation keys, used to look the certificates up in it.
    /// </summary>
    protected IAndroidKeyAttestationStatusSerialNumberFormatter SerialNumberFormatter { get; }

    /// <summary>
    ///     Counters for the metrics of the certificate revocation status list of the Android attestation keys, used to count the attestation statements that it rejects.
    /// </summary>
    protected IAndroidKeyAttestationStatusCounters StatusCounters { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultAttestationTrustPathValidator> Logger { get; }

    /// <inheritdoc />
    /// <remarks>
    ///     <para>
    ///         The <a href="https://www.w3.org/TR/webauthn-3/#attestation-trust-path">attestation trust path</a> of <a href="https://www.w3.org/TR/webauthn-3/#self-attestation">self attestation</a> and of
    ///         <a href="https://www.w3.org/TR/webauthn-3/#none">no attestation</a> is empty, and step 24 of <a href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">§7.1</a> assesses them
    ///         by the policy of the Relying Party only, so a result of these types is valid only if it has no trust path.
    ///     </para>
    ///     <para>
    ///         For the other attestation types, the trust path must chain up to one of the root certificates of the result, or its single certificate must be the single root certificate.
    ///         If the chain ends at a root certificate of the key attestation of Google, its certificates must also pass the certificate revocation status list of the Android attestation keys,
    ///         whatever the attestation statement format (see <see cref="IsTrustedByStatusListAsync" />).
    ///     </para>
    /// </remarks>
    public virtual async Task<bool> IsValidAsync(VerifiedAttestationStatement verificationResult, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (verificationResult is null)
        {
            return false;
        }

        switch (verificationResult.AttestationType)
        {
            case AttestationType.None:
            case AttestationType.Self:
                {
                    // §6.5.2: "This attestation trust path is either empty (in case of self attestation), or a set of X.509 certificates";
                    // the verification procedures of the packed self attestation (§8.2) and of the none attestation statement format (§8.7) return an empty trust path.
                    // There is nothing to chain up to a root certificate, so a result of these types that has a trust path contradicts the specification and is rejected.
                    return verificationResult.AttestationTrustPath is null;
                }
            case AttestationType.Basic:
            case AttestationType.AttCa:
            case AttestationType.AnonCa:
                {
                    if (verificationResult.AttestationTrustPath is null)
                    {
                        return false;
                    }

                    if (verificationResult.AttestationRootCertificates is null)
                    {
                        return false;
                    }


                    return await IsValidAsync(
                        verificationResult.Fmt,
                        verificationResult.AttestationTrustPath,
                        verificationResult.AttestationRootCertificates.ToArray(),
                        cancellationToken);
                }
            default:
                {
                    return false;
                }
        }
    }

    /// <summary>
    ///     Validates the <a href="https://www.w3.org/TR/webauthn-3/#attestation-trust-path">attestation trust path</a>
    /// </summary>
    /// <param name="fmt">The attestation statement format whose verification procedure returned the trust path.</param>
    /// <param name="attestationTrustPath"><a href="https://www.w3.org/TR/webauthn-3/#attestation-trust-path">Attestation trust path</a>, containing a certificate chain that needs to be validated.</param>
    /// <param name="attestationRootCertificates">Root CA certificates, one of which should fit for the verification of the certificate chain specified in the <paramref name="attestationTrustPath" /></param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>
    ///     <see langword="true" /> if the certificate chain from <paramref name="attestationTrustPath" /> is successfully validated by one of the Root CA certificates specified in <paramref name="attestationRootCertificates" />
    ///     and passes the certificate revocation status list of the Android attestation keys, otherwise - <see langword="false" />.
    /// </returns>
    [SuppressMessage("ReSharper", "ConditionalAccessQualifierIsNonNullableAccordingToAPIContract")]
    protected virtual async Task<bool> IsValidAsync(
        AttestationStatementFormat fmt,
        byte[][] attestationTrustPath,
        byte[][] attestationRootCertificates,
        CancellationToken cancellationToken)
    {
        if (!(attestationTrustPath?.Length > 0 && attestationRootCertificates?.Length > 0))
        {
            return false;
        }

        byte[][]? chainCertificates;
        if (attestationRootCertificates.Length == 1
            && attestationTrustPath.Length == 1
            && attestationRootCertificates[0].AsSpan().SequenceEqual(attestationTrustPath[0].AsSpan()))
        {
            // The certificate of the trust path is itself the acceptable root certificate.
            chainCertificates = attestationTrustPath;
        }
        else if (!X509TrustChainValidator.TryBuildAttestationTrustPathChain(
                     attestationRootCertificates,
                     attestationTrustPath,
                     Options.CurrentValue.X509ChainValidation.OnValidateAttestationTrustPathChain,
                     out chainCertificates))
        {
            return false;
        }

        return await IsTrustedByStatusListAsync(fmt, chainCertificates, cancellationToken);
    }

    /// <summary>
    ///     Checks the certificates of the chain against the <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">certificate revocation status list</a>
    ///     that Google publishes for the Android attestation keys, if the chain ends at a <a href="https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate">root certificate of the key attestation of Google</a>.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         Google <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">requires</a> to check the status of each certificate in such a chain against the status list,
    ///         which contains the certificates that don't have a normal valid status. Therefore, a certificate in the status list is untrusted whatever its status (REVOKED, SUSPENDED or another one),
    ///         and so is the attestation statement. The certificates are looked up by their serial numbers in the form of the keys of the status list (see <see cref="IAndroidKeyAttestationStatusSerialNumberFormatter" />).
    ///     </para>
    ///     <para>
    ///         This applies to every attestation statement format, not only to "Android Key": an Android attestation key (for example, one extracted from a device) can sign any certificate,
    ///         such as the attestation certificate of a "Packed" attestation statement, and the FIDO Metadata Service lists the root certificates of Google as the trust anchors of the Android authenticator.
    ///     </para>
    ///     <para>
    ///         While no status list is available (for example, before the first successful download), such a chain is rejected too: it can't be told from one with a revoked certificate.
    ///     </para>
    /// </remarks>
    /// <param name="fmt">The attestation statement format whose verification procedure returned the trust path.</param>
    /// <param name="chainCertificates">The DER-encoded certificates of the chain, from the first certificate of the attestation trust path up to the root certificate.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>
    ///     <see langword="true" /> if the chain doesn't end at a root certificate of the key attestation of Google, or if a status list is available and none of the certificates of the chain is in it,
    ///     otherwise - <see langword="false" />.
    /// </returns>
    protected virtual async Task<bool> IsTrustedByStatusListAsync(AttestationStatementFormat fmt, byte[][] chainCertificates, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(chainCertificates);
        cancellationToken.ThrowIfCancellationRequested();
        var certificates = new List<X509Certificate2>(chainCertificates.Length);
        try
        {
            foreach (var certificateBytes in chainCertificates)
            {
                if (!X509CertificateInMemoryLoader.TryLoad(certificateBytes, out var certificate))
                {
                    certificate?.Dispose();
                    return false;
                }

                certificates.Add(certificate);
            }

            if (certificates.Count == 0 || !IsGoogleAttestationRoot(certificates[^1]))
            {
                return true;
            }

            var statusList = await StatusStorage.GetAsync(cancellationToken);
            if (statusList is null)
            {
                Logger.StatusListNotAvailable(fmt);
                StatusCounters.IncrementCheckWithoutStatusList();
                return false;
            }

            for (var index = 0; index < certificates.Count; index++)
            {
                if (SerialNumberFormatter.TryFormat(certificates[index], out var serialNumber)
                    && statusList.Entries.TryGetValue(serialNumber, out var entry))
                {
                    Logger.CertificateInStatusList(index, serialNumber, fmt, entry.Status, entry.Reason);
                    StatusCounters.IncrementCertificateListed();
                    return false;
                }
            }

            return true;
        }
        finally
        {
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }

    /// <summary>
    ///     Returns the root certificates of the key attestation of Google. A chain that ends at a certificate with the key of one of them is checked against the certificate revocation status list of the Android attestation keys.
    /// </summary>
    /// <returns>By default, the root certificates that Google publishes for the key attestation (<see cref="GoogleAttestationRoots.Certificates" />).</returns>
    protected virtual UniqueByteArraysCollection GetGoogleAttestationRootCertificates()
    {
        return new(GoogleAttestationRoots.Certificates);
    }

    // A root certificate is identified by its key, so that a root certificate that Google issues again for the same key is recognized as well.
    private bool IsGoogleAttestationRoot(X509Certificate2 rootCertificate)
    {
        var subjectPublicKeyInfo = rootCertificate.PublicKey.ExportSubjectPublicKeyInfo();
        foreach (var googleRootBytes in GetGoogleAttestationRootCertificates())
        {
            if (!X509CertificateInMemoryLoader.TryLoad(googleRootBytes, out var googleRoot))
            {
                googleRoot?.Dispose();
                continue;
            }

            using (googleRoot)
            {
                if (googleRoot.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(subjectPublicKeyInfo))
                {
                    return true;
                }
            }
        }

        return false;
    }
}

/// <summary>
///     Extension methods for logging the attestation trust path validator.
/// </summary>
public static partial class DefaultAttestationTrustPathValidatorLoggingExtensions
{
    /// <summary>
    ///     The certificate revocation status list of the Android attestation keys is not available, so the '{Fmt}' attestation statement, whose certificate chain ends at a root certificate of the key attestation of Google, is rejected
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="fmt">The attestation statement format.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The certificate revocation status list of the Android attestation keys is not available, so the '{Fmt}' attestation statement, whose certificate chain ends at a root certificate of the key attestation of Google, is rejected")]
    public static partial void StatusListNotAvailable(this ILogger logger, AttestationStatementFormat fmt);

    /// <summary>
    ///     The certificate #{Index} (serial number '{SerialNumber}') of the certificate chain of the '{Fmt}' attestation statement is in the certificate revocation status list of the Android attestation keys with the status '{Status}' and the reason '{Reason}'
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="index">The zero-based index of the certificate in the chain, from the first certificate of the attestation trust path up to the root certificate.</param>
    /// <param name="serialNumber">The serial number of the certificate in lowercase hexadecimal.</param>
    /// <param name="fmt">The attestation statement format.</param>
    /// <param name="status">The status of the entry, or <see langword="null" /> if it has none that the library knows.</param>
    /// <param name="reason">The reason of the entry, or <see langword="null" /> if it has none that the library knows.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The certificate #{Index} (serial number '{SerialNumber}') of the certificate chain of the '{Fmt}' attestation statement is in the certificate revocation status list of the Android attestation keys with the status '{Status}' and the reason '{Reason}'")]
    public static partial void CertificateInStatusList(this ILogger logger, int index, string serialNumber, AttestationStatementFormat fmt, AndroidKeyAttestationRevocationStatus? status, AndroidKeyAttestationRevocationReason? reason);
}
