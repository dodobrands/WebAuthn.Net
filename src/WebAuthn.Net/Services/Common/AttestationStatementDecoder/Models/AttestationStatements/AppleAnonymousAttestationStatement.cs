using System;
using System.Linq;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;

/// <summary>
///     Decoded <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-apple-anonymous-attestation">Apple Anonymous attestation statement</a>.
/// </summary>
public class AppleAnonymousAttestationStatement : AbstractAttestationStatement
{
    /// <summary>
    ///     Constructs <see cref="AppleAnonymousAttestationStatement" />.
    /// </summary>
    /// <param name="x5C">credCert (the credential public key certificate used for attestation, encoded in X.509 format) followed by its certificate chain, each encoded in X.509 format.</param>
    /// <exception cref="ArgumentNullException"><paramref name="x5C" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException">One of the <paramref name="x5C" /> elements is <see langword="null" /></exception>
    public AppleAnonymousAttestationStatement(byte[][] x5C)
    {
        ArgumentNullException.ThrowIfNull(x5C);
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (x5C.Any(static x => x is null))
        {
            throw new ArgumentException($"One or more objects contained in the {nameof(x5C)} array are equal to null.", nameof(x5C));
        }

        X5C = x5C;
    }

    /// <summary>
    ///     credCert (the credential public key certificate used for attestation, encoded in X.509 format) followed by its certificate chain, each encoded in X.509 format.
    /// </summary>
    public byte[][] X5C { get; }
}
