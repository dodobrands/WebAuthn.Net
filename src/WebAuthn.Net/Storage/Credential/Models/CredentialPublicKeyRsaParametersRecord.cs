namespace WebAuthn.Net.Storage.Credential.Models;

/// <summary>
///     Model for storing data about a public COSE key in RSA format.
/// </summary>
public class CredentialPublicKeyRsaParametersRecord
{
    /// <summary>
    ///     Constructs <see cref="CredentialPublicKeyRsaParametersRecord" />.
    /// </summary>
    /// <param name="modulusN">RSA modulus N.</param>
    /// <param name="exponentE">RSA exponent E.</param>
    public CredentialPublicKeyRsaParametersRecord(byte[] modulusN, byte[] exponentE)
    {
        ModulusN = modulusN;
        ExponentE = exponentE;
    }

    /// <summary>
    ///     RSA modulus N.
    /// </summary>
    public byte[] ModulusN { get; }

    /// <summary>
    ///     RSA exponent E.
    /// </summary>
    public byte[] ExponentE { get; }
}
