using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models.Enums.Extensions;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models;

/// <summary>
///     The TPMT_PUBLIC structure (see [TPMv2-Part2] section 12.2.4) used by the TPM to represent the credential public key.
/// </summary>
public class PubArea
{
    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    protected PubArea(
        TpmAlgPublic type,
        TpmAlgIdHash nameAlg,
        ObjectAttributes objectAttributes,
        AbstractPublicParms parameters,
        AbstractUnique unique)
    {
        Type = type;
        NameAlg = nameAlg;
        ObjectAttributes = objectAttributes;
        Parameters = parameters;
        Unique = unique;
    }

    public TpmAlgPublic Type { get; }

    public TpmAlgIdHash NameAlg { get; }

    public ObjectAttributes ObjectAttributes { get; }

    public AbstractPublicParms Parameters { get; }

    public AbstractUnique Unique { get; }

    public virtual bool TryToAsymmetricAlgorithm([NotNullWhen(true)] out AsymmetricAlgorithm? algorithm)
    {
        switch (Type)
        {
            case TpmAlgPublic.Rsa:
                {
                    if (Unique is not RsaUnique tpmModulus)
                    {
                        algorithm = null;
                        return false;
                    }

                    if (Parameters is not RsaParms tpmExponent)
                    {
                        algorithm = null;
                        return false;
                    }

                    var pubAreaExponent = new byte[4];
                    BinaryPrimitives.WriteUInt32BigEndian(pubAreaExponent, tpmExponent.Exponent);
                    var rsa = RSA.Create(new RSAParameters
                    {
                        Modulus = tpmModulus.Buffer,
                        Exponent = pubAreaExponent
                    });
                    algorithm = rsa;
                    return true;
                }
            case TpmAlgPublic.Ecc:
                {
                    if (Unique is not EccUnique tpmEcPoint)
                    {
                        algorithm = null;
                        return false;
                    }

                    if (Parameters is not EccParms tpmCurve)
                    {
                        algorithm = null;
                        return false;
                    }

                    if (!tpmCurve.CurveId.TryToEcCurve(out var ecCurve))
                    {
                        algorithm = null;
                        return false;
                    }

                    var point = new ECPoint
                    {
                        X = tpmEcPoint.X,
                        Y = tpmEcPoint.Y
                    };
                    using var ecdsa = ECDsa.Create(new ECParameters
                    {
                        Q = point,
                        Curve = ecCurve.Value
                    });
                    algorithm = ecdsa;
                    return true;
                }
            default:
                {
                    algorithm = null;
                    return false;
                }
        }
    }

    public static bool TryParse(Span<byte> bytes, [NotNullWhen(true)] out PubArea? pubArea)
    {
        var buffer = bytes;
        // 12.2.4 TPMT_PUBLIC
        // Table 200 defines the public area structure. The Name of the object is nameAlg concatenated with the digest of this structure using nameAlg.
        // Table 200 — Definition of TPMT_PUBLIC Structure
        // | Parameter        | Type              | Description
        // | type             | TPMI_ALG_PUBLIC   | "Algorithm" associated with this object.
        // | nameAlg          | +TPMI_ALG_HASH    | Algorithm used for computing the Name of the object. Note: The "+" indicates that the instance of a TPMT_PUBLIC may have a "+" to indicate that the nameAlg may be TPM_ALG_NULL.
        // | objectAttributes | TPMA_OBJECT       | Attributes that, along with type, determine the manipulations of this object.
        // | authPolicy       | TPM2B_DIGEST      | Optional policy for using this key. The policy is computed using the nameAlg of the object. Note: Shall be the Empty Policy if no authorization policy is present.
        // | [type]parameters | TPMU_PUBLIC_PARMS | The algorithm or structure details.
        // | [type]unique     | TPMU_PUBLIC_ID    | The unique identifier of the structure. For an asymmetric key, this would be the public key.

        // type
        if (!TryConsume(ref buffer, 2, out var rawType))
        {
            pubArea = null;
            return false;
        }

        var type = (TpmAlgPublic) BinaryPrimitives.ReadUInt16BigEndian(rawType);
        if (!Enum.IsDefined(type))
        {
            pubArea = null;
            return false;
        }

        // nameAlg
        if (!TryConsume(ref buffer, 2, out var rawNameAlg))
        {
            pubArea = null;
            return false;
        }

        var nameAlg = (TpmAlgIdHash) BinaryPrimitives.ReadUInt16BigEndian(rawNameAlg);
        if (!Enum.IsDefined(nameAlg))
        {
            pubArea = null;
            return false;
        }

        // objectAttributes
        if (!TryConsume(ref buffer, 4, out var rawObjectAttributes))
        {
            pubArea = null;
            return false;
        }

        var objectAttributes = (ObjectAttributes) BinaryPrimitives.ReadUInt32BigEndian(rawObjectAttributes);

        // authPolicy
        // 10.4.2 TPM2B_DIGEST
        // This structure is used for a sized buffer that cannot be larger than the largest digest produced by any hash algorithm implemented on the TPM.
        // Table 80 — Definition of TPM2B_DIGEST Structure
        // | Parameter                      | Type           | Description
        // | size                           | UINT16         | size in octets of the buffer field; may be 0
        // | buffer[size]{:sizeof(TPMU_HA)} | +TPMI_ALG_HASH | the buffer area that can be no larger than a digest
        // ------
        // skip authPolicy
        if (!TryConsume(ref buffer, 2, out var rawAuthPolicySize))
        {
            pubArea = null;
            return false;
        }

        var authPolicySize = BinaryPrimitives.ReadUInt16BigEndian(rawAuthPolicySize);
        if (authPolicySize > 0)
        {
            if (!TryConsume(ref buffer, authPolicySize, out _))
            {
                pubArea = null;
                return false;
            }
        }

        // [type]parameters
        if (!AbstractPublicParms.TryParse(ref buffer, type, objectAttributes, out var parameters))
        {
            pubArea = null;
            return false;
        }

        //[type]unique
        if (!AbstractUnique.TryParse(ref buffer, type, out var unique))
        {
            pubArea = null;
            return false;
        }

        if (buffer.Length > 0)
        {
            pubArea = null;
            return false;
        }

        pubArea = new(type, nameAlg, objectAttributes, parameters, unique);
        return true;
    }

    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    protected static bool TryConsume(ref Span<byte> input, int bytesToConsume, out Span<byte> consumed)
    {
        if (input.Length < bytesToConsume)
        {
            consumed = default;
            return false;
        }

        consumed = input[..bytesToConsume];
        input = input[bytesToConsume..];
        return true;
    }
}
