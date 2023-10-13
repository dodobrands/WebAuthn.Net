namespace WebAuthn.Net.Services.TrustChainValidator.Models;

public class TrustChainVerificationResult
{
    public TrustChainVerificationResult(bool isVerificationRequired, bool hasVerifiedTrustChain)
    {
        IsVerificationRequired = isVerificationRequired;
        HasVerifiedTrustChain = hasVerifiedTrustChain;
    }

    public bool IsVerificationRequired { get; }

    public bool HasVerifiedTrustChain { get; }
}
