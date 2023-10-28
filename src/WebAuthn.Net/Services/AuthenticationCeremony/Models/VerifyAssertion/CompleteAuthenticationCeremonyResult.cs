using System;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions.Enums;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Models.VerifyAssertion;

public class CompleteAuthenticationCeremonyResult
{
    public CompleteAuthenticationCeremonyResult(
        bool successful,
        CredentialBackupStateRecommendedAction[] recommendedActions,
        bool requireAuthorizationByAdditionalFactorBecauseUserVerificationFlagWasUpdated)
    {
        Successful = successful;
        RecommendedActions = recommendedActions;
        RequireAuthorizationByAdditionalFactorBecauseUserVerificationFlagWasUpdated = requireAuthorizationByAdditionalFactorBecauseUserVerificationFlagWasUpdated;
    }

    public bool Successful { get; }
    public CredentialBackupStateRecommendedAction[] RecommendedActions { get; }
    public bool RequireAuthorizationByAdditionalFactorBecauseUserVerificationFlagWasUpdated { get; }

    public static CompleteAuthenticationCeremonyResult Success(
        CredentialBackupStateRecommendedAction[] recommendedActions,
        bool requireAuthorization)
    {
        return new(true, recommendedActions, requireAuthorization);
    }

    public static CompleteAuthenticationCeremonyResult Fail()
    {
        return new(
            false,
            Array.Empty<CredentialBackupStateRecommendedAction>(),
            false);
    }
}
