namespace WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions.Enums;

public enum CredentialBackupStateRecommendedAction
{
    RequiringAdditionalAuthenticators = 1,
    UpgradingUserToPasswordlessAccount = 2,
    AddingAdditionalFactorAfterStateChange = 3
}
