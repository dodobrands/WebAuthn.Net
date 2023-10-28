namespace WebAuthn.Net.Services.Common.ChallengeGenerator;

public interface IChallengeGenerator
{
    /// <summary>
    /// </summary>
    /// <param name="size"></param>
    /// <returns></returns>
    public byte[] GenerateChallenge(int size);
}
