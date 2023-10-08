using System;
using System.Security.Cryptography;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.ChallengeGenerator.Implementation;

public class DefaultChallengeGenerator : IChallengeGenerator
{
    public byte[] GenerateChallenge(int size)
    {
        // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-cryptographic-challenges
        if (size < 16)
        {
            throw new ArgumentException($"The minimum value of {nameof(size)} is 16.", nameof(size));
        }

        return RandomNumberGenerator.GetBytes(size);
    }
}
