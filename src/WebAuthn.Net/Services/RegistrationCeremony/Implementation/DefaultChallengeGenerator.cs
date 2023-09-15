using System;
using System.Security.Cryptography;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation;

public class DefaultChallengeGenerator : IChallengeGenerator
{
    public byte[] GenerateChallenge(int size)
    {
        // https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges
        if (size < 16)
        {
            throw new ArgumentException($"The minimum value of {nameof(size)} is 16.", nameof(size));
        }

        return RandomNumberGenerator.GetBytes(size);
    }
}
