using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace WebAuthn.Net.Services.Static;

/// <summary>
///     A static utility for validating JWT tokens.
/// </summary>
public static class JwtValidator
{
    /// <summary>
    ///     The JWS algorithms accepted for the tokens validated by this utility: the asymmetric (RSA and ECDSA) signature algorithms of <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">RFC 7518 §3.1</a>.
    ///     The tokens are always verified with public keys taken from certificates, so 'none' and the HMAC algorithms are never acceptable, regardless of how the token handler treats them.
    /// </summary>
    private static readonly string[] AsymmetricSignatureAlgorithms =
    {
        SecurityAlgorithms.RsaSha256,
        SecurityAlgorithms.RsaSha384,
        SecurityAlgorithms.RsaSha512,
        SecurityAlgorithms.RsaSsaPssSha256,
        SecurityAlgorithms.RsaSsaPssSha384,
        SecurityAlgorithms.RsaSsaPssSha512,
        SecurityAlgorithms.EcdsaSha256,
        SecurityAlgorithms.EcdsaSha384,
        SecurityAlgorithms.EcdsaSha512
    };

    /// <summary>
    ///     Validates the JWT token, allowing it to be as large as twice its own length (but at least <see cref="TokenValidationParameters.DefaultMaximumTokenSizeInBytes" />).
    ///     Intended for tokens from trusted sources whose size is not bounded by this utility (for example, the FIDO Metadata Service blob); for tokens received from clients, use the overload with an explicit size limit.
    /// </summary>
    /// <param name="jwt">The JWT token that needs to be validated.</param>
    /// <param name="securityKeys">The keys with which the content of the JWT token should be signed.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>The result of the JWT token validation</returns>
    public static Task<TokenValidationResult> ValidateAsync(
        string jwt,
        IReadOnlyCollection<SecurityKey> securityKeys,
        CancellationToken cancellationToken)
    {
        var maximumTokenSizeInBytes = 0;
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (jwt is not null)
        {
            maximumTokenSizeInBytes = Math.Max(TokenValidationParameters.DefaultMaximumTokenSizeInBytes, jwt.Length * 2);
        }

        return ValidateAsync(jwt!, securityKeys, maximumTokenSizeInBytes, cancellationToken);
    }

    /// <summary>
    ///     Validates the JWT token, rejecting tokens larger than <paramref name="maximumTokenSizeInBytes" />.
    /// </summary>
    /// <param name="jwt">The JWT token that needs to be validated.</param>
    /// <param name="securityKeys">The keys with which the content of the JWT token should be signed.</param>
    /// <param name="maximumTokenSizeInBytes">The maximum size of the token (in characters of the compact serialization) that will be validated; a larger token is reported as invalid.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>The result of the JWT token validation</returns>
    [SuppressMessage("Security", "CA5404:Do not disable token validation checks")]
    public static async Task<TokenValidationResult> ValidateAsync(
        string jwt,
        IReadOnlyCollection<SecurityKey> securityKeys,
        int maximumTokenSizeInBytes,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = securityKeys,
            // only the asymmetric JWS algorithms are acceptable: the tokens are verified with public keys, so 'none' and the HMAC algorithms can never match them
            ValidAlgorithms = AsymmetricSignatureAlgorithms,
            ValidateLifetime = false,
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateSignatureLast = false,
            TryAllIssuerSigningKeys = true
        };
        var tokenHandler = new JwtSecurityTokenHandler
        {
            MaximumTokenSizeInBytes = maximumTokenSizeInBytes
        };
        tokenHandler.InboundClaimFilter.Clear();
        tokenHandler.InboundClaimTypeMap.Clear();
        tokenHandler.OutboundAlgorithmMap.Clear();
        tokenHandler.OutboundClaimTypeMap.Clear();
        return await tokenHandler.ValidateTokenAsync(jwt, validationParameters);
    }
}
