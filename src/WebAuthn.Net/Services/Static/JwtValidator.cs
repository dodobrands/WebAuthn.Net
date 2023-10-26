using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace WebAuthn.Net.Services.Static;

public static class JwtValidator
{
    [SuppressMessage("Security", "CA5404:Do not disable token validation checks")]
    public static async Task<TokenValidationResult> ValidateAsync(
        string jwt,
        IReadOnlyCollection<SecurityKey> securityKeys,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var maximumTokenSizeInBytes = 0;
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (jwt is not null)
        {
            maximumTokenSizeInBytes = Math.Max(TokenValidationParameters.DefaultMaximumTokenSizeInBytes, jwt.Length * 2);
        }

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = securityKeys,
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
