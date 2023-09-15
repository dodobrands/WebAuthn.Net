using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Extensions;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony;
using WebAuthn.Net.Services.Context;
using WebAuthn.Net.Services.RegistrationCeremony.Models;
using WebAuthn.Net.Services.TimeProvider;
using WebAuthn.Net.Storage.Operations;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation;

public class DefaultRegistrationCeremonyService<TContext> : IRegistrationCeremonyService
    where TContext : class, IWebAuthnContext
{
    private readonly IChallengeGenerator _challengeGenerator;
    private readonly IWebAuthnContextFactory<TContext> _contextFactory;
    private readonly IOperationalStorage<TContext> _storage;
    private readonly ITimeProvider _timeProvider;

    public DefaultRegistrationCeremonyService(
        IWebAuthnContextFactory<TContext> contextFactory,
        IChallengeGenerator challengeGenerator,
        IOperationalStorage<TContext> storage,
        ITimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(contextFactory);
        ArgumentNullException.ThrowIfNull(challengeGenerator);
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(timeProvider);
        _contextFactory = contextFactory;
        _challengeGenerator = challengeGenerator;
        _storage = storage;
        _timeProvider = timeProvider;
    }

    public async Task<BeginCeremonyResult> BeginCeremonyAsync(
        HttpContext httpContext,
        BeginCeremonyRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        await using var context = await _contextFactory.CreateAsync(httpContext, cancellationToken);
        var challenge = _challengeGenerator.GenerateChallenge(request.ChallengeSize);
        var credentialsToExclude = await GetCredentialsToExcludeAsync(
            context,
            request.Rp,
            request.User,
            request.ExcludeCredentials,
            cancellationToken);
        var createdAt = _timeProvider.GetUtcDateTime();
        var expiresAt = createdAt.ComputeExpiresAtUtc(request.Timeout);
        var ceremonyId = await _storage.SaveRegistrationCeremonyAsync(
            context,
            challenge,
            request.Rp,
            request.User,
            request.PubKeyCredParams,
            request.Timeout,
            credentialsToExclude,
            request.AuthenticatorSelection,
            request.Attestation,
            createdAt,
            expiresAt,
            cancellationToken);
        await context.CommitAsync(cancellationToken);
        var options = ConvertToOptions(request, challenge, credentialsToExclude);
        return new(options, ceremonyId);
    }

    public async Task<Result<RegistrationCeremonyResult>> HandleAsync(
        HttpContext httpContext,
        RegistrationCeremonyRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await using var context = await _contextFactory.CreateAsync(httpContext, cancellationToken);
        throw new NotImplementedException();
    }

    private async Task<PublicKeyCredentialDescriptor[]?> GetCredentialsToExcludeAsync(
        TContext context,
        PublicKeyCredentialRpEntity rp,
        PublicKeyCredentialUserEntity user,
        ExcludeCredentialsOptions options,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (options.ExcludeAllExistingKeys)
        {
            var existingKeys = await _storage.GetExistingCredentialsAsync(context, rp, user, cancellationToken);
            if (existingKeys?.Length > 0)
            {
                return existingKeys;
            }

            return null;
        }

        if (options.ExcludeSpecificKeys)
        {
            var existingKeys = await _storage.GetExistingCredentialsAsync(context, rp, user, cancellationToken);
            if ((existingKeys?.Length > 0) is not true)
            {
                return null;
            }

            var resultKeysToExclude = new List<PublicKeyCredentialDescriptor>(options.SpecificKeysToExclude.Length);
            foreach (var existingKey in existingKeys)
            {
                var requestedKeyToExclude = options
                    .SpecificKeysToExclude
                    .FirstOrDefault(x => x.Type == existingKey.Type && x.Id.AsSpan().SequenceEqual(existingKey.Id));
                if (requestedKeyToExclude is not null)
                {
                    resultKeysToExclude.Add(requestedKeyToExclude);
                }
            }

            if (resultKeysToExclude.Count > 0)
            {
                return resultKeysToExclude.ToArray();
            }
        }

        return null;
    }

    private static CredentialCreationOptions ConvertToOptions(
        BeginCeremonyRequest request,
        byte[] challenge,
        PublicKeyCredentialDescriptor[]? excludeCredentials)
    {
        return new(new(
            request.Rp,
            request.User,
            challenge,
            request.PubKeyCredParams,
            request.Timeout,
            excludeCredentials,
            request.AuthenticatorSelection,
            request.Attestation,
            null));
    }
}
