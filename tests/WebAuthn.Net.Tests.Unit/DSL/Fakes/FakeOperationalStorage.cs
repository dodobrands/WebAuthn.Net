using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions.Protocol;
using WebAuthn.Net.Storage.Operations;
using WebAuthn.Net.Storage.Operations.Models;

namespace WebAuthn.Net.DSL.Fakes;

public class FakeOperationalStorage : IOperationalStorage<FakeWebAuthnContext>
{
    private readonly object _locker = new();
    private readonly Dictionary<string, RegistrationCeremonyOptions> _registrationOptions = new();
    private readonly Dictionary<string, UserCredential> _usersCredentials = new();

    public Task<RegistrationPublicKeyCredentialDescriptor[]?> GetExistingCredentialsAsync(
        FakeWebAuthnContext context,
        string rpId,
        byte[] userHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var resultAccumulator = new List<RegistrationPublicKeyCredentialDescriptor>();
        var descriptorToSearch = new UserCredentialDescriptor(rpId, userHandle);
        lock (_locker)
        {
            foreach (var userCredential in _usersCredentials.Values)
            {
                if (!userCredential.UserCredentialDescriptor.Equals(descriptorToSearch))
                {
                    continue;
                }

                var publicKeyCredentialDescriptor = new RegistrationPublicKeyCredentialDescriptor(
                    userCredential.CredentialRecord.Type,
                    userCredential.CredentialRecord.Id,
                    userCredential.CredentialRecord.Transports);
                resultAccumulator.Add(publicKeyCredentialDescriptor);
            }
        }

        if (resultAccumulator.Count > 0)
        {
            var result = resultAccumulator.ToArray();
            return Task.FromResult<RegistrationPublicKeyCredentialDescriptor[]?>(result);
        }

        return Task.FromResult<RegistrationPublicKeyCredentialDescriptor[]?>(null);
    }

    public Task<string> SaveRegistrationCeremonyOptionsAsync(
        FakeWebAuthnContext context,
        RegistrationCeremonyOptions registrationCeremonyOptions,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var registrationCeremonyOptionsId = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);
        lock (_locker)
        {
            _registrationOptions.Add(registrationCeremonyOptionsId, registrationCeremonyOptions);
        }

        return Task.FromResult(registrationCeremonyOptionsId);
    }

    public Task<RegistrationCeremonyOptions?> FindRegistrationCeremonyOptionsAsync(
        FakeWebAuthnContext context,
        string registrationCeremonyOptionsId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RegistrationCeremonyOptions? result = null;
        lock (_locker)
        {
            if (_registrationOptions.TryGetValue(registrationCeremonyOptionsId, out var options))
            {
                result = options;
            }
        }

        return Task.FromResult(result);
    }

    public void ReplaceChallengeForRegistrationCeremonyOptions(string registrationCeremonyOptionsId, byte[] newChallenge)
    {
        lock (_locker)
        {
            if (!_registrationOptions.TryGetValue(registrationCeremonyOptionsId, out var existingOptions))
            {
                throw new InvalidOperationException("Can't find registration ceremony!");
            }

            var existingCredentialOptions = existingOptions.Options;
            var newPubKeyOptions = new PublicKeyCredentialCreationOptions(
                existingCredentialOptions.Rp,
                existingCredentialOptions.User,
                newChallenge,
                existingCredentialOptions.PubKeyCredParams,
                existingCredentialOptions.Timeout,
                existingCredentialOptions.ExcludeCredentials,
                existingCredentialOptions.AuthenticatorSelection,
                existingCredentialOptions.Hints,
                existingCredentialOptions.Attestation,
                existingCredentialOptions.AttestationFormats,
                existingCredentialOptions.Extensions);
            var newOptions = new RegistrationCeremonyOptions(
                newPubKeyOptions,
                existingOptions.ExpectedOrigin,
                existingOptions.ExpectedTopOrigins,
                existingOptions.CreatedAt,
                existingOptions.ExpiresAt);
            _registrationOptions[registrationCeremonyOptionsId] = newOptions;
        }
    }


    private class UserCredential
    {
        public UserCredential(UserCredentialDescriptor userCredentialDescriptor, CredentialRecord credentialRecord)
        {
            UserCredentialDescriptor = userCredentialDescriptor;
            CredentialRecord = credentialRecord;
        }

        public UserCredentialDescriptor UserCredentialDescriptor { get; }

        public CredentialRecord CredentialRecord { get; }
    }

    private class UserCredentialDescriptor : IEquatable<UserCredentialDescriptor>
    {
        public UserCredentialDescriptor(string rpId, byte[] userHandle)
        {
            RpId = rpId;
            UserHandle = userHandle;
        }

        public string RpId { get; }
        public byte[] UserHandle { get; }

        public bool Equals(UserCredentialDescriptor? other)
        {
            if (ReferenceEquals(null, other))
            {
                return false;
            }

            if (ReferenceEquals(this, other))
            {
                return true;
            }

            return RpId == other.RpId && UserHandle.AsSpan().SequenceEqual(other.UserHandle.AsSpan());
        }

        public override bool Equals(object? obj)
        {
            if (ReferenceEquals(null, obj))
            {
                return false;
            }

            if (ReferenceEquals(this, obj))
            {
                return true;
            }

            if (obj.GetType() != typeof(UserCredentialDescriptor))
            {
                return false;
            }

            return Equals((UserCredentialDescriptor) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return (string.GetHashCode(RpId, StringComparison.Ordinal) * 397) ^ UserHandle.GetHashCode();
            }
        }

        public static bool operator ==(UserCredentialDescriptor? left, UserCredentialDescriptor? right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(UserCredentialDescriptor? left, UserCredentialDescriptor? right)
        {
            return !Equals(left, right);
        }
    }
}
