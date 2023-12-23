using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using WebAuthn.Net.Demo.Mvc.Constants;
using WebAuthn.Net.Demo.Mvc.Services.Abstractions.CookieStore;
using WebAuthn.Net.Demo.Mvc.Services.Abstractions.User;
using WebAuthn.Net.Demo.Mvc.Services.Abstractions.User.Models;

namespace WebAuthn.Net.Demo.Mvc.Services.Implementation;

public class DefaultUserService : AbstractProtectedCookieStore, IUserService
{
    private const string DataProtectionPurpose = "WebAuthn.Net.Demo.RegistrationCeremonyHandle";
    private const int ItemsToPreserve = 5;

    public DefaultUserService(IDataProtectionProvider provider)
        : base(provider, DataProtectionPurpose, CookieConstants.UserHandle)
    {
    }

    public Task<byte[]> CreateAsync(
        HttpContext httpContext,
        string userName,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var existingItems = Read(httpContext);
        var newItem = Create(userName);
        var itemsToPreserve = BuildNewItemsToPreserve(newItem, existingItems);
        Write(httpContext, itemsToPreserve);
        return Task.FromResult(newItem.UserHandle);
    }

    public Task<ApplicationUser?> FindAsync(
        HttpContext httpContext,
        byte[] userHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var existingItems = Read(httpContext);
        var foundItem = existingItems
            .FirstOrDefault(x => x.UserHandle.AsSpan().SequenceEqual(userHandle));
        if (foundItem is not null)
        {
            var applicationUser = new ApplicationUser(foundItem.UserHandle, foundItem.UserName);
            return Task.FromResult<ApplicationUser?>(applicationUser);
        }

        return Task.FromResult<ApplicationUser?>(null);
    }

    public Task<ApplicationUser?> FindAsync(
        HttpContext httpContext,
        string userName,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var existingItems = Read(httpContext);
        var foundItem = existingItems
            .FirstOrDefault(x => x.UserName == userName);
        if (foundItem is not null)
        {
            var applicationUser = new ApplicationUser(foundItem.UserHandle, foundItem.UserName);
            return Task.FromResult<ApplicationUser?>(applicationUser);
        }

        return Task.FromResult<ApplicationUser?>(null);
    }

    public Task DeleteAsync(
        HttpContext httpContext,
        byte[] userHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var existingItems = Read(httpContext);
        var itemsToPreserve = BuildNewItemsToPreserve(userHandle, existingItems);
        Write(httpContext, itemsToPreserve);
        return Task.CompletedTask;
    }

    private TypedInternalApplicationUser[] Read(HttpContext httpContext)
    {
        if (!TryRead(httpContext, out var payload))
        {
            return Array.Empty<TypedInternalApplicationUser>();
        }

        var jsonUsers = JsonSerializer.Deserialize<JsonApplicationUser[]>(payload);
        if (jsonUsers is null)
        {
            return Array.Empty<TypedInternalApplicationUser>();
        }

        var result = jsonUsers
            .Select(x => x.ToTyped())
            .OrderByDescending(x => x.CreatedAt)
            .ToArray();

        return result;
    }

    private void Write(HttpContext httpContext, TypedInternalApplicationUser[] itemsToWrite)
    {
        var jsonModels = itemsToWrite.Select(x => x.ToJson());
        var dataToWrite = JsonSerializer.SerializeToUtf8Bytes(jsonModels);
        Save(httpContext, dataToWrite);
    }

    private static TypedInternalApplicationUser Create(string userName)
    {
        var userHandle = Guid.NewGuid().ToByteArray();
        var createdAt = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        return new(userHandle, userName, createdAt);
    }

    private static TypedInternalApplicationUser[] BuildNewItemsToPreserve(
        byte[] userHandleToRemove,
        TypedInternalApplicationUser[] existingItems)
    {
        var resultAccumulator = new List<TypedInternalApplicationUser>();
        foreach (var existingItem in existingItems)
        {
            if (!existingItem.UserHandle.AsSpan().SequenceEqual(userHandleToRemove))
            {
                resultAccumulator.Add(existingItem);
            }
        }

        var itemsToPreserve = resultAccumulator
            .OrderByDescending(x => x.CreatedAt)
            .Take(ItemsToPreserve)
            .ToArray();
        return itemsToPreserve;
    }

    private static TypedInternalApplicationUser[] BuildNewItemsToPreserve(
        TypedInternalApplicationUser newItem,
        TypedInternalApplicationUser[] existingItems)
    {
        var resultAccumulator = new List<TypedInternalApplicationUser>();
        resultAccumulator.Add(newItem);
        foreach (var existingItem in existingItems)
        {
            if (existingItem.UserName != newItem.UserName)
            {
                resultAccumulator.Add(existingItem);
            }
        }

        var itemsToPreserve = resultAccumulator
            .OrderByDescending(x => x.CreatedAt)
            .Take(ItemsToPreserve)
            .ToArray();
        return itemsToPreserve;
    }

    private class JsonApplicationUser
    {
        [JsonConstructor]
        public JsonApplicationUser(string userHandle, string userName, long createdAt)
        {
            UserHandle = userHandle;
            UserName = userName;
            CreatedAt = createdAt;
        }

        [JsonPropertyName("userHandle")]
        public string UserHandle { get; }

        [JsonPropertyName("userName")]
        public string UserName { get; }

        [JsonPropertyName("createdAt")]
        public long CreatedAt { get; }

        public TypedInternalApplicationUser ToTyped()
        {
            var userHandle = WebEncoders.Base64UrlDecode(UserHandle);
            var createdAt = DateTimeOffset.FromUnixTimeSeconds(CreatedAt);
            return new(userHandle, UserName, createdAt);
        }
    }

    private class TypedInternalApplicationUser
    {
        public TypedInternalApplicationUser(byte[] userHandle, string userName, DateTimeOffset createdAt)
        {
            UserHandle = userHandle;
            UserName = userName;
            CreatedAt = createdAt;
        }

        public byte[] UserHandle { get; }
        public string UserName { get; }
        public DateTimeOffset CreatedAt { get; }

        public JsonApplicationUser ToJson()
        {
            var userHandle = WebEncoders.Base64UrlEncode(UserHandle);
            var createdAt = CreatedAt.ToUnixTimeSeconds();
            return new(userHandle, UserName, createdAt);
        }
    }
}
