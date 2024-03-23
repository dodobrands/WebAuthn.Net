using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using WebAuthn.Net.Demo.Mvc.Constants;
using WebAuthn.Net.Demo.Mvc.Services.Abstractions.CookieStore;
using WebAuthn.Net.Demo.Mvc.Services.Abstractions.User;
using WebAuthn.Net.Demo.Mvc.Services.Abstractions.User.Models;

namespace WebAuthn.Net.Demo.Mvc.Services.Implementation;

public class DefaultUserService(IDataProtectionProvider provider)
    : AbstractProtectedCookieStore(provider, DataProtectionPurpose, CookieConstants.UserHandle), IUserService
{
    private const string DataProtectionPurpose = "WebAuthn.Net.Demo.RegistrationCeremonyHandle";
    private const int ItemsToPreserve = 5;

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
        var userHandle = SHA256.HashData(Encoding.UTF8.GetBytes(userName));
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
        resultAccumulator.AddRange(existingItems);

        if (resultAccumulator.All(x => x.UserName != newItem.UserName))
        {
            resultAccumulator.Add(newItem);
        }

        var itemsToPreserve = resultAccumulator
            .OrderByDescending(x => x.CreatedAt)
            .Take(ItemsToPreserve)
            .ToArray();
        return itemsToPreserve;
    }

    [method: JsonConstructor]
    private sealed class JsonApplicationUser(string userHandle, string userName, long createdAt)
    {
        [JsonPropertyName("userHandle")]
        public string UserHandle { get; } = userHandle;

        [JsonPropertyName("userName")]
        public string UserName { get; } = userName;

        [JsonPropertyName("createdAt")]
        public long CreatedAt { get; } = createdAt;

        public TypedInternalApplicationUser ToTyped()
        {
            var userHandle = WebEncoders.Base64UrlDecode(UserHandle);
            var createdAt = DateTimeOffset.FromUnixTimeSeconds(CreatedAt);
            return new(userHandle, UserName, createdAt);
        }
    }

    private sealed class TypedInternalApplicationUser(byte[] userHandle, string userName, DateTimeOffset createdAt)
    {
        public byte[] UserHandle { get; } = userHandle;
        public string UserName { get; } = userName;
        public DateTimeOffset CreatedAt { get; } = createdAt;

        public JsonApplicationUser ToJson()
        {
            var userHandle = WebEncoders.Base64UrlEncode(UserHandle);
            var createdAt = CreatedAt.ToUnixTimeSeconds();
            return new(userHandle, UserName, createdAt);
        }
    }
}
