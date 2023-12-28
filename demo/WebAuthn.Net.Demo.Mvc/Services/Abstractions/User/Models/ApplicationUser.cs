namespace WebAuthn.Net.Demo.Mvc.Services.Abstractions.User.Models;

public class ApplicationUser(
    byte[] userHandle,
    string userName)
{
    public byte[] UserHandle { get; } = userHandle;

    public string UserName { get; } = userName;
}
