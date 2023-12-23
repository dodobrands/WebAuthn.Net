namespace WebAuthn.Net.Demo.Mvc.Services.Abstractions.User.Models;

public class ApplicationUser
{
    public ApplicationUser(byte[] userHandle, string userName)
    {
        UserHandle = userHandle;
        UserName = userName;
    }

    public byte[] UserHandle { get; }

    public string UserName { get; }
}
