namespace WebAuthn.Net.Sample.Mvc.Services;

public class UserHandleStore
{
    private readonly Dictionary<string, string> _displayNames = new();

    public string Get(string userHandle)
    {
        return _displayNames[userHandle];
    }

    public string GetUserHandle(string name)
    {
        return _displayNames.FirstOrDefault(x => x.Value.Equals(name, StringComparison.Ordinal)).Key;
    }

    public void Set(string userHandle, string name)
    {
        _displayNames.TryAdd(userHandle, name);
    }
}
