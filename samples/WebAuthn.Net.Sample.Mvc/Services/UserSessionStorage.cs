namespace WebAuthn.Net.Sample.Mvc.Services;

public class UserSessionStorage
{
    private readonly Dictionary<string, string> _registrations = new();
    private readonly Dictionary<string, string> _assertions = new();

    public string GetUsernameByRegId(string registrationId) => _registrations[registrationId];
    public void SaveRegistration(string name, string registrationId) => _registrations[registrationId] = name;
    public void ClearRegistration(string id) => _registrations.Remove(id);

    public string GetUsernameByAssertionId(string assertionId) => _assertions[assertionId];
    public void SaveAssertion(string name, string assertionId) => _assertions[assertionId] = name;
    public void ClearAssertion(string id) => _assertions.Remove(id);
}
