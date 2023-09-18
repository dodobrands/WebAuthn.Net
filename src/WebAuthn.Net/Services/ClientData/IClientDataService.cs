using WebAuthn.Net.Models;
using WebAuthn.Net.Services.ClientData.Models;

namespace WebAuthn.Net.Services.ClientData;

public interface IClientDataService
{
    Result<CollectedClientData> GetClientData(byte[] clientData);
}
