using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.ClientDataDecoder.Models;

namespace WebAuthn.Net.Services.Common.ClientDataDecoder;

/// <summary>
///     Service for decoding <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-client-data">clientData</a> from JSON into a typed representation for further work.
/// </summary>
public interface IClientDataDecoder
{
    /// <summary>
    ///     Decodes clientData from JSON into a typed representation for further work.
    /// </summary>
    /// <param name="jsonText">A string containing clientData serialized into JSON.</param>
    /// <returns>If decoding was successful, a result containing <see cref="CollectedClientData" />, otherwise, a result indicating that an error occurred during decoding.</returns>
    Result<CollectedClientData> Decode(string jsonText);
}
