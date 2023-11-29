using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.ClientDataDecoder.Models;

namespace WebAuthn.Net.Services.Common.ClientDataDecoder;

/// <summary>
///     Decoder for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-client-data">clientData</a> from JSON into a typed representation.
/// </summary>
public interface IClientDataDecoder
{
    /// <summary>
    ///     Decodes clientData from JSON into a typed representation for further work.
    /// </summary>
    /// <param name="jsonText">A string containing clientData serialized into JSON.</param>
    /// <returns>If the decoding was successful, the result contains the <see cref="CollectedClientData" />; otherwise, the result indicates that an error occurred during the decoding process.</returns>
    Result<CollectedClientData> Decode(string jsonText);
}
