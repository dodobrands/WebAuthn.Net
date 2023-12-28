using System.Text.Json.Serialization;

namespace WebAuthn.Net.Demo.Mvc.ViewModels.Error;

[method: JsonConstructor]
public class ErrorViewModel(string errorMessage, int statusCode, string requestId)
{
    public string ErrorMessage { get; } = errorMessage;
    public int StatusCode { get; } = statusCode;

    public string RequestId { get; } = requestId;
}
