using System.Text.Json.Serialization;

#pragma warning disable CA1716
namespace WebAuthn.Net.Demo.Mvc.ViewModels.Error;
#pragma warning restore CA1716

[method: JsonConstructor]
public class ErrorViewModel(string errorMessage, int statusCode, string requestId)
{
    public string ErrorMessage { get; } = errorMessage;
    public int StatusCode { get; } = statusCode;

    public string RequestId { get; } = requestId;
}
