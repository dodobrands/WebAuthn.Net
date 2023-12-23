using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using WebAuthn.Net.Demo.FidoConformance.Constants;

namespace WebAuthn.Net.Demo.FidoConformance.Models.Common.Response;

public class ServerResponse
{
    public ServerResponse(string status, string errorMessage)
    {
        if (status == ServerResponseStatus.Ok)
        {
            if (!string.IsNullOrWhiteSpace(errorMessage))
            {
                throw new ArgumentException(
                    $"If the status is \"{ServerResponseStatus.Ok}\", then \"errorMessage\" should not be specified",
                    nameof(errorMessage));
            }

            Status = ServerResponseStatus.Ok;
            ErrorMessage = string.Empty;
        }
        else if (status == ServerResponseStatus.Failed)
        {
            if (string.IsNullOrWhiteSpace(errorMessage))
            {
                throw new ArgumentException(
                    $"If the status is \"{ServerResponseStatus.Failed}\", then \"errorMessage\" must not be an empty string",
                    nameof(errorMessage));
            }

            Status = ServerResponseStatus.Failed;
            ErrorMessage = errorMessage;
        }
        else
        {
            throw new ArgumentException(
                $"The status must be either \"{ServerResponseStatus.Ok}\" or \"{ServerResponseStatus.Failed}\"",
                nameof(status));
        }
    }

    [JsonPropertyName("status")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string Status { get; }

    [JsonPropertyName("errorMessage")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string ErrorMessage { get; }


    public static ServerResponse Error(string errorMessage)
    {
        if (string.IsNullOrWhiteSpace(errorMessage))
        {
            throw new ArgumentException(
                $"If the status is \"{ServerResponseStatus.Failed}\", then \"errorMessage\" must not be an empty string",
                nameof(errorMessage));
        }

        return new(ServerResponseStatus.Failed, errorMessage);
    }

    public static ServerResponse Success()
    {
        return new(ServerResponseStatus.Ok, string.Empty);
    }
}
