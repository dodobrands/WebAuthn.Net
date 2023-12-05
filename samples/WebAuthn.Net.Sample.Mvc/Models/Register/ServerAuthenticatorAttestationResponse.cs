﻿using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Sample.Mvc.Models.Register;

public class ServerAuthenticatorAttestationResponse
{
    [JsonConstructor]
    public ServerAuthenticatorAttestationResponse(string clientDataJson, string attestationObject)
    {
        ClientDataJson = clientDataJson;
        AttestationObject = attestationObject;
    }

    [JsonPropertyName("clientDataJSON")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string ClientDataJson { get; }

    [JsonPropertyName("attestationObject")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string AttestationObject { get; }
}