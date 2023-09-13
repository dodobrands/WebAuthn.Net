using System.Collections.Generic;
using System.Collections.Immutable;
using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Models;

/// <summary>
/// PublicKeyCredentialCreationOptions. <see cref="https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions"/>
/// </summary>
public class PublicKeyCredentialCreationOptions
{
    [Required]
    [JsonPropertyName("rp")]
    public PublicKeyCredentialRpEntity Rp { get; }

    [Required]
    [JsonPropertyName("user")]
    public PublicKeyCredentialUserEntity User { get; }

    [Required]
    [JsonPropertyName("challenge")]
    public byte[] Challenge { get; }

    [Required]
    [JsonPropertyName("pubKeyCredParams")]
    public ReadOnlyCollection<PublicKeyCredentialParameters> PubKeyCredParams { get; }

    [JsonPropertyName("timeout")]
    public ulong Timeout { get; }

    [JsonPropertyName("excludeCredentials")]
    public ReadOnlyCollection<PublicKeyCredentialDescriptor> ExcludeCredentials { get; }

    [JsonPropertyName("authenticatorSelection")]
    public AuthenticatorSelectionCriteria AuthenticatorSelection { get; }

    [JsonPropertyName("attestation")]
    public string Attestation { get; } = "none";

    [JsonPropertyName("extensions")]
    public AuthenticationExtensionsClientInputs Extensions { get; }
}

public class PublicKeyCredentialRpEntity
{
    // TODO: implement
}
