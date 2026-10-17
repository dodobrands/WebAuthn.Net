using System;
using System.Globalization;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;
using WebAuthn.Net.Services.Serialization.Json.Implementation;

namespace WebAuthn.Net.DSL.Fakes;

public static class FakeMetadataBlobPayloadJsonFactory
{
    public const string Aaguid = "531126d6-e717-415c-9320-3d9aa6981239";
    public const string SecondAaguid = "a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa";

    private const string PayloadTemplate =
        """
        {
          "legalHeader": "Retrieval and use of this BLOB indicates acceptance of the appropriate agreement located at https://fidoalliance.org/metadata/metadata-legal-terms/",
          "no": 1,
          "nextUpdate": "2026-11-01",
          "entries": [
            {
              "aaguid": "531126d6-e717-415c-9320-3d9aa6981239",
              "metadataStatement": {
                "aaguid": "531126d6-e717-415c-9320-3d9aa6981239",
                "description": "Test Authenticator",
                "authenticatorVersion": 1,
                "protocolFamily": "fido2",
                "schema": 3,
                "upv": [
                  {
                    "major": 1,
                    "minor": 3
                  }
                ],
                "authenticationAlgorithms": [
                  "secp256r1_ecdsa_sha256_raw"
                ],
                "publicKeyAlgAndEncodings": [
                  "cose"
                ],
                "attestationTypes": [
                  "basic_full"
                ],
                "userVerificationDetails": [
                  [
                    {
                      "userVerificationMethod": "presence_internal"
                    }
                  ]
                ],
                "keyProtection": [
                  "hardware",
                  "secure_element"
                ],
                "matcherProtection": [
                  "on_chip"
                ],
                "tcDisplay": [],
                "attestationRootCertificates": [],
                "authenticatorGetInfo": {
                  "versions": [
                    "FIDO_2_0",
                    "FIDO_2_1",
                    "FIDO_2_3"
                  ],
                  "aaguid": "531126d6e717415c93203d9aa6981239",
                  "algorithms": [
                    {
                      "type": "public-key",
                      "alg": -7
                    }
                  ]
                }
              },
              "statusReports": [
                {
                  "status": "FIDO_CERTIFIED_L1",
                  "effectiveDate": "2026-09-30"
                }
              ],
              "timeOfLastStatusChange": "2026-09-30"
            }
          ]
        }
        """;

    public static MetadataBLOBPayloadJSON Create(Action<JsonObject>? configure = null)
    {
        var payload = JsonNode.Parse(PayloadTemplate)?.AsObject() ?? throw new InvalidOperationException("Failed to parse the metadata payload template");
        configure?.Invoke(payload);
        var serializer = new DefaultSafeJsonSerializer(NullLogger<DefaultSafeJsonSerializer>.Instance);
        var result = serializer.DeserializeNonNullable<MetadataBLOBPayloadJSON>(payload.ToJsonString());
        if (result.HasError)
        {
            throw new InvalidOperationException("Failed to deserialize the metadata payload");
        }

        return result.Ok;
    }

    public static JsonObject GetEntry(JsonObject payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return payload["entries"]?[0]?.AsObject() ?? throw new InvalidOperationException("The metadata payload has no entries");
    }

    public static JsonArray GetEntries(JsonObject payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return payload["entries"]?.AsArray() ?? throw new InvalidOperationException("The metadata payload has no entries");
    }

    /// <summary>
    ///     Appends a copy of the first entry with a different AAGUID to the payload and returns the appended entry.
    /// </summary>
    public static JsonObject AddEntry(JsonObject payload, string aaguid)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(aaguid);
        var entries = GetEntries(payload);
        var entry = GetEntry(payload).DeepClone().AsObject();
        entry["aaguid"] = aaguid;
        var metadataStatement = entry["metadataStatement"]?.AsObject() ?? throw new InvalidOperationException("The metadata payload entry has no metadata statement");
        metadataStatement["aaguid"] = aaguid;
        metadataStatement["description"] = $"Test Authenticator {aaguid}";
        var authenticatorGetInfo = metadataStatement["authenticatorGetInfo"]?.AsObject();
        if (authenticatorGetInfo is not null)
        {
            authenticatorGetInfo["aaguid"] = Guid.Parse(aaguid).ToString("N", CultureInfo.InvariantCulture);
        }

        entries.Add(entry);
        return entry;
    }

    public static JsonObject GetMetadataStatement(JsonObject payload)
    {
        return GetEntry(payload)["metadataStatement"]?.AsObject() ?? throw new InvalidOperationException("The metadata payload entry has no metadata statement");
    }

    public static JsonObject GetAuthenticatorGetInfo(JsonObject payload)
    {
        return GetMetadataStatement(payload)["authenticatorGetInfo"]?.AsObject() ?? throw new InvalidOperationException("The metadata statement has no authenticatorGetInfo");
    }
}
