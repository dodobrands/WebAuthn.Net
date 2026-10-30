using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationObjectDecoder.Implementation;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Implementation;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Implementation;
using WebAuthn.Net.Services.Serialization.Cose.Implementation;
using WebAuthn.Net.Services.Serialization.Json.Implementation;
using static WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidKey.AndroidKeyAttestationBuilder;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidKey;

// Tests of DefaultAndroidKeyAttestationStatementVerifier.VerifyAsync: every attestation is built from scratch by AndroidKeyAttestationBuilder,
// valid in every respect except the one rule a test breaks, so a test fails only if the check it names is missing.
public class DefaultAndroidKeyAttestationStatementVerifierTests
{
    // WebAuthn L3 §16.14 "Android Key Attestation with ES256 Credential" (registration): the attestation object and the client data JSON, base64url-encoded.
    // Its KeyDescription has the purpose and the origin in hardwareEnforced, but says Software for both security levels.
    private const string WebAuthnTestVectorAttestationObject = "o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKNjYWxnJmNzaWdYSDBGAiEA6VUSmCqj8hbP8uh8jsVwV7hSn2dOqr7Mqif9A9h3nxkCIQCvtr9FnaSoJvANAfxrYHEv8x3E6zMWGcj4dLsX5DFOlGN4NWOBWQJ8MIICeDCCAh6gAwIBAgIQH_kfdrY_RIEvmYslCwKGvzAKBggqhkjOPQQDAjBiMR4wHAYDVQQDDBVXZWJBdXRobiB0ZXN0IHZlY3RvcnMxDDAKBgNVBAoMA1czQzElMCMGA1UECwwcQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbiBDQTELMAkGA1UEBhMCQUEwIBcNMjQwMTAxMDAwMDAwWhgPMzAyNDAxMDEwMDAwMDBaMF8xHjAcBgNVBAMMFVdlYkF1dGhuIHRlc3QgdmVjdG9yczEMMAoGA1UECgwDVzNDMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJBQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJkWllcDbQiaKpghp9AGPTQfGkYTOJNZY276tfPL8azP3ZHFVUMXbqmbZEQG3R3WN3S2r2WsdZ4G_0CxyKsC32ujgbYwgbMwDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFBrIHlBkHo0TOauffrJfDNWqwFSwMB8GA1UdIwQYMBaAFEWv9xWw3XhnQf7pluvBZUejkxseMFMGCisGAQQB1nkCAREERTBDAgIBLAoBAAIBAAoBAAQgtDUCjXtqj4O7Rh1BwZsFOp082zA1Gk83TNTN6NvvtgYEADAAMA6hBTEDAgECv4U-AwIBADAKBggqhkjOPQQDAgNIADBFAiATVPkUmZb24YMIUtpim4bTfBDaD_4XRxxn1Idl7YP2OwIhAIbbV0aUTOzfzgcdngQQcs6sPRxQQ4LyBWdumh8C12MlaGF1dGhEYXRhWKS_q8N0MpWLBjNg061kYcnEc1rn-O3UZZKl4PAUUrLktV0AAAAArelwXhznCFuJmlQNAhmb-AAgCkcpUZeItu2KLXcrSU4YYkTYx5jAUpYNvIwQyRUXZ5WlAQIDJiABIVggmRaWVwNtCJoqmCGn0AY9NB8aRhM4k1ljbvq188vxrM8iWCDdkcVVQxduqZtkRAbdHdY3dLavZax1ngb_QLHIqwLfaw";

    private const string WebAuthnTestVectorClientDataJson = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiUGVId3R6WmR6TjRfOE12eVhpYl9wN3JfaC04UWJJRDhobDNFQXRtV0FGQSIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5vcmciLCJjcm9zc09yaWdpbiI6ZmFsc2UsImV4dHJhRGF0YSI6ImNsaWVudERhdGFKU09OIG1heSBiZSBleHRlbmRlZCB3aXRoIGFkZGl0aW9uYWwgZmllbGRzIGluIHRoZSBmdXR1cmUsIHN1Y2ggYXMgdGhpczogVlYxY1F1UjJxTE1fYW1QZm9IekwwZyJ9";

    private static readonly Guid WebAuthnTestVectorAaguid = Guid.Parse("ade9705e-1ce7-085b-899a-540d02199bf8");

    // ---------------------------------------------------------------------------------------------
    // Positive

    [Test]
    public async Task VerifyAsync_Succeeds_WithBasicAttestation_AndTheRootsOfTheFidoMetadataEntry()
    {
        var verifier = new TestAndroidKeyAttestationStatementVerifier();
        var attestation = new AndroidKeyAttestationBuilder().Build();

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok!.Fmt, Is.EqualTo(AttestationStatementFormat.AndroidKey));
            Assert.That(result.Ok.AttestationType, Is.EqualTo(AttestationType.Basic));
            Assert.That(result.Ok.AttestationTrustPath, Is.EqualTo(attestation.AttStmt.X5C));
            Assert.That(result.Ok.AttestationRootCertificates, Is.EquivalentTo(new[] { MetadataRoot }));
            Assert.That(verifier.FakeFidoMetadataSearchService.AaguidLookups, Is.EqualTo(new[] { Aaguid }));
            Assert.That(verifier.FakeLogger.Entries, Is.Empty);
        });
    }

    [TestCase(SecurityLevelStrongBox, SecurityLevelStrongBox)]
    [TestCase(SecurityLevelTrustedEnvironment, SecurityLevelStrongBox)]
    public async Task VerifyAsync_Succeeds_WhenKeyIsInStrongBox(int attestationSecurityLevel, int keyMintSecurityLevel)
    {
        var verifier = new TestAndroidKeyAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new AndroidKeyAttestationBuilder { AttestationSecurityLevel = attestationSecurityLevel, KeyMintSecurityLevel = keyMintSecurityLevel }.Build());

        Assert.That(result.HasError, Is.False);
    }

    [Test]
    public async Task VerifyAsync_Succeeds_ForSoftwareKey_WhenKeysOnlyFromTrustedExecutionEnvironmentAreNotRequired()
    {
        // the union of the authorization lists: a key of the software keystore has its fields in softwareEnforced
        var verifier = new TestAndroidKeyAttestationStatementVerifier(false);
        var attestation = new AndroidKeyAttestationBuilder
        {
            AttestationSecurityLevel = SecurityLevelSoftware,
            KeyMintSecurityLevel = SecurityLevelSoftware,
            TeeEnforcedPurpose = null,
            TeeEnforcedOrigin = null,
            SoftwareEnforcedPurpose = new[] { KeyPurposeSign },
            SoftwareEnforcedOrigin = KeyOriginGenerated
        }.Build();

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(verifier.FakeLogger.Entries, Is.Empty);
        });
    }

    // ---------------------------------------------------------------------------------------------
    // The trust anchors come from the FIDO Metadata Service entry for the aaguid: the attestation statement doesn't attest the aaguid, which the client chooses

    [Test]
    public async Task VerifyAsync_Fails_WhenAaguidHasNoFidoMetadataEntry()
    {
        // e.g. the zero aaguid, a random one, or one of a model that is not certified: before, the embedded Google roots made it acceptable, so any aaguid could be claimed
        var claimedAaguid = Guid.Parse("4f1b2a8c-5d3e-4a6b-9c7d-0e1f2a3b4c5d");
        var verifier = new TestAndroidKeyAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new AndroidKeyAttestationBuilder { AuthenticatorDataAaguid = claimedAaguid }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(verifier.FakeFidoMetadataSearchService.AaguidLookups, Is.EqualTo(new[] { claimedAaguid }));
            AssertWarning(verifier, $"The FIDO Metadata Service has no usable metadata for the aaguid {claimedAaguid} of the Android Key attestation statement, which doesn't attest the aaguid itself, so no trust anchor is acceptable");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenNoFidoMetadataIsAvailable()
    {
        var verifier = new TestAndroidKeyAttestationStatementVerifier(new RecordingFidoMetadataSearchService().WithAaguid(Aaguid, FidoMetadataSearchError.MetadataNotAvailable));

        var result = await verifier.VerifyAsync(new AndroidKeyAttestationBuilder().Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, $"No metadata from the FIDO Metadata Service is available to check the aaguid {Aaguid} of the Android Key attestation statement, so no trust anchor is acceptable");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenFidoMetadataEntryIsUntrusted()
    {
        var verifier = new TestAndroidKeyAttestationStatementVerifier(new RecordingFidoMetadataSearchService().WithAaguid(Aaguid, FidoMetadataSearchError.Untrusted));

        var result = await verifier.VerifyAsync(new AndroidKeyAttestationBuilder().Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, $"The FIDO Metadata Service entry for the aaguid {Aaguid} of the Android Key attestation statement doesn't allow to trust the authenticator, so no trust anchor is acceptable");
        });
    }

    [TestCase(AuthenticatorAttestationType.ATTESTATION_ATTCA)]
    [TestCase(AuthenticatorAttestationType.ATTESTATION_BASIC_SURROGATE)]
    public async Task VerifyAsync_Fails_WhenFidoMetadataEntryDoesNotListBasicFull(AuthenticatorAttestationType attestationType)
    {
        var verifier = new TestAndroidKeyAttestationStatementVerifier(new RecordingFidoMetadataSearchService().WithAaguid(Aaguid, RecordingFidoMetadataSearchService.Metadata(MetadataRoot, attestationType)));

        var result = await verifier.VerifyAsync(new AndroidKeyAttestationBuilder().Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, $"The metadata of the aaguid {Aaguid} doesn't list the attestation type that an Android Key attestation statement conveys (basic_full), so no trust anchor is acceptable");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Syntax, signature and credential public key

    [Test]
    public async Task VerifyAsync_Fails_WhenX5CIsEmpty()
    {
        var verifier = new TestAndroidKeyAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new AndroidKeyAttestationBuilder { EmptyX5C = true }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "The 'x5c' of the Android Key attestation statement is empty");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenSignatureIsInvalid()
    {
        var verifier = new TestAndroidKeyAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new AndroidKeyAttestationBuilder { CorruptSignature = true }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "The 'sig' of the Android Key attestation statement is not a valid signature");
            Assert.That(verifier.FakeFidoMetadataSearchService.AaguidLookups, Is.Empty);
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenCredentialPublicKeyIsNotTheKeyOfCredCert()
    {
        var verifier = new TestAndroidKeyAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new AndroidKeyAttestationBuilder { MismatchedCoseKey = true }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "The public key of credCert of the Android Key attestation statement does not match the credential public key");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // The android key attestation certificate extension data (KeyDescription) and its attestationChallenge

    [Test]
    public async Task VerifyAsync_Fails_WhenAttestationChallengeIsNotTheClientDataHash()
    {
        var verifier = new TestAndroidKeyAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new AndroidKeyAttestationBuilder { WrongAttestationChallenge = true }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "The attestationChallenge of the KeyDescription of the Android Key attestation statement is not identical to the client data hash");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenKeyDescriptionIsMissing()
    {
        var verifier = new TestAndroidKeyAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new AndroidKeyAttestationBuilder { OmitKeyDescription = true }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "credCert of the Android Key attestation statement doesn't have exactly one valid android key attestation certificate extension");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenKeyDescriptionOccursTwice()
    {
        // RFC 5280 §4.2: a certificate must not include more than one instance of an extension; the platform loader may also refuse such a certificate
        var verifier = new TestAndroidKeyAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new AndroidKeyAttestationBuilder { DuplicateKeyDescription = true }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(
                verifier.FakeLogger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.Some.Contains("doesn't have exactly one valid android key attestation certificate extension")
                    .Or.Some.Contains("Failed to load a certificate from the 'x5c' of the Android Key attestation statement"));
        });
    }

    [TestCase("3000")] // an empty SEQUENCE
    [TestCase("0500")] // NULL instead of a SEQUENCE
    [TestCase("30030201")] // a truncated SEQUENCE
    public async Task VerifyAsync_Fails_WithoutException_WhenKeyDescriptionIsMalformed(string keyDescriptionHex)
    {
        var verifier = new TestAndroidKeyAttestationStatementVerifier();
        var attestation = new AndroidKeyAttestationBuilder { KeyDescriptionValue = Convert.FromHexString(keyDescriptionHex) }.Build();

        Result<VerifiedAttestationStatement>? result = null;
        await Assert.DoesNotThrowAsync(async () => result = await verifier.VerifyAsync(attestation));
        Assert.That(result!.HasError, Is.True);
    }

    // ---------------------------------------------------------------------------------------------
    // The authorization lists: allApplications, purpose, origin (and, when only keys from a trusted execution environment are accepted, the security levels)

    [TestCase(true, false)]
    [TestCase(false, true)]
    public async Task VerifyAsync_Fails_WhenAllApplicationsIsPresent(bool teeEnforced, bool softwareEnforced)
    {
        var verifier = new TestAndroidKeyAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new AndroidKeyAttestationBuilder { TeeEnforcedAllApplications = teeEnforced, SoftwareEnforcedAllApplications = softwareEnforced }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "has the allApplications field, but the credential must be scoped to the RP ID");
        });
    }

    [TestCase(new[] { KeyPurposeVerify }, "3")]
    [TestCase(new[] { KeyPurposeSign, KeyPurposeVerify }, "2, 3")] // AuthorizationList.purpose is a SET OF INTEGER: it is equal to KM_PURPOSE_SIGN only if signing is the only purpose
    [TestCase(new[] { 1, KeyPurposeSign }, "1, 2")]
    [TestCase(new[] { KeyPurposeSign, 7 }, "2, 7")] // ATTEST_KEY
    [TestCase(new int[0], "")]
    public async Task VerifyAsync_Fails_WhenPurposeIsNotSignAlone(int[] purpose, string loggedPurpose)
    {
        var verifier = new TestAndroidKeyAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new AndroidKeyAttestationBuilder { TeeEnforcedPurpose = purpose }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, $"The purpose ({loggedPurpose}) in the teeEnforced authorization list of the KeyDescription of the Android Key attestation statement is not KM_PURPOSE_SIGN (2) alone");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenOriginIsNotGenerated()
    {
        var verifier = new TestAndroidKeyAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new AndroidKeyAttestationBuilder { TeeEnforcedOrigin = KeyOriginImported }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "The origin (2) in the teeEnforced authorization list of the KeyDescription of the Android Key attestation statement is not KM_ORIGIN_GENERATED (0)");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_ForSoftwareKey_WhenOnlyKeysFromTrustedExecutionEnvironmentAreAccepted()
    {
        // the fields are in softwareEnforced only, and only teeEnforced counts
        var verifier = new TestAndroidKeyAttestationStatementVerifier();
        var attestation = new AndroidKeyAttestationBuilder
        {
            TeeEnforcedPurpose = null,
            TeeEnforcedOrigin = null,
            SoftwareEnforcedPurpose = new[] { KeyPurposeSign },
            SoftwareEnforcedOrigin = KeyOriginGenerated
        }.Build();

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "The 'purpose' field is missing from the teeEnforced authorization list of the KeyDescription of the Android Key attestation statement");
        });
    }

    [TestCase(SecurityLevelSoftware, SecurityLevelTrustedEnvironment)]
    [TestCase(SecurityLevelTrustedEnvironment, SecurityLevelSoftware)]
    [TestCase(SecurityLevelSoftware, SecurityLevelSoftware)]
    [TestCase(3, SecurityLevelTrustedEnvironment)] // not a SecurityLevel
    public async Task VerifyAsync_Fails_WhenSecurityLevelIsNotSecure_AndOnlyKeysFromTrustedExecutionEnvironmentAreAccepted(int attestationSecurityLevel, int keyMintSecurityLevel)
    {
        // the fields are in teeEnforced, but the KeyDescription says that the key or the attestation is not from a secure environment
        var verifier = new TestAndroidKeyAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new AndroidKeyAttestationBuilder { AttestationSecurityLevel = attestationSecurityLevel, KeyMintSecurityLevel = keyMintSecurityLevel }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "The attestationSecurityLevel or the keyMintSecurityLevel of the KeyDescription of the Android Key attestation statement is not TrustedEnvironment or StrongBox");
        });
    }

    [TestCase(true)]
    [TestCase(false)]
    public async Task VerifyAsync_Fails_WhenPurposeIsInBothAuthorizationLists(bool acceptKeysOnlyFromTrustedExecutionEnvironment)
    {
        var verifier = new TestAndroidKeyAttestationStatementVerifier(acceptKeysOnlyFromTrustedExecutionEnvironment);

        var result = await verifier.VerifyAsync(new AndroidKeyAttestationBuilder { SoftwareEnforcedPurpose = new[] { KeyPurposeSign } }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "The 'purpose' field is in both authorization lists (softwareEnforced and teeEnforced)");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenOriginIsInBothAuthorizationLists()
    {
        var verifier = new TestAndroidKeyAttestationStatementVerifier(false);

        var result = await verifier.VerifyAsync(new AndroidKeyAttestationBuilder { SoftwareEnforcedOrigin = KeyOriginGenerated }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "The 'origin' field is in both authorization lists (softwareEnforced and teeEnforced)");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Malformed or repeated fields of the authorization lists are rejected without an exception,
    // and never taken for absent ones (which the union of the lists would then look up in the other list)

    [TestCase("A1083106020103020102", "purpose")] // [1] { SET { INTEGER 3, INTEGER 2 } } - a SET OF that is not in DER order
    [TestCase("A106310402020002", "purpose")] // [1] { SET { INTEGER 00 02 } } - an INTEGER that is not minimally encoded
    [TestCase("8103020102", "purpose")] // [1] primitive - EXPLICIT tagging requires a constructed [1]
    [TestCase("A103020102", "purpose")] // [1] { INTEGER 2 } - no SET OF
    [TestCase("A10731030201020500", "purpose")] // [1] { SET { INTEGER 2 }, NULL } - an element after the SET OF
    [TestCase("A10431020500", "purpose")] // [1] { SET { NULL } } - not an INTEGER
    [TestCase("BF853E0402020000", "origin")] // [702] { INTEGER 00 00 } - an INTEGER that is not minimally encoded
    [TestCase("9F853E03020100", "origin")] // [702] primitive
    [TestCase("BF853E03040100", "origin")] // [702] { OCTET STRING } - not an INTEGER
    [TestCase("BF853E050201000500", "origin")] // [702] { INTEGER 0, NULL } - an element after the INTEGER
    public async Task VerifyAsync_Fails_WithoutException_WhenAuthorizationListFieldIsMalformed(string fieldHex, string field)
    {
        // the malformed field replaces the well-formed one in teeEnforced, and softwareEnforced has a well-formed one, so that the union would succeed if the malformed field were taken for an absent one
        var verifier = new TestAndroidKeyAttestationStatementVerifier(false);
        var attestation = new AndroidKeyAttestationBuilder
        {
            TeeEnforcedPurpose = field == "purpose" ? null : new[] { KeyPurposeSign },
            TeeEnforcedOrigin = field == "origin" ? null : KeyOriginGenerated,
            TeeEnforcedExtraFields = new[] { Convert.FromHexString(fieldHex) },
            SoftwareEnforcedPurpose = field == "purpose" ? new[] { KeyPurposeSign } : null,
            SoftwareEnforcedOrigin = field == "origin" ? KeyOriginGenerated : null
        }.Build();

        Result<VerifiedAttestationStatement>? result = null;
        await Assert.DoesNotThrowAsync(async () => result = await verifier.VerifyAsync(attestation));
        Assert.Multiple(() =>
        {
            Assert.That(result!.HasError, Is.True);
            AssertWarning(verifier, $"The '{field}' field of an authorization list of the KeyDescription of the Android Key attestation statement is malformed or occurs more than once");
        });
    }

    [TestCase("A1053103020102", "purpose")] // [1] { SET { INTEGER 2 } }
    [TestCase("BF853E03020100", "origin")] // [702] { INTEGER 0 }
    public async Task VerifyAsync_Fails_WhenAuthorizationListFieldOccursTwice(string fieldHex, string field)
    {
        // a SEQUENCE has each field at most once; even an identical repetition is rejected
        var verifier = new TestAndroidKeyAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new AndroidKeyAttestationBuilder { TeeEnforcedExtraFields = new[] { Convert.FromHexString(fieldHex) } }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, $"The '{field}' field of an authorization list of the KeyDescription of the Android Key attestation statement is malformed or occurs more than once");
        });
    }

    [Test]
    public async Task VerifyAsync_Succeeds_WhenAuthorizationListHasFieldsUnknownToTheLibrary()
    {
        // the authorization lists get new fields with new versions of KeyMint (e.g. attestationApplicationId [709], moduleHash [724]); the fields that are not needed are not read
        var verifier = new TestAndroidKeyAttestationStatementVerifier();
        var attestation = new AndroidKeyAttestationBuilder
        {
            TeeEnforcedExtraFields = new[] { Convert.FromHexString("BF85540402020100") }, // [724] { INTEGER 256 }
            SoftwareEnforcedExtraFields = new[] { Convert.FromHexString("BF8545030401FF") } // [709] { OCTET STRING FF }
        }.Build();

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(verifier.FakeLogger.Entries, Is.Empty);
        });
    }

    // ---------------------------------------------------------------------------------------------
    // The test vector of WebAuthn L3 §16.14

    [Test]
    public async Task VerifyAsync_Succeeds_ForWebAuthnTestVector_WhenKeysOnlyFromTrustedExecutionEnvironmentAreNotRequired()
    {
        var verifier = new TestAndroidKeyAttestationStatementVerifier(
            new RecordingFidoMetadataSearchService().WithAaguid(WebAuthnTestVectorAaguid, RecordingFidoMetadataSearchService.Metadata(MetadataRoot, AuthenticatorAttestationType.ATTESTATION_BASIC_FULL)),
            false);

        var result = await verifier.VerifyAsync(DecodeAttestation(WebAuthnTestVectorAttestationObject, WebAuthnTestVectorClientDataJson));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok!.AttestationType, Is.EqualTo(AttestationType.Basic));
            Assert.That(verifier.FakeLogger.Entries, Is.Empty);
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_ForWebAuthnTestVector_WhenOnlyKeysFromTrustedExecutionEnvironmentAreAccepted()
    {
        // the test vector says Software for attestationSecurityLevel and keyMintSecurityLevel
        var verifier = new TestAndroidKeyAttestationStatementVerifier(
            new RecordingFidoMetadataSearchService().WithAaguid(WebAuthnTestVectorAaguid, RecordingFidoMetadataSearchService.Metadata(MetadataRoot, AuthenticatorAttestationType.ATTESTATION_BASIC_FULL)),
            true);

        var result = await verifier.VerifyAsync(DecodeAttestation(WebAuthnTestVectorAttestationObject, WebAuthnTestVectorClientDataJson));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "The attestationSecurityLevel or the keyMintSecurityLevel of the KeyDescription of the Android Key attestation statement is not TrustedEnvironment or StrongBox");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers

    private static AndroidKeyAttestation DecodeAttestation(string attestationObjectBase64Url, string clientDataJsonBase64Url)
    {
        var cborDeserializer = new DefaultCborDeserializer(NullLogger<DefaultCborDeserializer>.Instance);
        var attestationObjectDecoder = new DefaultAttestationObjectDecoder(
            cborDeserializer,
            new DefaultEnumMemberAttributeSerializer<AttestationStatementFormat>(),
            NullLogger<DefaultAttestationObjectDecoder>.Instance);
        var authenticatorDataDecoder = new DefaultAuthenticatorDataDecoder(
            new DefaultCoseKeyDeserializer(cborDeserializer, NullLogger<DefaultCoseKeyDeserializer>.Instance),
            cborDeserializer,
            NullLogger<DefaultAuthenticatorDataDecoder>.Instance);
        var attestationStatementDecoder = new DefaultAndroidKeyAttestationStatementDecoder(new FakeRegistrationCeremonyCounters(), NullLogger<DefaultAndroidKeyAttestationStatementDecoder>.Instance);

        var attestationObject = attestationObjectDecoder.Decode(WebEncoders.Base64UrlDecode(attestationObjectBase64Url));
        Assert.That(attestationObject.HasError, Is.False, "the attestation object must decode");
        Assert.That(attestationObject.Ok!.Fmt, Is.EqualTo(AttestationStatementFormat.AndroidKey));
        var authenticatorData = authenticatorDataDecoder.Decode(attestationObject.Ok.AuthData!);
        Assert.That(authenticatorData.HasError, Is.False, "the authenticator data must decode");
        var attStmt = attestationStatementDecoder.Decode(attestationObject.Ok.AttStmt);
        Assert.That(attStmt.HasError, Is.False, "the attestation statement must decode");
        var clientDataHash = SHA256.HashData(WebEncoders.Base64UrlDecode(clientDataJsonBase64Url));
        return new(attStmt.Ok!, (AttestedAuthenticatorData) authenticatorData.Ok!, clientDataHash);
    }

    private static void AssertWarning(TestAndroidKeyAttestationStatementVerifier verifier, string messagePart)
    {
        Assert.That(
            verifier.FakeLogger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
            Has.Some.Contains(messagePart),
            $"expected a Warning containing '{messagePart}'");
    }
}
