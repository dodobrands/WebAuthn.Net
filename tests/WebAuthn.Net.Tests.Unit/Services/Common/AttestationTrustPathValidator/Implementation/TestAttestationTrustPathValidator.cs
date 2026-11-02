using System.Collections.Generic;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusSerialNumberFormatter;
using WebAuthn.Net.Services.Common.AttestationTrustPathValidator.Implementation.Constants;

namespace WebAuthn.Net.Services.Common.AttestationTrustPathValidator.Implementation;

internal sealed class TestAttestationTrustPathValidator : DefaultAttestationTrustPathValidator
{
    public TestAttestationTrustPathValidator(IOptionsMonitor<WebAuthnOptions> options)
        : this(options, new(), new(), new())
    {
    }

    public TestAttestationTrustPathValidator(
        IOptionsMonitor<WebAuthnOptions> options,
        FakeAndroidKeyAttestationStatusStorage statusStorage,
        FakeAndroidKeyAttestationStatusCounters statusCounters,
        FakeLogger<DefaultAttestationTrustPathValidator> logger)
        : base(options, statusStorage, new DefaultAndroidKeyAttestationStatusSerialNumberFormatter(), statusCounters, logger)
    {
        FakeStatusStorage = statusStorage;
        FakeStatusCounters = statusCounters;
        FakeLogger = logger;
    }

    public FakeAndroidKeyAttestationStatusStorage FakeStatusStorage { get; }

    public FakeAndroidKeyAttestationStatusCounters FakeStatusCounters { get; }

    public FakeLogger<DefaultAttestationTrustPathValidator> FakeLogger { get; }

    // the embedded root certificates of the key attestation of Google, to which a test adds the root certificate of its own hierarchy:
    // nobody outside Google can issue a certificate under the real ones
    public List<byte[]> GoogleRoots { get; } = new(GoogleAttestationRoots.Certificates);

    protected override UniqueByteArraysCollection GetGoogleAttestationRootCertificates()
    {
        return new(GoogleRoots);
    }
}
