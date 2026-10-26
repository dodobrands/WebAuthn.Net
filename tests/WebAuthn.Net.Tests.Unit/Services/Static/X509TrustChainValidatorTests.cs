using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using WebAuthn.Net.Configuration.Options;

namespace WebAuthn.Net.Services.Static;

public class X509TrustChainValidatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Test]
    public void IsFidoMetadataBlobJwtChainValid_ReturnsTrue_WhenChainEndsInRoot()
    {
        using var root = CreateRoot("CN=WebAuthn.Net Test Metadata Root");
        using var leaf = CreateLeaf(root);

        var valid = X509TrustChainValidator.IsFidoMetadataBlobJwtChainValid(new[] { root }, new[] { leaf }, ConfigureChain);
        var validWithStatus = X509TrustChainValidator.IsFidoMetadataBlobJwtChainValid(new[] { root }, new[] { leaf }, ConfigureChain, out var chainStatus);

        Assert.Multiple(() =>
        {
            Assert.That(valid, Is.True);
            Assert.That(validWithStatus, Is.True);
            Assert.That(chainStatus, Is.Empty);
        });
    }

    [Test]
    public void IsFidoMetadataBlobJwtChainValid_ReturnsFalse_WithChainStatus_WhenChainEndsInAnotherRoot()
    {
        using var root = CreateRoot("CN=WebAuthn.Net Test Metadata Root");
        using var leaf = CreateLeaf(root);
        using var otherRoot = CreateRoot("CN=WebAuthn.Net Other Root");

        var valid = X509TrustChainValidator.IsFidoMetadataBlobJwtChainValid(new[] { otherRoot }, new[] { leaf }, ConfigureChain, out var chainStatus);

        Assert.Multiple(() =>
        {
            Assert.That(valid, Is.False);
            Assert.That(chainStatus, Is.Not.Empty);
        });
    }

    [Test]
    public void IsFidoMetadataBlobJwtChainValid_WithCustomDelegateThatDoesNotSetTrustMode_UsesProvidedRootsAsTrustAnchors()
    {
        // CustomRootTrust is applied before the delegate: in System mode a non-empty CustomTrustStore is not allowed by X509Chain,
        // so a delegate that doesn't mention the trust mode used to throw an exception out of the provider instead of rejecting the blob.
        using var root = CreateRoot("CN=WebAuthn.Net Test Metadata Root");
        using var leaf = CreateLeaf(root);

        var valid = false;
        Assert.DoesNotThrow(() => valid = X509TrustChainValidator.IsFidoMetadataBlobJwtChainValid(
            new[] { root },
            new[] { leaf },
            static chain =>
            {
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationTime = Now.UtcDateTime;
            }));

        Assert.That(valid, Is.True);
    }

    [Test]
    public void IsFidoMetadataBlobJwtChainValid_WithDefaultEmbeddedBlobPolicy_AcceptsChainOutsideItsValidityPeriod()
    {
        // The blob embedded in the application is validated regardless of the validity period of its certificates (they are short-lived),
        // but the chain still has to end in one of the provided roots.
        using var root = CreateRoot("CN=WebAuthn.Net Test Metadata Root");
        using var leaf = CreateLeaf(root);
        using var otherRoot = CreateRoot("CN=WebAuthn.Net Other Root");
        var afterExpiration = Now.AddYears(5).UtcDateTime;

        void ConfigureEmbeddedBlobChain(X509Chain chain)
        {
            new X509ChainValidationOptions().OnValidateEmbeddedFidoMetadataBlobJwtChain(chain);
            chain.ChainPolicy.VerificationTime = afterExpiration;
        }

        var valid = X509TrustChainValidator.IsFidoMetadataBlobJwtChainValid(new[] { root }, new[] { leaf }, ConfigureEmbeddedBlobChain);
        var validWithOtherRoot = X509TrustChainValidator.IsFidoMetadataBlobJwtChainValid(new[] { otherRoot }, new[] { leaf }, ConfigureEmbeddedBlobChain);

        Assert.Multiple(() =>
        {
            Assert.That(valid, Is.True);
            Assert.That(validWithOtherRoot, Is.False);
        });
    }

    [Test]
    public void IsFidoMetadataBlobJwtChainValid_ReturnsFalse_WhenThereAreNoRoots()
    {
        using var root = CreateRoot("CN=WebAuthn.Net Test Metadata Root");
        using var leaf = CreateLeaf(root);

        var valid = X509TrustChainValidator.IsFidoMetadataBlobJwtChainValid(Array.Empty<X509Certificate2>(), new[] { leaf }, ConfigureChain, out var chainStatus);

        Assert.Multiple(() =>
        {
            Assert.That(valid, Is.False);
            Assert.That(chainStatus, Is.Empty);
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Attestation trust path: the chain is built from client-supplied certificates, so the chain engine must never fetch the issuer certificates
    // named by their Authority Information Access extension (blind SSRF from the server, and a synchronous stall of UrlRetrievalTimeout per unreachable URL).
    // The issuer that is "not provided to the chain" gets a unique name per test: macOS caches the result of an Authority Information Access lookup per issuer across processes for a while,
    // and a cached lookup would hide a download in the test that follows.

    [Test]
    public void IsAttestationTrustPathChainValid_WithDefaultOptions_DoesNotDownloadIssuerFromAuthorityInformationAccess()
    {
        using var aiaServer = new CountingHttpServer();
        using var realIssuer = CreateRoot(UniqueIssuerName(), DateTimeOffset.UtcNow);
        using var otherRoot = CreateRoot("CN=WebAuthn.Net Other Root", DateTimeOffset.UtcNow);
        using var leaf = CreateLeaf(realIssuer, DateTimeOffset.UtcNow, new X509AuthorityInformationAccessExtension(null, new[] { aiaServer.Url + "issuer.cer" }));

        var valid = X509TrustChainValidator.IsAttestationTrustPathChainValid(
            new[] { otherRoot.RawData },
            new[] { leaf.RawData },
            new X509ChainValidationOptions().OnValidateAttestationTrustPathChain);

        Assert.Multiple(() =>
        {
            Assert.That(valid, Is.False);
            Assert.That(aiaServer.Requests, Is.EqualTo(0), "the chain engine must not fetch the AIA URL of a client-supplied certificate");
        });
    }

    [Test]
    public void IsAttestationTrustPathChainValid_WithCustomDelegateThatOnlySetsTrustMode_DoesNotDownloadIssuerFromAuthorityInformationAccess()
    {
        // the safe defaults are applied before the delegate, so a delegate that mentions neither DisableCertificateDownloads nor RevocationMode keeps them
        // (the .NET default RevocationMode is Online, which would fetch CRLs / OCSP responses - and on macOS the issuer certificates as well)
        using var aiaServer = new CountingHttpServer();
        using var realIssuer = CreateRoot(UniqueIssuerName(), DateTimeOffset.UtcNow);
        using var otherRoot = CreateRoot("CN=WebAuthn.Net Other Root", DateTimeOffset.UtcNow);
        using var leaf = CreateLeaf(realIssuer, DateTimeOffset.UtcNow, new X509AuthorityInformationAccessExtension(null, new[] { aiaServer.Url + "issuer.cer" }));

        var valid = X509TrustChainValidator.IsAttestationTrustPathChainValid(
            new[] { otherRoot.RawData },
            new[] { leaf.RawData },
            static chain => chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust);

        Assert.Multiple(() =>
        {
            Assert.That(valid, Is.False);
            Assert.That(aiaServer.Requests, Is.EqualTo(0));
        });
    }

    [Test]
    public void IsAttestationTrustPathChainValid_WithDefaultOptions_ReturnsQuickly_WhenAuthorityInformationAccessServerNeverResponds()
    {
        using var hangingServer = new HangingTcpServer();
        using var realIssuer = CreateRoot(UniqueIssuerName(), DateTimeOffset.UtcNow);
        using var otherRoot = CreateRoot("CN=WebAuthn.Net Other Root", DateTimeOffset.UtcNow);
        using var leaf = CreateLeaf(realIssuer, DateTimeOffset.UtcNow, new X509AuthorityInformationAccessExtension(null, new[] { hangingServer.Url + "slow.cer" }));
        var options = new X509ChainValidationOptions();

        var stopwatch = Stopwatch.StartNew();
        var valid = X509TrustChainValidator.IsAttestationTrustPathChainValid(new[] { otherRoot.RawData }, new[] { leaf.RawData }, options.OnValidateAttestationTrustPathChain);
        stopwatch.Stop();

        Assert.Multiple(() =>
        {
            Assert.That(valid, Is.False);
            // with downloads enabled the build blocks for the whole UrlRetrievalTimeout (10 seconds) of the default delegate
            Assert.That(stopwatch.Elapsed, Is.LessThan(TimeSpan.FromSeconds(5)), "the chain build must not wait for the AIA server");
            Assert.That(hangingServer.Connections, Is.EqualTo(0));
        });
    }

    [Test]
    public void IsAttestationTrustPathChainValid_WithCustomDelegateThatDoesNotSetTrustMode_UsesProvidedRootsAsTrustAnchors()
    {
        // the safe default (CustomRootTrust) is applied before the delegate: in System mode a non-empty CustomTrustStore is not allowed by X509Chain
        using var root = CreateRoot("CN=WebAuthn.Net Test Attestation Root", DateTimeOffset.UtcNow);
        using var leaf = CreateLeaf(root, DateTimeOffset.UtcNow);

        var valid = false;
        Assert.DoesNotThrow(() => valid = X509TrustChainValidator.IsAttestationTrustPathChainValid(
            new[] { root.RawData },
            new[] { leaf.RawData },
            static chain => chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck));

        Assert.That(valid, Is.True);
    }

    [Test]
    public void IsAttestationTrustPathChainValid_WithDefaultOptions_ReturnsTrue_WhenChainEndsInProvidedRoot()
    {
        using var root = CreateRoot("CN=WebAuthn.Net Test Attestation Root", DateTimeOffset.UtcNow);
        using var leaf = CreateLeaf(root, DateTimeOffset.UtcNow);

        var valid = X509TrustChainValidator.IsAttestationTrustPathChainValid(new[] { root.RawData }, new[] { leaf.RawData }, new X509ChainValidationOptions().OnValidateAttestationTrustPathChain);

        Assert.That(valid, Is.True);
    }

    [Test]
    public void DefaultAttestationTrustPathChainPolicy_DisablesCertificateDownloadsAndRevocationChecking()
    {
        using var chain = new X509Chain();

        new X509ChainValidationOptions().OnValidateAttestationTrustPathChain(chain);

        Assert.Multiple(() =>
        {
            Assert.That(chain.ChainPolicy.DisableCertificateDownloads, Is.True);
            // on macOS the chain engine fetches the issuer certificates whenever revocation checking is enabled, regardless of DisableCertificateDownloads
            Assert.That(chain.ChainPolicy.RevocationMode, Is.EqualTo(X509RevocationMode.NoCheck));
            Assert.That(chain.ChainPolicy.TrustMode, Is.EqualTo(X509ChainTrustMode.CustomRootTrust));
        });
    }

    [Test]
    public void DefaultFidoMetadataBlobJwtChainPolicy_IsUnchanged_AndChecksRevocationOnline()
    {
        // the metadata blob comes from a trusted source (the FIDO Metadata Service) and its chain is expected to be checked online
        using var chain = new X509Chain();

        new X509ChainValidationOptions().OnValidateFidoMetadataBlobJwtChain(chain);

        Assert.Multiple(() =>
        {
            Assert.That(chain.ChainPolicy.RevocationMode, Is.EqualTo(X509RevocationMode.Online));
            Assert.That(chain.ChainPolicy.DisableCertificateDownloads, Is.False);
            Assert.That(chain.ChainPolicy.TrustMode, Is.EqualTo(X509ChainTrustMode.CustomRootTrust));
        });
    }

    [Test]
    public void DefaultEmbeddedFidoMetadataBlobJwtChainPolicy_DoesNotUseNetwork_AndIgnoresOnlyValidityPeriod()
    {
        // The blob embedded in the application has to work without the network and long after its short-lived signing certificate has expired,
        // so its chain is validated without the revocation check, and the validity period is the only validation error that is ignored.
        using var chain = new X509Chain();

        new X509ChainValidationOptions().OnValidateEmbeddedFidoMetadataBlobJwtChain(chain);

        Assert.Multiple(() =>
        {
            Assert.That(chain.ChainPolicy.RevocationMode, Is.EqualTo(X509RevocationMode.NoCheck));
            Assert.That(chain.ChainPolicy.DisableCertificateDownloads, Is.True);
            Assert.That(chain.ChainPolicy.TrustMode, Is.EqualTo(X509ChainTrustMode.CustomRootTrust));
            Assert.That(chain.ChainPolicy.VerificationFlags, Is.EqualTo(X509VerificationFlags.IgnoreNotTimeValid));
        });
    }

    [Test]
    public void DefaultChainPolicies_DoNotIgnoreAnyValidationErrors()
    {
        // the defaults are what an application gets out of the box: relaxations needed only by the tests or the FIDO Conformance demo are configured there, not here
        using var attestationTrustPathChain = new X509Chain();
        using var fidoMetadataBlobJwtChain = new X509Chain();
        var options = new X509ChainValidationOptions();

        options.OnValidateAttestationTrustPathChain(attestationTrustPathChain);
        options.OnValidateFidoMetadataBlobJwtChain(fidoMetadataBlobJwtChain);

        Assert.Multiple(() =>
        {
            Assert.That(attestationTrustPathChain.ChainPolicy.VerificationFlags, Is.EqualTo(X509VerificationFlags.NoFlag));
            Assert.That(fidoMetadataBlobJwtChain.ChainPolicy.VerificationFlags, Is.EqualTo(X509VerificationFlags.NoFlag));
        });
    }

    private static void ConfigureChain(X509Chain chain)
    {
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = Now.UtcDateTime;
    }

    // a self-signed CA certificate together with its private key
    private static X509Certificate2 CreateRoot(string subject)
    {
        return CreateRoot(subject, Now);
    }

    private static X509Certificate2 CreateRoot(string subject, DateTimeOffset validAround)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return request.CreateSelfSigned(validAround.AddYears(-1), validAround.AddYears(1));
    }

    private static X509Certificate2 CreateLeaf(X509Certificate2 root)
    {
        return CreateLeaf(root, Now);
    }

    private static X509Certificate2 CreateLeaf(X509Certificate2 root, DateTimeOffset validAround, params X509Extension[] extensions)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=WebAuthn.Net Test Metadata Signer", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        foreach (var extension in extensions)
        {
            request.CertificateExtensions.Add(extension);
        }

        return request.Create(root, validAround.AddDays(-1), validAround.AddDays(30), new byte[] { 1, 2, 3, 4 });
    }

    private static string UniqueIssuerName()
    {
        return $"CN=WebAuthn.Net Issuer Not Provided To The Chain {Guid.NewGuid():N}";
    }

    private static int GetFreeLoopbackPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint) listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    // an HTTP server on the loopback interface that counts the requests it receives (and answers 404)
    private sealed class CountingHttpServer : IDisposable
    {
        private readonly HttpListener _listener;
        private int _requests;

        public CountingHttpServer()
        {
            Url = $"http://127.0.0.1:{GetFreeLoopbackPort()}/";
            _listener = new();
            _listener.Prefixes.Add(Url);
            _listener.Start();
            _ = Task.Run(ServeAsync);
        }

        public string Url { get; }

        public int Requests => Volatile.Read(ref _requests);

        public void Dispose()
        {
            _listener.Stop();
            _listener.Close();
        }

        private async Task ServeAsync()
        {
            try
            {
                while (_listener.IsListening)
                {
                    var context = await _listener.GetContextAsync();
                    Interlocked.Increment(ref _requests);
                    context.Response.StatusCode = 404;
                    context.Response.Close();
                }
            }
            catch (HttpListenerException)
            {
                // the listener was stopped
            }
            catch (ObjectDisposedException)
            {
                // the listener was disposed
            }
        }
    }

    // a TCP server on the loopback interface that accepts connections and never answers them
    private sealed class HangingTcpServer : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly System.Collections.Generic.List<TcpClient> _clients = new();
        private int _connections;

        public HangingTcpServer()
        {
            _listener = new(IPAddress.Loopback, 0);
            _listener.Start();
            Url = $"http://127.0.0.1:{((IPEndPoint) _listener.LocalEndpoint).Port}/";
            _ = Task.Run(AcceptAsync);
        }

        public string Url { get; }

        public int Connections => Volatile.Read(ref _connections);

        public void Dispose()
        {
            _listener.Stop();
            _listener.Dispose();
            lock (_clients)
            {
                foreach (var client in _clients)
                {
                    client.Dispose();
                }

                _clients.Clear();
            }
        }

        private async Task AcceptAsync()
        {
            try
            {
                while (true)
                {
                    var client = await _listener.AcceptTcpClientAsync();
                    Interlocked.Increment(ref _connections);
                    lock (_clients)
                    {
                        _clients.Add(client);
                    }
                }
            }
            catch (SocketException)
            {
                // the listener was stopped
            }
            catch (ObjectDisposedException)
            {
                // the listener was disposed
            }
        }
    }
}
