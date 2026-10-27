using System;
using System.Reflection;
using NUnit.Framework;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataIngest;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

// The assembly and the name of the resource are specified together or not at all (the option is null),
// so an incomplete configuration of the embedded blob fails where the options are configured instead of being silently ignored at start-up.
public class FidoMetadataEmbeddedBlobOptionsTests
{
    private const string ResourceName = "WebAuthn.Net.DSL.Fakes.FakeResources.blob.jwt";
    private static readonly Assembly TestAssembly = typeof(FidoMetadataEmbeddedBlobOptionsTests).Assembly;

    [Test]
    public void Constructor_KeepsAssemblyAndResourceName()
    {
        var embeddedBlob = new FidoMetadataEmbeddedBlobOptions(TestAssembly, ResourceName);

        Assert.Multiple(() =>
        {
            Assert.That(embeddedBlob.Assembly, Is.SameAs(TestAssembly));
            Assert.That(embeddedBlob.ResourceName, Is.EqualTo(ResourceName));
        });
    }

    [Test]
    public void Constructor_WhenAssemblyIsNull_ThrowsArgumentNullException()
    {
        var exception = Assert.Throws<ArgumentNullException>(static () => _ = new FidoMetadataEmbeddedBlobOptions(null!, ResourceName));

        Assert.That(exception!.ParamName, Is.EqualTo("assembly"));
    }

    [Test]
    public void Constructor_WhenResourceNameIsNull_ThrowsArgumentNullException()
    {
        var exception = Assert.Throws<ArgumentNullException>(static () => _ = new FidoMetadataEmbeddedBlobOptions(TestAssembly, null!));

        Assert.That(exception!.ParamName, Is.EqualTo("resourceName"));
    }

    [TestCase("")]
    [TestCase(" ")]
    [TestCase("\t\r\n")]
    public void Constructor_WhenResourceNameIsEmptyOrWhiteSpace_ThrowsArgumentException(string resourceName)
    {
        var exception = Assert.Throws<ArgumentException>(() => _ = new FidoMetadataEmbeddedBlobOptions(TestAssembly, resourceName));

        Assert.That(exception!.ParamName, Is.EqualTo("resourceName"));
    }
}
