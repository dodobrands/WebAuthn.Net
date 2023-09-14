using NUnit.Framework;

namespace WebAuthn.Net;

public class AlwaysPass
{
    [Test]
    public void Pass()
    {
        Assert.Pass();
    }
}
