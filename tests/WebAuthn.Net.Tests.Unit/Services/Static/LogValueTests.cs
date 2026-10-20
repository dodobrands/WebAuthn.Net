using NUnit.Framework;

namespace WebAuthn.Net.Services.Static;

public class LogValueTests
{
    [Test]
    public void LogValue_KeepsPrintableValue()
    {
        Assert.That(LogValue.Sanitize("https://example.com"), Is.EqualTo("https://example.com"));
    }

    [Test]
    public void LogValue_ReplacesCharactersThatCanForgeLogRecords()
    {
        var sanitized = LogValue.Sanitize("https://evil.example\r\n[INF] forged\u2028\u202E\u001b[31m\u0000");

        Assert.That(sanitized, Is.EqualTo("https://evil.example??[INF] forged???[31m?"));
    }

    [Test]
    public void LogValue_TruncatesLongValue()
    {
        var sanitized = LogValue.Sanitize(new string('a', LogValue.DefaultMaxLength + 10));

        Assert.That(sanitized, Is.EqualTo(new string('a', LogValue.DefaultMaxLength) + "..."));
    }

    [Test]
    public void LogValue_ReturnsEmptyString_WhenValueIsNull()
    {
        Assert.That(LogValue.Sanitize(null), Is.Empty);
    }
}
