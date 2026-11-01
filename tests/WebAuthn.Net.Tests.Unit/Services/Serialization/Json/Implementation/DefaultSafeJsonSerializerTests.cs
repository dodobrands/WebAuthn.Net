using System.Linq;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.Common.ClientDataDecoder.Implementation.Models;

namespace WebAuthn.Net.Services.Serialization.Json.Implementation;

// The client data is JSON chosen by the client, and the message of a JsonException repeats parts of it verbatim:
// the JSON path contains the member names, and an invalid literal is quoted together with the rest of the input.
public class DefaultSafeJsonSerializerTests
{
    private const string Forged = "\r\n[Information] forged\u001b[0m";

    // the JSON escapes of Forged in a JSON string
    private const string EscapedForged = "\\r\\n[Information] forged\\u001b[0m";

    private const string SanitizedForged = "??[Information] forged?[0m";

    private const string WarningPrefix = "An error occurred during the deserialization of the 'WebAuthn.Net.Services.Common.ClientDataDecoder.Implementation.Models.CollectedClientDataJson' value: "
                                         + "System.Text.Json.JsonException: ";

    private const int MaxLoggedExceptionMessageLength = 512;

    private FakeLogger<DefaultSafeJsonSerializer> Logger { get; set; } = null!;

    private DefaultSafeJsonSerializer Serializer { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        Logger = new();
        Serializer = new(Logger);
    }

    [Test]
    public void DeserializeNonNullable_FromString_LogsSanitizedMessageWithoutException_WhenMemberNameContainsControlCharacters()
    {
        var json = "{\"type\":\"webauthn.get\",\"" + EscapedForged + "\":[1,]}";

        var result = Serializer.DeserializeNonNullable<CollectedClientDataJson>(json);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Logger.Entries, Has.Count.EqualTo(1));
            Assert.That(Logger.Entries[0].Level, Is.EqualTo(LogLevel.Warning));
            Assert.That(Logger.Entries[0].Exception, Is.Null);
            Assert.That(Logger.Entries[0].Message, Does.StartWith(WarningPrefix));
            Assert.That(Logger.Entries[0].Message, Does.Contain(SanitizedForged));
            Assert.That(Logger.Entries[0].Message, Has.None.Matches<char>(char.IsControl));
        });
    }

    [Test]
    public void DeserializeNonNullable_FromUtf8Bytes_LogsSanitizedMessageWithoutException_WhenInvalidLiteralContainsControlCharacters()
    {
        var json = Encoding.UTF8.GetBytes("{\"type\":nul" + Forged + "}");

        var result = Serializer.DeserializeNonNullable<CollectedClientDataJson>(json);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Logger.Entries, Has.Count.EqualTo(1));
            Assert.That(Logger.Entries[0].Level, Is.EqualTo(LogLevel.Warning));
            Assert.That(Logger.Entries[0].Exception, Is.Null);
            Assert.That(Logger.Entries[0].Message, Does.StartWith(WarningPrefix));
            Assert.That(Logger.Entries[0].Message, Does.Contain(SanitizedForged));
            Assert.That(Logger.Entries[0].Message, Has.None.Matches<char>(char.IsControl));
        });
    }

    // a member name of 200,000 characters makes a JsonException message of about 200 KB
    [Test]
    public void DeserializeNonNullable_FromString_TruncatesLoggedMessage_WhenMemberNameIsLong()
    {
        var json = "{\"" + new string('a', 200_000) + "\":[1,]}";

        var result = Serializer.DeserializeNonNullable<CollectedClientDataJson>(json);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Logger.Entries.Select(static x => x.Message), Has.One.StartWith(WarningPrefix));
            Assert.That(Logger.Entries[0].Message, Has.Length.EqualTo(WarningPrefix.Length + MaxLoggedExceptionMessageLength + "...".Length));
            Assert.That(Logger.Entries[0].Message, Does.EndWith("aaa..."));
        });
    }

    // an invalid literal is quoted together with the rest of the input, however long it is
    [Test]
    public void DeserializeNonNullable_FromUtf8Bytes_TruncatesLoggedMessage_WhenInvalidLiteralIsLong()
    {
        var json = Encoding.UTF8.GetBytes("{\"type\":n" + new string('a', 200_000) + "}");

        var result = Serializer.DeserializeNonNullable<CollectedClientDataJson>(json);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Logger.Entries.Select(static x => x.Message), Has.One.StartWith(WarningPrefix));
            Assert.That(Logger.Entries[0].Message, Has.Length.EqualTo(WarningPrefix.Length + MaxLoggedExceptionMessageLength + "...".Length));
        });
    }

    [Test]
    public void DeserializeNonNullable_FromString_LogsWholeMessage_WhenItIsShort()
    {
        const string json = "{\"type\":1}";
        var exceptionMessage = Assert.Throws<JsonException>(static () => JsonSerializer.Deserialize<CollectedClientDataJson>(json))?.Message;

        var result = Serializer.DeserializeNonNullable<CollectedClientDataJson>(json);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(exceptionMessage, Has.Length.LessThan(MaxLoggedExceptionMessageLength));
            Assert.That(Logger.Entries.Select(static x => x.Message), Is.EqualTo(new[] { WarningPrefix + exceptionMessage }));
        });
    }
}
