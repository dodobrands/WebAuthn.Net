using System;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Implementation.AttestationStatements;

public class DefaultNoneAttestationStatementDecoder : INoneAttestationStatementDecoder
{
    private readonly ILogger<DefaultNoneAttestationStatementDecoder> _logger;

    public DefaultNoneAttestationStatementDecoder(ILogger<DefaultNoneAttestationStatementDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
    }

    public Result<NoneAttestationStatement> Decode(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        var dict = attStmt.RawValue;
        if (dict.Count > 0)
        {
            _logger.NoneNonEmptyMap();
            return Result<NoneAttestationStatement>.Fail();
        }

        return Result<NoneAttestationStatement>.Success(new());
    }
}

public static partial class DefaultNoneAttestationStatementDecoderLoggingExtensions
{
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'attStmt' for the 'none' type should consist of an empty CBOR map")]
    public static partial void NoneNonEmptyMap(this ILogger logger);
}
