using System;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Abstractions.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;

/// <summary>
///     Default implementation of <see cref="INoneAttestationStatementDecoder" />.
/// </summary>
public class DefaultNoneAttestationStatementDecoder : INoneAttestationStatementDecoder
{
    /// <summary>
    ///     Constructs <see cref="DefaultNoneAttestationStatementDecoder" />.
    /// </summary>
    /// <param name="logger">Logger.</param>
    public DefaultNoneAttestationStatementDecoder(ILogger<DefaultNoneAttestationStatementDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        Logger = logger;
    }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultNoneAttestationStatementDecoder> Logger { get; }

    /// <inheritdoc />
    public virtual Result<NoneAttestationStatement> Decode(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        var dict = attStmt.RawValue;
        if (dict.Count > 0)
        {
            Logger.NoneNonEmptyMap();
            return Result<NoneAttestationStatement>.Fail();
        }

        return Result<NoneAttestationStatement>.Success(new());
    }
}

/// <summary>
///     Extension methods for logging the None attestation statement decoder.
/// </summary>
public static partial class DefaultNoneAttestationStatementDecoderLoggingExtensions
{
    /// <summary>
    ///     The 'attStmt' for the 'none' type should consist of an empty CBOR map
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'attStmt' for the 'none' type should consist of an empty CBOR map")]
    public static partial void NoneNonEmptyMap(this ILogger logger);
}
