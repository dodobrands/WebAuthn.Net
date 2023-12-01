using System;
using System.ComponentModel;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

namespace WebAuthn.Net.Services.Common.AttestationObjectDecoder.Models;

/// <summary>
///     Decoded <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-object">attestationObject</a>.
/// </summary>
public class AttestationObject
{
    /// <summary>
    ///     Constructs <see cref="AttestationObject" />.
    /// </summary>
    /// <param name="fmt">
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement-format">Attestation statement format (fmt)</a>.
    /// </param>
    /// <param name="attStmt"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">Attestation statement (attStmt)</a>.</param>
    /// <param name="authData"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">Authenticator data (authData)</a>. May be <see langword="null" />.</param>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="fmt" /> contains a value that is not defined in <see cref="AttestationStatementFormat" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="attStmt" /> is <see langword="null" /></exception>
    public AttestationObject(
        AttestationStatementFormat fmt,
        CborMap attStmt,
        byte[]? authData)
    {
        // fmt
        if (!Enum.IsDefined(typeof(AttestationStatementFormat), fmt))
        {
            throw new InvalidEnumArgumentException(nameof(fmt), (int) fmt, typeof(AttestationStatementFormat));
        }

        Fmt = fmt;

        // attStmt
        ArgumentNullException.ThrowIfNull(attStmt);
        AttStmt = attStmt;

        // authData
        AuthData = authData;
    }

    /// <summary>
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement-format">Attestation statement format (fmt)</a>.
    /// </summary>
    public AttestationStatementFormat Fmt { get; }

    /// <summary>
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">Attestation statement (attStmt)</a>.
    /// </summary>
    public CborMap AttStmt { get; }

    /// <summary>
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">Authenticator data (authData)</a>. May be <see langword="null" />.
    /// </summary>
    public byte[]? AuthData { get; }
}
