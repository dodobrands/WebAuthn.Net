using System;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text.Json;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Storage.SqlServer.Storage.Models;

/// <summary>
///     Model for representing <see cref="PublicKeyCredentialDescriptor" /> stored in Microsoft SQL Server as part of <see cref="SqlServerUserCredentialRecord" />.
/// </summary>
[SuppressMessage("Design", "CA1812:Avoid uninstantiated internal classes")]
public class SqlServerPublicKeyCredentialDescriptor
{
    /// <summary>
    ///     Constructs <see cref="SqlServerPublicKeyCredentialDescriptor" />.
    /// </summary>
    /// <param name="type">The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source-type">type</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>.</param>
    /// <param name="credentialId">The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id">Credential ID</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>.</param>
    /// <param name="transports">
    ///     The value returned from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-gettransports">getTransports()</a> when the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a> was <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration">registered</a>. For storage in Microsoft SQL Server, the values are
    ///     transformed into json ('nvarchar(max)' data type).
    /// </param>
    /// <param name="createdAtUnixTime">Creation date of the credential record in unixtime seconds format.</param>
    public SqlServerPublicKeyCredentialDescriptor(int type, byte[] credentialId, string transports, long createdAtUnixTime)
    {
        Type = type;
        CredentialId = credentialId;
        Transports = transports;
        CreatedAtUnixTime = createdAtUnixTime;
    }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source-type">type</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>.
    /// </summary>
    public int Type { get; }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id">Credential ID</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>.
    /// </summary>
    [Required]
    [MaxLength(1024)]
    public byte[] CredentialId { get; }

    /// <summary>
    ///     The value returned from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-gettransports">getTransports()</a> when the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a> was <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration">registered</a>. For storage in Microsoft SQL Server, the values are
    ///     transformed into json ('nvarchar(max)' data type).
    /// </summary>
    [Required]
    public string Transports { get; }

    /// <summary>
    ///     Creation date of the credential record in unixtime seconds format.
    /// </summary>
    public long CreatedAtUnixTime { get; }

    /// <summary>
    ///     Converts <see cref="SqlServerPublicKeyCredentialDescriptor" /> to <see cref="PublicKeyCredentialDescriptor" /> if possible.
    /// </summary>
    /// <param name="result">Output parameter. Contains <see cref="PublicKeyCredentialDescriptor" /> if the conversion was successful and the method returned <see langword="true" />, otherwise - <see langword="null" />.</param>
    /// <returns><see langword="true" /> if the conversion was successful, otherwise - <see langword="false" />.</returns>
    public virtual bool TryToPublicKeyCredentialDescriptor([NotNullWhen(true)] out PublicKeyCredentialDescriptor? result)
    {
        result = null;
        var type = (PublicKeyCredentialType) Type;
        if (!Enum.IsDefined(type))
        {
            return false;
        }

        var transports = Array.Empty<AuthenticatorTransport>();
        if (!string.IsNullOrEmpty(Transports))
        {
            var transportsIntegers = JsonSerializer.Deserialize<int[]>(Transports);
            if (transportsIntegers?.Length > 0)
            {
                var typedTransports = transportsIntegers
                    .Select(x => (AuthenticatorTransport) x)
                    .ToArray();
                foreach (var authenticatorTransport in typedTransports)
                {
                    if (!Enum.IsDefined(authenticatorTransport))
                    {
                        return false;
                    }
                }

                transports = typedTransports;
            }
        }

        result = new(type, CredentialId, transports);
        return true;
    }
}
