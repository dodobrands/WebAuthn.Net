using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.None;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.None;

/// <summary>
///     Default implementation of <see cref="INoneAttestationStatementVerifier{TContext}" />.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public class DefaultNoneAttestationStatementVerifier<TContext> :
    INoneAttestationStatementVerifier<TContext> where TContext : class, IWebAuthnContext
{
    /// <inheritdoc />
    public virtual Task<Result<VerifiedAttestationStatement>> VerifyAsync(
        TContext context,
        NoneAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken)
    {
        // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-none-attestation
        // §8.7. None Attestation Statement Format
        var result = new VerifiedAttestationStatement(
            AttestationStatementFormat.None,
            AttestationType.None,
            null,
            null);
        return Task.FromResult(Result<VerifiedAttestationStatement>.Success(result));
    }
}
