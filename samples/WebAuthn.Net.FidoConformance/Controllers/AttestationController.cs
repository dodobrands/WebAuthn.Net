using System.Diagnostics.CodeAnalysis;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using WebAuthn.Net.FidoConformance.Constants;
using WebAuthn.Net.FidoConformance.Models.Attestation.CompleteCeremony.Request;
using WebAuthn.Net.FidoConformance.Models.Attestation.CreateOptions.Request;
using WebAuthn.Net.FidoConformance.Models.Attestation.CreateOptions.Response;
using WebAuthn.Net.FidoConformance.Models.Common.Response;
using WebAuthn.Net.Services.RegistrationCeremony;

namespace WebAuthn.Net.FidoConformance.Controllers;

[Route("/attestation")]
public class AttestationController : Controller
{
    private readonly IRegistrationCeremonyService _registration;

    public AttestationController(IRegistrationCeremonyService registration)
    {
        ArgumentNullException.ThrowIfNull(registration);
        _registration = registration;
    }

    [HttpPost("options")]
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    public async Task<IActionResult> CreateOptionsAsync(
        [FromBody] ServerPublicKeyCredentialCreationOptionsRequest model,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!ModelState.IsValid || model is null)
        {
            return BadRequest(ServerResponse.Error("Invalid model"));
        }

        var beginCeremonyRequest = model.ToBeginCeremonyRequest();
        var result = await _registration.BeginCeremonyAsync(HttpContext, beginCeremonyRequest, cancellationToken);
        var successfulResult = ServerPublicKeyCredentialCreationOptionsResponse
            .FromPublicKeyCredentialCreationOptions(result.Options);
        SaveRegistrationId(result.RegistrationCeremonyId);
        return Ok(successfulResult);
    }

    [HttpPost("result")]
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    public async Task<IActionResult> PerformAttestationAsync(
        [FromBody] ServerPublicKeyCredential model,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!ModelState.IsValid || model is null)
        {
            return BadRequest(ServerResponse.Error("Invalid model"));
        }

        if (!TryReadRegistrationId(out var registrationId))
        {
            return BadRequest(ServerResponse.Error("Can't get registration id"));
        }

        var completeCeremonyRequest = model.ToCompleteCeremonyRequest(registrationId);
        var result = await _registration.CompleteCeremonyAsync(HttpContext, completeCeremonyRequest, cancellationToken);
        if (!result.Successful)
        {
            return BadRequest(ServerResponse.Error("Can't register key"));
        }

        return Ok(ServerResponse.Success());
    }

    private void SaveRegistrationId(string registrationCeremonyId)
    {
        HttpContext.Response.Cookies.Append(
            TempCookies.RegistrationCeremonyId,
            WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(registrationCeremonyId)));
    }

    private bool TryReadRegistrationId([NotNullWhen(true)] out string? registrationId)
    {
        if (!HttpContext.Request.Cookies.TryGetValue(TempCookies.RegistrationCeremonyId, out var cookies) || string.IsNullOrEmpty(cookies))
        {
            registrationId = null;
            return false;
        }

        var utf8Bytes = WebEncoders.Base64UrlDecode(cookies);
        registrationId = Encoding.UTF8.GetString(utf8Bytes);
        return true;
    }
}
