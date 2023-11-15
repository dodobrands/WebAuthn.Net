using System.Diagnostics.CodeAnalysis;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using WebAuthn.Net.FidoConformance.Constants;
using WebAuthn.Net.FidoConformance.Models.Assertion.CompleteCeremony.Request;
using WebAuthn.Net.FidoConformance.Models.Assertion.CreateOptions.Request;
using WebAuthn.Net.FidoConformance.Models.Assertion.CreateOptions.Response;
using WebAuthn.Net.FidoConformance.Models.Common.Response;
using WebAuthn.Net.Services.AuthenticationCeremony;

namespace WebAuthn.Net.FidoConformance.Controllers;

[Route("/assertion")]
public class AssertionController : Controller
{
    private readonly IAuthenticationCeremonyService _authentication;

    public AssertionController(IAuthenticationCeremonyService authentication)
    {
        ArgumentNullException.ThrowIfNull(authentication);
        _authentication = authentication;
    }

    [HttpPost("options")]
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    public async Task<IActionResult> CreateOptionsAsync(
        [FromBody] ServerPublicKeyCredentialGetOptionsRequest model,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!ModelState.IsValid || model is null)
        {
            return BadRequest(ServerResponse.Error("Invalid model"));
        }

        var beginCeremonyRequest = model.ToBeginCeremonyRequest();
        var result = await _authentication.BeginCeremonyAsync(HttpContext, beginCeremonyRequest, cancellationToken);
        var successfulResult = ServerPublicKeyCredentialGetOptionsResponse.FromPublicKeyCredentialRequestOptions(result.Options);
        SaveAuthenticationId(result.AuthenticationCeremonyId);
        return Ok(successfulResult);
    }

    [HttpPost("result")]
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    public async Task<IActionResult> PerformAssertionAsync(
        [FromBody] ServerPublicKeyCredential model,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!ModelState.IsValid || model is null)
        {
            return BadRequest(ServerResponse.Error("Invalid model"));
        }

        if (!TryReadAuthenticationId(out var registrationId))
        {
            return BadRequest(ServerResponse.Error("Can't get authentication id"));
        }

        var completeCeremonyRequest = model.ToCompleteCeremonyRequest(registrationId);
        var result = await _authentication.CompleteCeremonyAsync(HttpContext, completeCeremonyRequest, cancellationToken);
        if (!result.Successful)
        {
            return BadRequest(ServerResponse.Error("Can't authenticate user"));
        }

        return Ok(ServerResponse.Success());
    }

    private void SaveAuthenticationId(string registrationCeremonyId)
    {
        HttpContext.Response.Cookies.Append(
            TempCookies.AuthenticationCeremonyId,
            WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(registrationCeremonyId)));
    }

    private bool TryReadAuthenticationId([NotNullWhen(true)] out string? registrationId)
    {
        if (!HttpContext.Request.Cookies.TryGetValue(TempCookies.AuthenticationCeremonyId, out var cookies) || string.IsNullOrEmpty(cookies))
        {
            registrationId = null;
            return false;
        }

        var utf8Bytes = WebEncoders.Base64UrlDecode(cookies);
        registrationId = Encoding.UTF8.GetString(utf8Bytes);
        return true;
    }
}
