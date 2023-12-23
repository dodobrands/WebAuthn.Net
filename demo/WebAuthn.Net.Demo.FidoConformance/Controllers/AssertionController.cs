using System.Diagnostics.CodeAnalysis;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using WebAuthn.Net.Demo.FidoConformance.Constants;
using WebAuthn.Net.Demo.FidoConformance.Models.Assertion.CompleteCeremony.Request;
using WebAuthn.Net.Demo.FidoConformance.Models.Assertion.CreateOptions.Request;
using WebAuthn.Net.Demo.FidoConformance.Models.Assertion.CreateOptions.Response;
using WebAuthn.Net.Demo.FidoConformance.Models.Common.Response;
using WebAuthn.Net.Services.AuthenticationCeremony;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Demo.FidoConformance.Controllers;

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

        if (!model.TryToBeginCeremonyRequest(out var beginCeremonyRequest))
        {
            return BadRequest(ServerResponse.Error("Can't map model to begin authentication ceremony request"));
        }

        var result = await _authentication.BeginCeremonyAsync(HttpContext, beginCeremonyRequest, cancellationToken);
        var successfulResult = ServerPublicKeyCredentialGetOptionsResponse
            .FromPublicKeyCredentialRequestOptions(result.Options);
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
        if (result.HasError)
        {
            return BadRequest(ServerResponse.Error("Can't authenticate user"));
        }

        return Ok(ServerResponse.Success());
    }

    private void SaveAuthenticationId(string registrationCeremonyId)
    {
        HttpContext.Response.Cookies.Append(
            TempCookies.AuthenticationCeremonyId,
            Base64Url.Encode(Encoding.UTF8.GetBytes(registrationCeremonyId)));
    }

    private bool TryReadAuthenticationId([NotNullWhen(true)] out string? authenticationId)
    {
        if (!HttpContext.Request.Cookies.TryGetValue(TempCookies.AuthenticationCeremonyId, out var cookies) || string.IsNullOrEmpty(cookies))
        {
            authenticationId = null;
            return false;
        }

        if (!Base64Url.TryDecode(cookies, out var utf8Bytes))
        {
            authenticationId = null;
            return false;
        }

        authenticationId = Encoding.UTF8.GetString(utf8Bytes);
        return true;
    }
}
