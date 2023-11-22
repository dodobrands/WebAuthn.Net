using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebAuthn.Net.Sample.Mvc.Constants;
using WebAuthn.Net.Sample.Mvc.Models.Attestation.CompleteCeremony.Request;
using WebAuthn.Net.Sample.Mvc.Models.Attestation.CreateOptions.Request;
using WebAuthn.Net.Services.AuthenticationCeremony;
using WebAuthn.Net.Services.RegistrationCeremony;

using AssertionOptions =
    WebAuthn.Net.Sample.Mvc.Models.Assertion.CreateOptions.Request.ServerPublicKeyCredentialGetOptionsRequest;
using AssertionKey =
    WebAuthn.Net.Sample.Mvc.Models.Assertion.CompleteCeremony.Request.ServerPublicKeyCredential;

namespace WebAuthn.Net.Sample.Mvc.Controllers;

public class FidoController : Controller
{
    private readonly IRegistrationCeremonyService _registrationCeremony;
    private readonly IAuthenticationCeremonyService _authenticationCeremony;

    public FidoController(IRegistrationCeremonyService registrationCeremony, IAuthenticationCeremonyService authenticationCeremony)
    {
        _registrationCeremony = registrationCeremony;
        _authenticationCeremony = authenticationCeremony;
    }

    // GET
    [HttpGet]
    [AllowAnonymous]
    public IActionResult Index(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        return View();
    }

    [HttpGet]
    [Authorize]
    public IActionResult Authenticated(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        return View();
    }

    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> BeginRegisterCeremony([FromBody] ServerPublicKeyCredentialCreationOptionsRequest request, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(request);
        token.ThrowIfCancellationRequested();

        if (!ModelState.IsValid)
        {
            throw new InvalidDataException();
        }

        var result = await _registrationCeremony.BeginCeremonyAsync(HttpContext, request.ToBeginCeremonyRequest(), token);
        HttpContext.Response.Cookies
            .Append(ExampleConstants.CookieAuthentication.RegistrationSessionId, result.RegistrationCeremonyId);
        return Json(result);
    }

    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> RegisterCeremony([FromBody] ServerPublicKeyCredential request, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(request);
        token.ThrowIfCancellationRequested();

        if (!ModelState.IsValid)
        {
            throw new InvalidDataException();
        }

        if (!HttpContext.Request.Cookies.TryGetValue(ExampleConstants.CookieAuthentication.RegistrationSessionId, out var cookie))
            throw new UnauthorizedAccessException();

        var ceremonyModel = request.ToCompleteCeremonyRequest(cookie!);
        var result = await _registrationCeremony.CompleteCeremonyAsync(HttpContext, ceremonyModel, token);

        HttpContext.Response.Cookies.Delete(ExampleConstants.CookieAuthentication.RegistrationSessionId);
        return Json(result);
    }

    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> BeginAuthenticationCeremony([FromBody] AssertionOptions request, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(request);
        token.ThrowIfCancellationRequested();

        if (!ModelState.IsValid)
        {
            throw new InvalidDataException();
        }

        var result = await _authenticationCeremony.BeginCeremonyAsync(HttpContext, request.ToBeginCeremonyRequest(), token);
        HttpContext.Response.Cookies.Append(ExampleConstants.CookieAuthentication.AuthAssertionSessionId, result.AuthenticationCeremonyId);
        return Ok(result);
    }

    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> AuthenticationCeremony([FromBody] AssertionKey request, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(request);
        token.ThrowIfCancellationRequested();

        if (!ModelState.IsValid)
        {
            throw new InvalidDataException();
        }

        if (!HttpContext.Request.Cookies.TryGetValue(ExampleConstants.CookieAuthentication.AuthAssertionSessionId, out var cookie))
            throw new UnauthorizedAccessException();

        var result = await _authenticationCeremony
            .CompleteCeremonyAsync(HttpContext, request.ToCompleteCeremonyRequest(cookie!), token);

        if (result.Successful)
        {
            var claims = new List<Claim>()
            {
                new (ClaimTypes.Name, request.Username),
            };
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new(claimsIdentity), new());
        }

        HttpContext.Response.Cookies.Delete(ExampleConstants.CookieAuthentication.AuthAssertionSessionId);
        return Ok(result);
    }

    [HttpGet]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync();
        return RedirectToAction("Index");
    }
}

