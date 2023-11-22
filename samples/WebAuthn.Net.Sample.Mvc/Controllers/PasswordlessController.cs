using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebAuthn.Net.Sample.Mvc.Constants;
using WebAuthn.Net.Services.AuthenticationCeremony;
using WebAuthn.Net.Services.RegistrationCeremony;

using AssertionOptions =
    WebAuthn.Net.Sample.Mvc.Models.Assertion.CreateOptions.Request.ServerPublicKeyCredentialGetOptionsRequest;
using AssertionKey =
    WebAuthn.Net.Sample.Mvc.Models.Assertion.CompleteCeremony.Request.ServerPublicKeyCredential;

namespace WebAuthn.Net.Sample.Mvc.Controllers;

public class PasswordlessController : Controller
{
    private readonly IRegistrationCeremonyService _registrationCeremony;
    private readonly IAuthenticationCeremonyService _authenticationCeremony;

    public PasswordlessController(IRegistrationCeremonyService registrationCeremony, IAuthenticationCeremonyService authenticationCeremony)
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
}

