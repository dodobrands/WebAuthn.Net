using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebAuthn.Net.Sample.Mvc.Constants;
using WebAuthn.Net.Sample.Mvc.Models.Passwordless;
using WebAuthn.Net.Sample.Mvc.Services;
using WebAuthn.Net.Services.AuthenticationCeremony;

namespace WebAuthn.Net.Sample.Mvc.Controllers;

public class PasswordlessController : Controller
{
    private readonly IAuthenticationCeremonyService _authenticationCeremony;
    private readonly UserHandleStore _userHandle;

    public PasswordlessController(IAuthenticationCeremonyService authenticationCeremony, UserHandleStore userHandle)
    {
        _authenticationCeremony = authenticationCeremony;
        _userHandle = userHandle;
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
    public async Task<IActionResult> BeginAuthenticationCeremony([FromBody] ServerPublicKeyCredentialGetOptionsRequest request, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(request);
        token.ThrowIfCancellationRequested();

        if (!ModelState.IsValid)
        {
            throw new InvalidDataException();
        }

        var userHandle = _userHandle.GetUserHandle(request.UserName);
        var result = await _authenticationCeremony.BeginCeremonyAsync(HttpContext, request.ToBeginCeremonyRequest(userHandle), token);
        HttpContext.Response.Cookies.Append(ExampleConstants.CookieAuthentication.AuthAssertionSessionId, result.AuthenticationCeremonyId);
        return Ok(result);
    }

    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> AuthenticationCeremony([FromBody] ServerPublicKeyCredential request, CancellationToken token)
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
                new (ClaimTypes.Name, _userHandle.Get(request.Response.UserHandle)),
            };
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new(claimsIdentity), new());
        }

        HttpContext.Response.Cookies.Delete(ExampleConstants.CookieAuthentication.AuthAssertionSessionId);
        return Ok(result);
    }
}

