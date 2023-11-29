using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebAuthn.Net.Sample.Mvc.Constants;
using WebAuthn.Net.Sample.Mvc.Models.Usernameless;
using WebAuthn.Net.Sample.Mvc.Services;
using WebAuthn.Net.Services.AuthenticationCeremony;
using WebAuthn.Net.Services.RegistrationCeremony;

namespace WebAuthn.Net.Sample.Mvc.Controllers;

public class UsernamelessController : Controller
{
    private readonly IAuthenticationCeremonyService _authenticationCeremony;
    private readonly IRegistrationCeremonyService _registrationCeremony;
    private readonly UserHandleStore _userHandle;

    public UsernamelessController(IAuthenticationCeremonyService authenticationCeremony, IRegistrationCeremonyService registrationCeremony, UserHandleStore userHandle)
    {
        _authenticationCeremony = authenticationCeremony;
        _registrationCeremony = registrationCeremony;
        _userHandle = userHandle;
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Index(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        return View();
    }

    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> BeginRegisterCeremony([FromBody] RegisterPublicKeyCredentialCreationOptionsRequest request, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(request);
        token.ThrowIfCancellationRequested();

        if (!ModelState.IsValid)
        {
            throw new InvalidDataException();
        }

        var id = Guid.NewGuid().ToString();
        var result = await _registrationCeremony.BeginCeremonyAsync(HttpContext, request.ToBeginCeremonyRequest(id), token);
        HttpContext.Response.Cookies
            .Append(ExampleConstants.CookieAuthentication.RegistrationSessionId, result.RegistrationCeremonyId);
        _userHandle.Set(id, result.Options.User.Name);
        return Json(result);
    }

    [HttpPost]
    [AllowAnonymous]
    public async Task<IActionResult> RegisterCeremony([FromBody] RegisterPublicKeyCredential request, CancellationToken token)
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
    public async Task<IActionResult> BeginAuthenticationCeremony([FromBody] AttestationServerPKeyOptionsRequest request, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(request);
        token.ThrowIfCancellationRequested();
        await Task.Yield();

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
    public async Task<IActionResult> AuthenticationCeremony([FromBody] AttestationPKeyCredential request, CancellationToken token)
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
