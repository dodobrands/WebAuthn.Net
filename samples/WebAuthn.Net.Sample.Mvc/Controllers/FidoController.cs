using Microsoft.AspNetCore.Mvc;
using WebAuthn.Net.Sample.Mvc.Constants;
using WebAuthn.Net.Sample.Mvc.Models.Attestation.CompleteCeremony.Request;
using WebAuthn.Net.Sample.Mvc.Models.Attestation.CreateOptions.Request;
using WebAuthn.Net.Sample.Mvc.Services;
using WebAuthn.Net.Services.AuthenticationCeremony;
using WebAuthn.Net.Services.RegistrationCeremony;

using AssertionOptions =
    WebAuthn.Net.Sample.Mvc.Models.Assertion.CreateOptions.Request.ServerPublicKeyCredentialGetOptionsRequest;
using AssertionKey =
    WebAuthn.Net.Sample.Mvc.Models.Assertion.CompleteCeremony.Request.ServerPublicKeyCredential;

namespace WebAuthn.Net.Sample.Mvc.Controllers;

public class FidoController : Controller
{

    private readonly UserSessionStorage _userSession;
    private readonly IRegistrationCeremonyService _registrationCeremony;
    private readonly IAuthenticationCeremonyService _authenticationCeremony;

    public FidoController(IRegistrationCeremonyService registrationCeremony, UserSessionStorage userSession, IAuthenticationCeremonyService authenticationCeremony)
    {
        _registrationCeremony = registrationCeremony;
        _userSession = userSession;
        _authenticationCeremony = authenticationCeremony;
    }

    // GET
    [HttpGet]
    public IActionResult Index(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (HttpContext.Request.Cookies.TryGetValue(ExampleConstants.CookieAuthentication.AuthCookieName, out var cookie))
            return RedirectToAction("Authenticated");

        return View();
    }

    [HttpGet]
    public IActionResult Authenticated(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!HttpContext.Request.Cookies.TryGetValue(ExampleConstants.CookieAuthentication.AuthCookieName, out var cookie))
            return RedirectToAction("Index");

        return View();
    }

    [HttpPost]
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
        _userSession.SaveRegistration(request.UserName, result.RegistrationCeremonyId);
        return Json(result);
    }

    [HttpPost]
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
        _userSession.ClearRegistration(cookie!);

        return Json(result);
    }

    [HttpPost]
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
        _userSession.SaveAssertion(request.UserName, result.AuthenticationCeremonyId);

        return Ok(result);
    }

    [HttpPost]
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
            var username = _userSession.GetUsernameByAssertionId(cookie!);
            var cookieOptions = new CookieBuilder()
            {
                HttpOnly = true,
                SecurePolicy = CookieSecurePolicy.Always,
                SameSite = SameSiteMode.None
            };
            var cookieResult = cookieOptions.Build(HttpContext, DateTimeOffset.Now.AddMonths(1));
            HttpContext.Response.Cookies.Append(ExampleConstants.CookieAuthentication.AuthCookieName, username, cookieResult);
        }

        HttpContext.Response.Cookies.Delete(ExampleConstants.CookieAuthentication.AuthAssertionSessionId);
        _userSession.ClearAssertion(cookie!);

        return Ok(result);
    }
}

