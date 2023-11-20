using Microsoft.AspNetCore.Mvc;
using WebAuthn.Net.Sample.Mvc.Constants;
using WebAuthn.Net.Sample.Mvc.Models.Attestation.CompleteCeremony.Request;
using WebAuthn.Net.Sample.Mvc.Models.Attestation.CreateOptions.Request;
using WebAuthn.Net.Sample.Mvc.Services;
using WebAuthn.Net.Services.RegistrationCeremony;


namespace WebAuthn.Net.Sample.Mvc.Controllers;

public class FidoController : Controller
{

    private readonly UserSessionStorage _userSession;
    private readonly IRegistrationCeremonyService _registrationCeremony;

    public FidoController(IRegistrationCeremonyService registrationCeremony, UserSessionStorage userSession)
    {
        _registrationCeremony = registrationCeremony;
        _userSession = userSession;
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

        if (!HttpContext.Request.Cookies.TryGetValue(ExampleConstants.CookieAuthentication.AuthCookieName, out var cookie))
            throw new UnauthorizedAccessException();

        var ceremonyModel = request.ToCompleteCeremonyRequest(cookie!);
        var userName = _userSession.GetUsernameByRegId(cookie!);
        var result = await _registrationCeremony.CompleteCeremonyAsync(HttpContext, ceremonyModel, token);

        HttpContext.Response.Cookies.Delete(ExampleConstants.CookieAuthentication.RegistrationSessionId);
        _userSession.ClearRegistration(cookie!);

        if (result.Successful)
        {
            var cookieBuilder = new CookieBuilder()
            {
                HttpOnly = true,
                SameSite = SameSiteMode.None,
                SecurePolicy = CookieSecurePolicy.Always
            };
            var cookieOptions = cookieBuilder.Build(HttpContext, DateTimeOffset.Now.AddDays(1));
            HttpContext.Response.Cookies.Append(ExampleConstants.CookieAuthentication.AuthCookieName, userName, cookieOptions);
        }
        return Json(result);
    }
}

