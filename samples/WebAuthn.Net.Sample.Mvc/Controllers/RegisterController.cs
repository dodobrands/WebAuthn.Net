using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebAuthn.Net.Sample.Mvc.Constants;
using WebAuthn.Net.Sample.Mvc.Models.Register;
using WebAuthn.Net.Sample.Mvc.Services;
using WebAuthn.Net.Services.RegistrationCeremony;

namespace WebAuthn.Net.Sample.Mvc.Controllers;

public class RegisterController : Controller
{
    private readonly IRegistrationCeremonyService _registrationCeremony;
    private readonly UserHandleStore _userHandle;

    public RegisterController(IRegistrationCeremonyService registrationCeremony, UserHandleStore userHandle)
    {
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
    public async Task<IActionResult> BeginRegisterCeremony([FromBody] ServerPublicKeyCredentialCreationOptionsRequest request, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(request);
        token.ThrowIfCancellationRequested();

        if (!ModelState.IsValid)
        {
            throw new InvalidDataException();
        }

        var userId = Guid.NewGuid().ToString();
        var result = await _registrationCeremony.BeginCeremonyAsync(HttpContext, request.ToBeginCeremonyRequest(userId), token);
        HttpContext.Response.Cookies.Append(ExampleConstants.CookieAuthentication.RegistrationSessionId, result.RegistrationCeremonyId);
        _userHandle.Set(userId, result.Options.User.Name);
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
}
