using System.Net.Mime;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using WebAuthn.Net.Sample.Mvc.Constants;
using WebAuthn.Net.Services.RegistrationCeremony;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateCredential;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;

#pragma warning disable CA1825
namespace WebAuthn.Net.Sample.Mvc.Controllers;

public class FidoController : Controller
{

    private readonly IRegistrationCeremonyService _registrationCeremony;

    public FidoController(IRegistrationCeremonyService registrationCeremony)
    {
        _registrationCeremony = registrationCeremony;
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
    [ProducesResponseType(typeof(BeginRegistrationCeremonyResult), StatusCodes.Status200OK, MediaTypeNames.Application.Json)]
    public async Task<IActionResult> BeginRegisterCeremony([FromBody] BeginRegisterViewModel request, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Request);
        token.ThrowIfCancellationRequested();

        var result = await _registrationCeremony.BeginCeremonyAsync(HttpContext, request.Request, token);
        return Json(result);
    }

    [HttpPost]
    [ProducesResponseType(typeof(CompleteRegistrationCeremonyResult), StatusCodes.Status200OK, MediaTypeNames.Application.Json)]
    public async Task<IActionResult> RegisterCeremony([FromBody] RegisterViewModel request, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Request);
        ArgumentNullException.ThrowIfNull(request.UserName);
        token.ThrowIfCancellationRequested();

        var result = await _registrationCeremony.CompleteCeremonyAsync(HttpContext, request.Request, token);
        if (result.Successful)
        {
            var cookieBuilder = new CookieBuilder()
            {
                HttpOnly = true,
                SameSite = SameSiteMode.None,
                SecurePolicy = CookieSecurePolicy.Always
            };
            var cookieOptions = cookieBuilder.Build(HttpContext, DateTimeOffset.Now.AddDays(1));
            HttpContext.Response.Cookies.Append(ExampleConstants.CookieAuthentication.AuthCookieName, request.UserName, cookieOptions);
        }
        return Json(result);
    }
}

public class BeginRegisterViewModel
{
    [JsonPropertyName("request")]
    public BeginRegistrationCeremonyRequest? Request { get; set; }
}

public class RegisterViewModel
{

    [JsonPropertyName("username")]
    public string? UserName { get; set; }

    [JsonPropertyName("request")]
    public CompleteRegistrationCeremonyRequest? Request { get; set; }
}

#pragma warning restore CA1825
