using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebAuthn.Net.Demo.Mvc.Services.Abstractions.AuthenticationCeremonyHandle;
using WebAuthn.Net.Demo.Mvc.Services.Abstractions.User;
using WebAuthn.Net.Demo.Mvc.ViewModels.Passwordless;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.VerifyAssertion;
using WebAuthn.Net.Services.AuthenticationCeremony;

namespace WebAuthn.Net.Demo.Mvc.Controllers;

public class PasswordlessController : Controller
{
    private readonly IAuthenticationCeremonyHandleService _authenticationCeremonyHandleService;
    private readonly IAuthenticationCeremonyService _authenticationCeremonyService;
    private readonly IUserService _userService;

    public PasswordlessController(
        IAuthenticationCeremonyService authenticationCeremonyService,
        IAuthenticationCeremonyHandleService authenticationCeremonyHandleService,
        IUserService userService)
    {
        ArgumentNullException.ThrowIfNull(authenticationCeremonyService);
        ArgumentNullException.ThrowIfNull(authenticationCeremonyHandleService);
        ArgumentNullException.ThrowIfNull(userService);
        _authenticationCeremonyService = authenticationCeremonyService;
        _authenticationCeremonyHandleService = authenticationCeremonyHandleService;
        _userService = userService;
    }

    // GET
    [HttpGet]
    [AllowAnonymous]
    public IActionResult Index(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return View();
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CreateAuthenticationOptions(
        [FromBody] PasswordlessAuthenticationViewModel model,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(model);
        cancellationToken.ThrowIfCancellationRequested();

        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var applicationUser = await _userService.FindAsync(
            HttpContext,
            model.UserName,
            cancellationToken);
        if (applicationUser is null)
        {
            ModelState.AddModelError(nameof(model.UserName), "User not found");
            return BadRequest(ModelState);
        }

        var result = await _authenticationCeremonyService.BeginCeremonyAsync(
            HttpContext,
            model.ToBeginCeremonyRequest(applicationUser.UserHandle),
            cancellationToken);
        await _authenticationCeremonyHandleService.SaveAsync(
            HttpContext,
            result.AuthenticationCeremonyId,
            cancellationToken);
        return Ok(result.Options);
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CompleteAuthentication(
        [FromBody] AuthenticationResponseJSON model,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(model);
        cancellationToken.ThrowIfCancellationRequested();

        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var authenticationCeremonyId = await _authenticationCeremonyHandleService.ReadAsync(
            HttpContext,
            cancellationToken);
        if (authenticationCeremonyId is null)
        {
            ModelState.AddModelError("", "Authentication ceremony not found");
            return BadRequest(ModelState);
        }

        var result = await _authenticationCeremonyService.CompleteCeremonyAsync(
            HttpContext,
            new(
                authenticationCeremonyId,
                model),
            cancellationToken);
        if (result.HasError)
        {
            ModelState.AddModelError("", "The authentication ceremony completed with an error");
            return BadRequest(ModelState);
        }

        var applicationUser = await _userService.FindAsync(
            HttpContext,
            result.Ok.UserHandle,
            cancellationToken);
        if (applicationUser is null)
        {
            ModelState.AddModelError("", "User not found");
            return BadRequest(ModelState);
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, Convert.ToHexString(applicationUser.UserHandle)),
            new(ClaimTypes.Name, applicationUser.UserName)
        };
        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new(claimsIdentity),
            new()
            {
                IsPersistent = true
            });
        await _authenticationCeremonyHandleService.DeleteAsync(HttpContext, cancellationToken);
        return Ok(result);
    }
}
