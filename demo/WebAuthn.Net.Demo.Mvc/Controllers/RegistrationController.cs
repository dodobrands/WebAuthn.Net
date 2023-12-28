using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebAuthn.Net.Demo.Mvc.Services.Abstractions.RegistrationCeremonyHandle;
using WebAuthn.Net.Demo.Mvc.Services.Abstractions.User;
using WebAuthn.Net.Demo.Mvc.ViewModels.Registration;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Services.RegistrationCeremony;

namespace WebAuthn.Net.Demo.Mvc.Controllers;

public class RegistrationController : Controller
{
    private readonly IRegistrationCeremonyHandleService _registrationCeremonyHandleService;
    private readonly IRegistrationCeremonyService _registrationCeremonyService;
    private readonly IUserService _userService;

    public RegistrationController(
        IRegistrationCeremonyService registrationCeremonyService,
        IRegistrationCeremonyHandleService registrationCeremonyHandleService,
        IUserService userService)
    {
        ArgumentNullException.ThrowIfNull(registrationCeremonyService);
        ArgumentNullException.ThrowIfNull(registrationCeremonyHandleService);
        ArgumentNullException.ThrowIfNull(userService);
        _registrationCeremonyService = registrationCeremonyService;
        _registrationCeremonyHandleService = registrationCeremonyHandleService;
        _userService = userService;
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CreateRegistrationOptions(
        [FromBody] CreateRegistrationOptionsViewModel model,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(model);
        cancellationToken.ThrowIfCancellationRequested();
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var userHandle = await _userService.CreateAsync(
            HttpContext,
            model.UserName,
            cancellationToken);
        var result = await _registrationCeremonyService.BeginCeremonyAsync(
            HttpContext,
            model.ToBeginCeremonyRequest(userHandle),
            cancellationToken);
        await _registrationCeremonyHandleService.SaveAsync(
            HttpContext,
            result.RegistrationCeremonyId,
            cancellationToken);
        return Ok(result.Options);
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CompleteRegistration(
        [FromBody] RegistrationResponseJSON model,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(model);
        cancellationToken.ThrowIfCancellationRequested();

        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var registrationCeremonyId = await _registrationCeremonyHandleService.ReadAsync(
            HttpContext,
            cancellationToken);
        if (registrationCeremonyId is null)
        {
            ModelState.AddModelError("", "Registration ceremony not found");
            return BadRequest(ModelState);
        }

        var result = await _registrationCeremonyService.CompleteCeremonyAsync(
            HttpContext,
            new(
                registrationCeremonyId,
                null,
                model),
            cancellationToken);
        if (result.HasError)
        {
            ModelState.AddModelError("", "The registration ceremony completed with an error");
            return BadRequest(ModelState);
        }

        await _registrationCeremonyHandleService.DeleteAsync(HttpContext, cancellationToken);
        return Ok();
    }
}
