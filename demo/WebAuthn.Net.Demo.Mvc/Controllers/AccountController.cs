using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace WebAuthn.Net.Demo.Mvc.Controllers;

public class AccountController : Controller
{
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout(string? returnUrl, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await HttpContext.SignOutAsync();

        if (!string.IsNullOrWhiteSpace(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            if (returnUrl == Url.Action("Index", "Passwordless"))
            {
                return RedirectToAction("Index", "Passwordless");
            }

            if (returnUrl == Url.Action("Index", "Usernameless"))
            {
                return RedirectToAction("Index", "Usernameless");
            }
        }

        return RedirectToAction("Index", "Home");
    }
}
