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
        return HandleReturnUrl(returnUrl);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Reset(string? returnUrl)
    {
        foreach (var (key, _) in HttpContext.Request.Cookies)
        {
            if (!key.Contains("antiforgery", StringComparison.InvariantCultureIgnoreCase))
            {
                HttpContext.Response.Cookies.Delete(key);
            }
        }

        return HandleReturnUrl(returnUrl);
    }

    private RedirectToActionResult HandleReturnUrl(string? returnUrl)
    {
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
