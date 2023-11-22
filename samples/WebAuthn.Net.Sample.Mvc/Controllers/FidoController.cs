using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebAuthn.Net.Sample.Mvc.Controllers;

[Authorize]
public class FidoController : Controller
{
    [HttpGet]
    public IActionResult Authenticated(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        return View();
    }

    [HttpGet]
    [Authorize]
    public async Task<IActionResult> Logout(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        await HttpContext.SignOutAsync();

        return RedirectToAction("Index", "Passwordless");
    }
}
