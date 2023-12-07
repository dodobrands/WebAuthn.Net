using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebAuthn.Net.Sample.Mvc.Controllers;

[Authorize]
public class FidoController : Controller
{
    [HttpGet]
    public async Task<IActionResult> Logout(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        await HttpContext.SignOutAsync();

        return RedirectToAction("Index", "Passwordless");
    }
}
