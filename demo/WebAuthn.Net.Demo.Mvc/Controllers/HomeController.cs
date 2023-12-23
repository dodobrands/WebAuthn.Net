using Microsoft.AspNetCore.Mvc;

namespace WebAuthn.Net.Demo.Mvc.Controllers;

public class HomeController : Controller
{
    [HttpGet]
    public IActionResult Index()
    {
        return RedirectToAction("Index", "Passwordless");
    }
}
