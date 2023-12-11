using Microsoft.AspNetCore.Mvc;

namespace WebAuthn.Net.Sample.Mvc.Controllers;

public class HomeController : Controller
{
    [HttpGet]
    public IActionResult Index()
    {
        return RedirectToAction("Index", "Passwordless");
    }
}
