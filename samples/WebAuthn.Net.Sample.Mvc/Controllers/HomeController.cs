using Microsoft.AspNetCore.Mvc;

namespace WebAuthn.Net.Sample.Mvc.Controllers;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}
