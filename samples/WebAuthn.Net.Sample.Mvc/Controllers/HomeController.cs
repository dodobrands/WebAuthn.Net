using Microsoft.AspNetCore.Mvc;

namespace WebAuthn.Net.Sample.Mvc.Controllers;

[Route("/")]
public class HomeController : Controller
{
    [HttpGet]
    public  IActionResult Index() => RedirectToActionPermanent("Index", "Fido");
}
