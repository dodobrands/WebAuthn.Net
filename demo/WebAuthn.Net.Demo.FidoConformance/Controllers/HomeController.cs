using Microsoft.AspNetCore.Mvc;

namespace WebAuthn.Net.Demo.FidoConformance.Controllers;

[Route("/")]
public class HomeController : Controller
{
    [HttpGet]
    public IActionResult Index()
    {
        return Ok(new
        {
            Status = "Alive"
        });
    }
}
