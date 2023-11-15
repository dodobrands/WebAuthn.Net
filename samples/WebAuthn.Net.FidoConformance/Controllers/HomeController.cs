using Microsoft.AspNetCore.Mvc;

namespace WebAuthn.Net.FidoConformance.Controllers;

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
