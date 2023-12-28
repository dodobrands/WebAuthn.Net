using System.Diagnostics.CodeAnalysis;
using System.Net;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using WebAuthn.Net.Demo.Mvc.ViewModels.Error;

namespace WebAuthn.Net.Demo.Mvc.Controllers;

public class ErrorController : Controller
{
    [SuppressMessage("Security", "CA5395")]
    [Route("/error")]
    public IActionResult Index()
    {
        ErrorViewModel? result = null;
        var feature = HttpContext.Features.Get<IExceptionHandlerFeature>();
        if (feature?.Error != null)
        {
            var lastExceptionMessage = GetExceptionMessage(feature.Error);
            if (!string.IsNullOrEmpty(lastExceptionMessage))
            {
                result = new(lastExceptionMessage, 500, HttpContext.TraceIdentifier);
            }
        }

        if (result is null)
        {
            result = new("Unknown error", 500, HttpContext.TraceIdentifier);
        }

        var jsonResult = Json(result);
        jsonResult.StatusCode = result.StatusCode;
        return jsonResult;
    }

    [SuppressMessage("Security", "CA5395")]
    [Route("/error/code/{code:required:int:min(1)}")]
    public IActionResult Code([FromRoute] int code)
    {
        ErrorViewModel result;

        if (Enum.IsDefined((HttpStatusCode) code))
        {
            result = new(
                $"HTTP status code {(HttpStatusCode) code:G}",
                code,
                HttpContext.TraceIdentifier);
        }
        else
        {
            result = new($"Unknown status code {code}", 500, HttpContext.TraceIdentifier);
        }

        var jsonResult = Json(result);
        jsonResult.StatusCode = result.StatusCode;
        return jsonResult;
    }

    private static string GetExceptionMessage(Exception exception)
    {
        var lastException = UnrollException(exception);
        return lastException.Message;
    }

    private static Exception UnrollException(Exception exception)
    {
        var currentException = exception;
        while (currentException.InnerException != null)
        {
            currentException = currentException.InnerException;
        }

        return currentException;
    }
}
