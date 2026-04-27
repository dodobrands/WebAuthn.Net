using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http.Extensions;

namespace WebAuthn.Net.Demo.FidoConformance.Middleware;

public class RequestLoggingMiddleware : IMiddleware
{
    private readonly JsonSerializerOptions _jsonSerializerOptions;
    private readonly ILogger<RequestLoggingMiddleware> _logger;

    public RequestLoggingMiddleware(ILogger<RequestLoggingMiddleware> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
        _jsonSerializerOptions = new(JsonSerializerDefaults.General)
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never,
            WriteIndented = true
        };
    }

    [SuppressMessage("Performance", "CA1848:Use the LoggerMessage delegates")]
    [SuppressMessage("Usage", "CA2254:Template should be a static expression")]
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);
        context.Request.EnableBuffering(1024 * 1024 * 1024);
        using var ms = new MemoryStream();
        await context.Request.Body.CopyToAsync(ms);
        ms.Seek(0L, SeekOrigin.Begin);
        context.Request.Body.Seek(0L, SeekOrigin.Begin);
        var json = Encoding.UTF8.GetString(ms.ToArray());
        var element = JsonSerializer.Deserialize<JsonElement>(json);
        var intendedJson = JsonSerializer.Serialize(element, _jsonSerializerOptions);
// Error CA1873 : Evaluation of this argument may be expensive and unnecessary if logging is disabled (https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca1873)
#pragma warning disable CA1873
        _logger.LogRequestInformation(context.Request.Method, context.Request.GetEncodedPathAndQuery(), intendedJson);
#pragma warning restore CA1873
        await next(context);
    }
}

internal static partial class RequestLoggingMiddlewareLoggingExtensions
{
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "Request {Method} {PathAndQuery}\nBody:\n{Body}")]
    public static partial void LogRequestInformation(
        this ILogger logger,
        string method,
        string pathAndQuery,
        string body);
}
