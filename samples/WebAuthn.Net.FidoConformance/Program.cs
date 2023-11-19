using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http.Extensions;
using WebAuthn.Net.FidoConformance.Services;
using WebAuthn.Net.FidoConformance.Services.ConformanceMetadata;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Storage.InMemory.Configuration.DependencyInjection;

namespace WebAuthn.Net.FidoConformance;

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddSingleton<RequestLoggingMiddleware>();
        builder.Services.AddSingleton<LocalFilesFidoMetadataHttpClientDelegatingHandler>();

        // Add services to the container.
        builder.Services.AddControllersWithViews();
        builder.Services.AddSingleton<IFidoMetadataProvider, LocalFilesFidoMetadataProviderForMdsTests>();
        builder.Services.AddSingleton<ITpmManufacturerVerifier, ConformanceTpmManufacturerVerifier>();
        builder.Services.AddWebAuthnInMemory(
            static options =>
            {
                options.AttestationTypes.None.IsAcceptable = true;
                options.AttestationTypes.Self.IsAcceptable = true;
            },
            static fidoHttp =>
            {
                fidoHttp.AddHttpMessageHandler<LocalFilesFidoMetadataHttpClientDelegatingHandler>();
            },
            static ingest =>
            {
            },
            static regOptions =>
            {
                regOptions.Cookie.HttpOnly = false;
            },
            static authOptions =>
            {
                authOptions.Cookie.HttpOnly = false;
            });

        //
        // builder.Services.AddWebAuthnMySql(
        //     static options =>
        //     {
        //         options.AttestationTypes.None.IsAcceptable = true;
        //         options.AttestationTypes.Self.IsAcceptable = true;
        //     },
        //     static fidoHttp =>
        //     {
        //         fidoHttp.AddHttpMessageHandler<LocalFilesFidoMetadataHttpClientDelegatingHandler>();
        //     },
        //     static ingest =>
        //     {
        //     },
        //     static regOptions =>
        //     {
        //         regOptions.Cookie.HttpOnly = false;
        //     },
        //     static authOptions =>
        //     {
        //         authOptions.Cookie.HttpOnly = false;
        //     },
        //     static mysql =>
        //     {
        //         mysql.ConnectionString = "Server=localhost;Port=3306;User ID=root;Password=root;Database=webauthn;Pooling=True;Default Command Timeout=30";
        //     });
        // builder.Services.AddWebAuthnPostgreSql(
        //     static options =>
        //     {
        //         options.AttestationTypes.None.IsAcceptable = true;
        //         options.AttestationTypes.Self.IsAcceptable = true;
        //     },
        //     static fidoHttp =>
        //     {
        //         fidoHttp.AddHttpMessageHandler<LocalFilesFidoMetadataHttpClientDelegatingHandler>();
        //     },
        //     static ingest =>
        //     {
        //     },
        //     static regOptions =>
        //     {
        //         regOptions.Cookie.HttpOnly = false;
        //     },
        //     static authOptions =>
        //     {
        //         authOptions.Cookie.HttpOnly = false;
        //     },
        //     static postgresql =>
        //     {
        //         postgresql.ConnectionString = "Host=localhost;Port=5432;Password=postgres;Username=postgres;Database=webauthn;Pooling=True";
        //     });
        // builder.Services.AddWebAuthnSqlServer(
        //     static options =>
        //     {
        //         options.AttestationTypes.None.IsAcceptable = true;
        //         options.AttestationTypes.Self.IsAcceptable = true;
        //     },
        //     static fidoHttp =>
        //     {
        //         fidoHttp.AddHttpMessageHandler<LocalFilesFidoMetadataHttpClientDelegatingHandler>();
        //     },
        //     static ingest =>
        //     {
        //     },
        //     static regOptions =>
        //     {
        //         regOptions.Cookie.HttpOnly = false;
        //     },
        //     static authOptions =>
        //     {
        //         authOptions.Cookie.HttpOnly = false;
        //     },
        //      static sqlServer =>
        //     {
        //         sqlServer.ConnectionString = "Data Source=localhost;Initial Catalog=webauthn;User ID=sa;Password=WebAuthn!1337;Pooling=True;Trust Server Certificate=True";
        //     });
        var app = builder.Build();
        app.UseMiddleware<RequestLoggingMiddleware>();

        // Configure the HTTP request pipeline.
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Home/Error");
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseStaticFiles();
        app.UseRouting();
        app.UseAuthorization();
        app.MapControllers();
        app.Run();
    }
}

public class RequestLoggingMiddleware : IMiddleware
{
    private readonly ILogger<RequestLoggingMiddleware> _logger;

    public RequestLoggingMiddleware(ILogger<RequestLoggingMiddleware> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
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
        var intendedJson = JsonSerializer.Serialize(element, new JsonSerializerOptions(JsonSerializerDefaults.General)
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never,
            WriteIndented = true
        });
        _logger.LogInformation($"Request {context.Request.Method} {context.Request.GetEncodedPathAndQuery()}{Environment.NewLine}Body:{Environment.NewLine}{intendedJson}");
        await next(context);
    }
}
