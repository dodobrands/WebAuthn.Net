using Microsoft.AspNetCore.Authentication.Cookies;
using OpenTelemetry.Metrics;
using WebAuthn.Net.Configuration.DependencyInjection;
using WebAuthn.Net.Demo.Mvc.Services.Abstractions.AuthenticationCeremonyHandle;
using WebAuthn.Net.Demo.Mvc.Services.Abstractions.RegistrationCeremonyHandle;
using WebAuthn.Net.Demo.Mvc.Services.Abstractions.User;
using WebAuthn.Net.Demo.Mvc.Services.Implementation;
using WebAuthn.Net.OpenTelemetry.Extensions;
using WebAuthn.Net.Storage.InMemory.Models;
using WebAuthn.Net.Storage.InMemory.Services.ContextFactory;

namespace WebAuthn.Net.Demo.Mvc;

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var services = builder.Services;
        services.AddControllersWithViews();
        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, static options =>
            {
                options.ExpireTimeSpan = TimeSpan.FromDays(1);
                options.SlidingExpiration = false;
                options.Cookie.SameSite = SameSiteMode.None;
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.LoginPath = "/passwordless";
                options.LogoutPath = "/account/logout";
            });
        services.Configure<RouteOptions>(options => options.LowercaseUrls = true);
        builder.Services.AddWebAuthnCore<DefaultInMemoryContext>()
            .AddDefaultStorages()
            .AddContextFactory<DefaultInMemoryContext, DefaultInMemoryContextFactory>()
            .AddCredentialStorage<DefaultInMemoryContext, DefaultCookieCredentialStorage<DefaultInMemoryContext>>();
        services.AddOpenTelemetry()
            .WithMetrics(metrics =>
            {
                metrics.AddWebAuthnNet();
                metrics.AddPrometheusExporter();
            });
        services.AddSingleton<IRegistrationCeremonyHandleService, DefaultRegistrationCeremonyHandleService>();
        services.AddSingleton<IAuthenticationCeremonyHandleService, DefaultAuthenticationCeremonyHandleService>();
        services.AddSingleton<IUserService, DefaultUserService>();


        var app = builder.Build();

        // Configure the HTTP request pipeline.
        app.UseExceptionHandler("/error");
        app.UseStatusCodePagesWithReExecute("/code/{0}");
        app.UseHsts();
        app.UseHttpsRedirection();
        app.UseStaticFiles();
        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();
        app.MapDefaultControllerRoute();
        app.UseOpenTelemetryPrometheusScrapingEndpoint();
        app.Run();
    }
}
