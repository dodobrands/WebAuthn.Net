using Microsoft.AspNetCore.Authentication.Cookies;
using OpenTelemetry.Metrics;
using WebAuthn.Net.OpenTelemetry.Extensions;
using WebAuthn.Net.Sample.Mvc.Services;
using WebAuthn.Net.Storage.InMemory.Configuration.DependencyInjection;

namespace WebAuthn.Net.Sample.Mvc;

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var services = builder.Services;
        services.AddControllersWithViews();
        services.AddWebAuthnInMemory(options => options.AttestationTypes.None.IsAcceptable = true);
        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(static options =>
            {
                options.ExpireTimeSpan = TimeSpan.FromDays(1);
                options.SlidingExpiration = false;
                options.Cookie.SameSite = SameSiteMode.None;
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.LoginPath = "/passwordless";
                options.LogoutPath = "/fido/logout";
            });
        services.AddSingleton<UserHandleStore>();
        services.Configure<RouteOptions>(options => options.LowercaseUrls = true);
        services.AddOpenTelemetry()
            .WithMetrics(metrics =>
            {
                metrics.AddWebAuthnNet();
                metrics.AddPrometheusExporter();
            });


        var app = builder.Build();

        // Configure the HTTP request pipeline.
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Home/Error");
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseStaticFiles();
        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapDefaultControllerRoute();
        });
        app.UseOpenTelemetryPrometheusScrapingEndpoint();
        app.Run();
    }
}
