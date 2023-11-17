using Microsoft.AspNetCore.Authentication.Cookies;
using WebAuthn.Net.Storage.InMemory.Configuration.DependencyInjection;

namespace WebAuthn.Net.Sample.Mvc;

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var services = builder.Services;
        services.AddControllersWithViews();
        services.AddWebAuthnInMemory();
        services.AddAuthentication()
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            {
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.None;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
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
        app.MapControllerRoute(
            "default",
            "{controller=Home}/{action=Index}/{id?}");
        app.Run();
    }
}
