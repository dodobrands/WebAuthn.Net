using WebAuthn.Net.Sample.Mvc.Services;
using WebAuthn.Net.Storage.InMemory.Configuration.DependencyInjection;

namespace WebAuthn.Net.Sample.Mvc;

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var services = builder.Services;
        services.AddSingleton<UserSessionStorage>();
        services.AddControllersWithViews();
        services.AddWebAuthnInMemory();

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

        app.MapControllerRoute(
            "default",
            "{controller=Home}/{action=Index}/{id?}");
        app.Run();
    }
}
