using System.Diagnostics.CodeAnalysis;
using Polly;
using WebAuthn.Net.Demo.FidoConformance.Middleware;
using WebAuthn.Net.Demo.FidoConformance.Services;
using WebAuthn.Net.Demo.FidoConformance.Services.ConformanceMetadata;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;
using WebAuthn.Net.Storage.InMemory.Configuration.DependencyInjection;

// using WebAuthn.Net.Storage.MySql.Configuration.DependencyInjection;
// using WebAuthn.Net.Storage.PostgreSql.Configuration.DependencyInjection;
// using WebAuthn.Net.Storage.SqlServer.Configuration.DependencyInjection;

namespace WebAuthn.Net.Demo.FidoConformance;

public static class Program
{
    [SuppressMessage("Performance", "CA1848:Use the LoggerMessage delegates")]
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddSingleton<RequestLoggingMiddleware>();
        builder.Services.AddSingleton<LocalFilesFidoMetadataHttpClientDelegatingHandler>();

        // Add services to the container.
        builder.Services.AddControllersWithViews();
        builder.Services.AddSingleton(new ResiliencePipelineBuilder<Result<MetadataBLOBPayloadJSON>>()
            .AddRetry(new()
            {
                ShouldHandle = new PredicateBuilder<Result<MetadataBLOBPayloadJSON>>().HandleResult(result => result.HasError),
                Delay = TimeSpan.FromMilliseconds(1),
                MaxRetryAttempts = 10,
                BackoffType = DelayBackoffType.Constant
            })
            .Build());
        builder.Services.AddSingleton<IFidoMetadataProvider, LocalFilesFidoMetadataProviderForMdsTests>();
        builder.Services.AddSingleton<ITpmManufacturerVerifier, ConformanceTpmManufacturerVerifier>();
        // ---------------------------
        // ---- IN-MEMORY STORAGE ----
        // ---------------------------
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
        // // ---------------------------
        // // ------ MYSQL STORAGE ------
        // // ---------------------------
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
        // // --------------------------
        // // --- POSTGRESQL STORAGE ---
        // // --------------------------
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
        // // ---------------------------
        // // -- MS SQL SERVER STORAGE --
        // // ---------------------------
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
        //     static sqlServer =>
        //     {
        //         sqlServer.ConnectionString = "Data Source=localhost;Initial Catalog=webauthn;User ID=sa;Password=WebAuthn!1337;Pooling=True;Trust Server Certificate=True";
        //     });
        // --------------------------
        // ---- REQUEST PIPELINE ----
        // --------------------------
        var app = builder.Build();
        app.Logger.Log(LogLevel.Critical, "Application started!");
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
