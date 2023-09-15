using System;
using Microsoft.AspNetCore.Http;

namespace WebAuthn.Net.Models.Abstractions;

public interface IWebAuthnContext : IAsyncDisposable
{
    public HttpContext HttpContext { get; }
}
