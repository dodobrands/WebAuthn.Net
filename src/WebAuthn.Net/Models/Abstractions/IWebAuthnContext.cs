using System;
using Microsoft.AspNetCore.Http;

namespace WebAuthn.Net.Models.Abstractions;

/// <summary>
///     The context in which the WebAuthn operation is being processed.
/// </summary>
public interface IWebAuthnContext : IAsyncDisposable
{
    /// <summary>
    ///     The context of the HTTP request in which the WebAuthn operation is being processed.
    /// </summary>
    public HttpContext HttpContext { get; }
}
