﻿using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.DSL.Fakes;

public class FakeWebAuthnContext : IWebAuthnContext
{
    public FakeWebAuthnContext(HttpContext? httpContext)
    {
        HttpContext = httpContext!;
    }

    public ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    public HttpContext HttpContext { get; }

    public Task CommitAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}