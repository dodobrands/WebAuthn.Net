﻿using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Configuration.Builder;

public interface IWebAuthnBuilder<TContext>
    where TContext : class, IWebAuthnContext
{
    IServiceCollection Services { get; }
}