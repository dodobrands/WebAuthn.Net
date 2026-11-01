using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace WebAuthn.Net.DSL.Fakes;

public class FakeLogger<T> : ILogger<T>
{
    private readonly List<FakeLogEntry> _entries = new();
    private readonly List<string?> _scopes = new();

    public IReadOnlyList<FakeLogEntry> Entries => _entries;

    // the formatted state of every scope that was begun
    public IReadOnlyList<string?> Scopes => _scopes;

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull
    {
        _scopes.Add(state.ToString());
        return null;
    }

    public bool IsEnabled(LogLevel logLevel)
    {
        return true;
    }

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        ArgumentNullException.ThrowIfNull(formatter);
        _entries.Add(new(logLevel, formatter(state, exception), exception));
    }
}

public sealed record FakeLogEntry(LogLevel Level, string Message, Exception? Exception);
