using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace WebAuthn.Net.DSL.Fakes;

public class FakeLogger<T> : ILogger<T>
{
    private readonly List<FakeLogEntry> _entries = new();

    public IReadOnlyList<FakeLogEntry> Entries => _entries;

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull
    {
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
