using System;
using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Models;

[SuppressMessage("Design", "CA1000:Do not declare static members on generic types")]
public class Optional<TValue>
{
    private Optional(TValue value)
    {
        Value = value;
        HasValue = true;
    }

    private Optional()
    {
        HasValue = false;
    }

    public TValue? Value { get; }

    [MemberNotNullWhen(true, nameof(Value))]
    public bool HasValue { get; }

    public static Optional<TValue> Empty()
    {
        return new();
    }

    public static Optional<TValue> Payload(TValue value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new(value);
    }
}
