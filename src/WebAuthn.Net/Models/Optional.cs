using System;
using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Models;

/// <summary>
///     Generic result of an operation describing the optional return value.
/// </summary>
/// <typeparam name="TValue">The type of value returned when executing an operation</typeparam>
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

    /// <summary>
    ///     The value, if it is present.
    /// </summary>
    public TValue? Value { get; }

    /// <summary>
    ///     Flag indicating the presence of a value.
    ///     If it returns <see langword="false" />, then the <see cref="Value" /> property is guaranteed to contain a value not equal to <see langword="null" />.
    /// </summary>
    [MemberNotNullWhen(true, nameof(Value))]
    public bool HasValue { get; }

    /// <summary>
    ///     Returns a container indicating the absence of a return value.
    /// </summary>
    /// <returns>A container indicating the absence of a return value.</returns>
    public static Optional<TValue> Empty()
    {
        return new();
    }

    /// <summary>
    ///     Returns a container denoting the guaranteed presence of a return value, which is definitely not <see langword="null" />.
    /// </summary>
    /// <param name="value">A <typeparamref name="TValue" /> type value not equal to <see langword="null" />.</param>
    /// <returns>A container denoting the guaranteed presence of a return value, which is definitely not <see langword="null" />.</returns>
    public static Optional<TValue> Payload(TValue value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new(value);
    }
}
