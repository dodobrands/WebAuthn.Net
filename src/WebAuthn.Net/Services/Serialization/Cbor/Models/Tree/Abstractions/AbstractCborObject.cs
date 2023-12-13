using System;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Enums;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

/// <summary>
///     Abstract CBOR element.
/// </summary>
public abstract class AbstractCborObject : IEquatable<AbstractCborObject>
{
    /// <summary>
    ///     The type of value in the CBOR object.
    /// </summary>
    public abstract CborType Type { get; }

    /// <inheritdoc />
    public abstract bool Equals(AbstractCborObject? other);

    /// <inheritdoc />
    public abstract override int GetHashCode();

    /// <inheritdoc />
    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is AbstractCborObject cborObject && Equals(cborObject)));
    }

    /// <summary>
    ///     Indicates whether the values of two specified <see cref="AbstractCborObject" /> objects are equal.
    /// </summary>
    /// <param name="left">The first object to compare.</param>
    /// <param name="right">The second object to compare.</param>
    /// <returns>><see langword="true" /> if <paramref name="left" /> and <paramref name="right" /> are equal; otherwise, <see langword="false" />.</returns>
    public static bool operator ==(AbstractCborObject? left, AbstractCborObject? right)
    {
        return Equals(left, right);
    }

    /// <summary>
    ///     Indicates whether the values of two specified <see cref="AbstractCborObject" /> objects are not equal.
    /// </summary>
    /// <param name="left">The first object to compare.</param>
    /// <param name="right">The second object to compare.</param>
    /// <returns><see langword="true" /> if <paramref name="left" /> and <paramref name="right" /> are not equal; otherwise, <see langword="false" />.</returns>
    public static bool operator !=(AbstractCborObject? left, AbstractCborObject? right)
    {
        return !Equals(left, right);
    }
}
