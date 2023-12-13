using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

/// <summary>
///     Abstract container for the integer CBOR element.
/// </summary>
public abstract class AbstractCborInteger : AbstractCborObject
{
    /// <summary>
    ///     Raw value.
    /// </summary>
    public abstract ulong RawValue { get; }

    /// <summary>
    ///     Reads the value as <see cref="int" />.
    /// </summary>
    /// <param name="value">Out parameter. If the method returns <see langword="true" /> - contains an <see cref="int" /> value, otherwise - <see langword="null" />.</param>
    /// <returns>If <see langword="true" />, an <see cref="int" /> number is contained in the output parameter. If <see langword="false" /> is returned, it implies the value exceeds the range of <see cref="int" />, therefore, the output parameter will be <see langword="null" />.</returns>
    public abstract bool TryReadAsInt32([NotNullWhen(true)] out int? value);
}
