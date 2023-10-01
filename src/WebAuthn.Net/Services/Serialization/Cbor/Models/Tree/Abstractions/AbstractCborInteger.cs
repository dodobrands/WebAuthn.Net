using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

public abstract class AbstractCborInteger : AbstractCborObject, IRawValueProvider<ulong>
{
    public abstract ulong RawValue { get; }

    public abstract bool TryReadAsInt32([NotNullWhen(true)] out int? value);
}
