namespace WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

public interface IRawValueProvider<out TValue>
{
    TValue RawValue { get; }
}
