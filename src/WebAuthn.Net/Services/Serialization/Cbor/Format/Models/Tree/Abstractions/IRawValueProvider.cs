namespace WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree.Abstractions;

public interface IRawValueProvider<out TValue>
{
    TValue Value { get; }
}
