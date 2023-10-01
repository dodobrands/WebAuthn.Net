namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

public interface IValueProvider<out TValue>
{
    TValue Value { get; }
}
