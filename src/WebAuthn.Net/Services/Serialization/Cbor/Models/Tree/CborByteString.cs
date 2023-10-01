using System;
using System.Linq;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

public class CborByteString : AbstractCborObject, IEquatable<CborByteString>, IEquatable<AbstractCborObject>, IRawValueProvider<byte[]>
{
    private const CborType ActualType = CborType.ByteString;

    public CborByteString()
    {
    }

    public CborByteString(byte[] values)
    {
        RawValue = values;
    }

    public override CborType Type => ActualType;

    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborByteString otherByteString && Equals(otherByteString)));
    }

    public bool Equals(CborByteString? other)
    {
        return other is not null && (ReferenceEquals(this, other) || RawValue.SequenceEqual(other.RawValue));
    }

    public byte[] RawValue { get; } = Array.Empty<byte>();

    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborByteString otherByteString && Equals(otherByteString)));
    }

    public override int GetHashCode()
    {
        var hashCode = (int) ActualType;
        foreach (var value in RawValue)
        {
            hashCode = HashCode.Combine(hashCode, value);
        }

        return hashCode;
    }

    public static bool operator ==(CborByteString? left, CborByteString? right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(CborByteString? left, CborByteString? right)
    {
        return !Equals(left, right);
    }
}
