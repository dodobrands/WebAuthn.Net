using System;
using System.Collections.Generic;
using System.Linq;
using WebAuthn.Net.Extensions;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

public class CborByteString : AbstractCborObject, IEquatable<CborByteString>, IEquatable<AbstractCborObject>, IRawValueProvider<byte[]>
{
    private const CborType ActualType = CborType.ByteString;

    public CborByteString()
    {
    }

    public CborByteString(byte[] values)
    {
        Value = values.CreateCopy();
    }

    public CborByteString(IEnumerable<byte> values)
    {
        Value = values.ToArray().CreateCopy();
    }

    public override CborType Type => ActualType;

    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborByteString otherByteString && Equals(otherByteString)));
    }

    public bool Equals(CborByteString? other)
    {
        return other is not null && (ReferenceEquals(this, other) || Value.SequenceEqual(other.Value));
    }

    public byte[] Value { get; } = Array.Empty<byte>();

    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborByteString otherByteString && Equals(otherByteString)));
    }

    public override int GetHashCode()
    {
        var hashCode = (int) ActualType;
        foreach (var value in Value)
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
