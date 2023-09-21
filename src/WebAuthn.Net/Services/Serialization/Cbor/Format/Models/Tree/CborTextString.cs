﻿using System;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

public class CborTextString : AbstractCborObject, IEquatable<CborTextString>, IEquatable<AbstractCborObject>, IRawValueProvider<string>
{
    private const CborType ActualType = CborType.TextString;

    public CborTextString(string value)
    {
        Value = value;
    }

    public override CborType Type => ActualType;

    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborTextString otherTextString && Equals(otherTextString)));
    }

    public bool Equals(CborTextString? other)
    {
        return other is not null && (ReferenceEquals(this, other) || Value == other.Value);
    }

    public string Value { get; }

    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborTextString otherTextString && Equals(otherTextString)));
    }

    public override int GetHashCode()
    {
        return HashCode.Combine((int) ActualType, Value);
    }

    public static bool operator ==(CborTextString? left, CborTextString? right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(CborTextString? left, CborTextString? right)
    {
        return !Equals(left, right);
    }
}