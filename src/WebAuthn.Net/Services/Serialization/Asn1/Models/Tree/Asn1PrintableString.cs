﻿using System.Formats.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;

public class Asn1PrintableString : AbstractAsn1Element, IValueProvider<string>
{
    public Asn1PrintableString(Asn1Tag tag, string value)
    {
        Tag = tag;
        Value = value;
    }

    public override Asn1Tag Tag { get; }
    public string Value { get; }
}
