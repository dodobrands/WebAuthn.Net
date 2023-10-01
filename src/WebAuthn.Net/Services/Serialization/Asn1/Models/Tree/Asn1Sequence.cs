﻿using System.Formats.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;

public class Asn1Sequence : AbstractAsn1Enumerable
{
    public Asn1Sequence(Asn1Tag tag, AbstractAsn1Element[] value) : base(tag, value)
    {
    }
}
