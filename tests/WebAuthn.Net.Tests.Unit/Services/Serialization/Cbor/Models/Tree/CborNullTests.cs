using NUnit.Framework;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

public class CborNullTests
{
    [Test]
    public void CborNull_ExposesType()
    {
        var cborNull = new CborNull();

        Assert.That(cborNull.Type, Is.EqualTo(CborType.Null));
    }

    [Test]
    public void CborNull_IsEqual_ToAnyOtherCborNull()
    {
        var left = new CborNull();
        var right = new CborNull();
        var typedEquals = left.Equals(right);
        var abstractEquals = left.Equals((AbstractCborObject) right);
        var operatorEquals = left == right;
        var operatorNotEquals = left != right;

        Assert.Multiple(() =>
        {
            Assert.That(left, Is.EqualTo(right));
            Assert.That(typedEquals, Is.True);
            Assert.That(abstractEquals, Is.True);
            Assert.That(operatorEquals, Is.True);
            Assert.That(operatorNotEquals, Is.False);
            Assert.That(left.GetHashCode(), Is.EqualTo(right.GetHashCode()));
        });
    }

    [Test]
    public void CborNull_IsNotEqual_ToOtherCborTypes()
    {
        var cborNull = new CborNull();
        var equalsBoolean = cborNull.Equals(new CborBoolean(false));
        var equalsUnsignedInteger = cborNull.Equals(new CborUnsignedInteger(0));
        var equalsEmptyByteString = cborNull.Equals(new CborByteString());

        Assert.Multiple(() =>
        {
            Assert.That(equalsBoolean, Is.False);
            Assert.That(equalsUnsignedInteger, Is.False);
            Assert.That(equalsEmptyByteString, Is.False);
        });
    }
}
