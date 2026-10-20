using NUnit.Framework;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

public class CborBooleanTests
{
    [TestCase(true)]
    [TestCase(false)]
    public void CborBoolean_ExposesTypeAndRawValue(bool value)
    {
        var cborBoolean = new CborBoolean(value);

        Assert.Multiple(() =>
        {
            Assert.That(cborBoolean.Type, Is.EqualTo(CborType.Boolean));
            Assert.That(cborBoolean.RawValue, Is.EqualTo(value));
        });
    }

    [TestCase(true)]
    [TestCase(false)]
    public void CborBoolean_IsEqual_WhenValuesAreEqual(bool value)
    {
        var left = new CborBoolean(value);
        var right = new CborBoolean(value);
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
    public void CborBoolean_IsNotEqual_WhenValuesDiffer()
    {
        var left = new CborBoolean(true);
        var right = new CborBoolean(false);
        var typedEquals = left.Equals(right);
        var operatorEquals = left == right;
        var operatorNotEquals = left != right;

        Assert.Multiple(() =>
        {
            Assert.That(left, Is.Not.EqualTo(right));
            Assert.That(typedEquals, Is.False);
            Assert.That(operatorEquals, Is.False);
            Assert.That(operatorNotEquals, Is.True);
            Assert.That(left.GetHashCode(), Is.Not.EqualTo(right.GetHashCode()));
        });
    }

    [Test]
    public void CborBoolean_IsNotEqual_ToOtherCborTypes()
    {
        var cborBoolean = new CborBoolean(true);
        var equalsUnsignedInteger = cborBoolean.Equals(new CborUnsignedInteger(1));
        var equalsNull = cborBoolean.Equals(new CborNull());
        var equalsTextString = cborBoolean.Equals(new CborTextString("true"));

        Assert.Multiple(() =>
        {
            Assert.That(equalsUnsignedInteger, Is.False);
            Assert.That(equalsNull, Is.False);
            Assert.That(equalsTextString, Is.False);
        });
    }
}
