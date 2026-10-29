using System;
using System.Buffers.Binary;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;

namespace WebAuthn.Net.Services.Serialization.Cbor.Implementation;

public class DefaultCborDeserializerDeclaredLengthTests
{
    // An array or a map declares the number of its items before them, and System.Formats.Cbor only checks that the rest of the input is long enough to hold that many items.
    // These inputs declare 1,048,576 items but fail at the second one, so whatever the deserializer allocates must not depend on the declared number.
    private const int DeclaredItems = 1 << 20;

    // Allocating for the declared number of items takes 8 MB for the array and about 29 MB for the map
    private const long MaxAllocatedBytes = 1 << 20;

    private DefaultCborDeserializer Deserializer { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        Deserializer = new(new FakeLogger<DefaultCborDeserializer>());
    }

    // array(1048576) with the items 0 and undefined (which is rejected), followed by zeros up to the declared length
    [Test]
    public void Deserialize_DoesNotAllocateForDeclaredItems_WhenArrayFailsBeforeThem()
    {
        var input = new byte[5 + DeclaredItems];
        input[0] = 0x9a;
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(1), DeclaredItems);
        input[6] = 0xf7;

        AssertFailsWithoutAllocatingForDeclaredItems(input);
    }

    // map(1048576) with the entry 0: undefined (which is rejected), followed by zeros up to the declared length
    [Test]
    public void Deserialize_DoesNotAllocateForDeclaredItems_WhenMapFailsBeforeThem()
    {
        var input = new byte[5 + (2 * DeclaredItems)];
        input[0] = 0xba;
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(1), DeclaredItems);
        input[6] = 0xf7;

        AssertFailsWithoutAllocatingForDeclaredItems(input);
    }

    private void AssertFailsWithoutAllocatingForDeclaredItems(byte[] input)
    {
        // the first call initializes whatever the deserializer and the logger initialize once
        Deserializer.Deserialize(input);
        var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        var result = Deserializer.Deserialize(input);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(allocated, Is.LessThan(MaxAllocatedBytes));
        });
    }
}
