using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace WebAuthn.Net.Storage.MySql.Services.Static;

/// <summary>
///     Uuidv7 generator that creates an optimal sequence of uuids, stored in MySQL as 'binary(16)' data type.
/// </summary>
public static class UuidVersion7Generator
{
    /// <summary>
    ///     Generates Uuidv7 for MySQL.
    /// </summary>
    /// <returns>Array of bytes containing Uuidv7 generated in a way to be optimally stored and used as a primary key in MySQL.</returns>
    public static byte[] Generate()
    {
        const ushort bits48To63ResetVersionMask = 0xFFF;
        const ushort bits48To63SetVersionMask = 0x7000;
        const byte bits64To71ResetVersionMask = 0x3F;
        const byte bits64To71SetVersionMask = 0x80;

        Span<Guid> guidBuffer = stackalloc Guid[1];
        guidBuffer[0] = Guid.NewGuid();
        var buffer = MemoryMarshal.AsBytes(guidBuffer);
        var temp48To63 = (ushort) ((ushort) (BinaryPrimitives.ReadUInt16LittleEndian(buffer[6..]) & bits48To63ResetVersionMask) | bits48To63SetVersionMask);
        buffer[8] = (byte) ((byte) (buffer[8] & bits64To71ResetVersionMask) | bits64To71SetVersionMask);
        var unixTimeMilliseconds = (ulong) DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        BinaryPrimitives.WriteUInt64BigEndian(buffer, (unixTimeMilliseconds << 16) | temp48To63);
        return buffer.ToArray();
    }
}
