using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace WebAuthn.Net.Storage.SqlServer.Services.Static;

/// <summary>
///     Uuidv7 generator that creates an optimal sequence of uuids, stored in Microsoft SQL Server as 'uniqueidentifier' data type.
/// </summary>
public static class UuidVersion7Generator
{
    /// <summary>
    ///     Generates Uuidv7 for Microsoft SQL Server.
    /// </summary>
    /// <returns><see cref="Guid" /> containing Uuidv7 generated in a way to be optimally stored and used as a primary key in Microsoft SQL Server.</returns>
    public static Guid Generate()
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
        Span<byte> result = stackalloc byte[16];
        result[0] = buffer[13];
        result[1] = buffer[12];
        result[2] = buffer[11];
        result[3] = buffer[10];
        result[4] = buffer[15];
        result[5] = buffer[14];
        result[6] = buffer[9];
        result[7] = buffer[8];
        result[8] = buffer[7];
        result[9] = buffer[6];
        result[10] = buffer[5];
        result[11] = buffer[4];
        result[12] = buffer[3];
        result[13] = buffer[2];
        result[14] = buffer[1];
        result[15] = buffer[0];
        var guid = Unsafe.As<byte, Guid>(ref result.GetPinnableReference());
        return guid;
    }
}
