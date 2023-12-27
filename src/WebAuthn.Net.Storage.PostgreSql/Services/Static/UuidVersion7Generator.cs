using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace WebAuthn.Net.Storage.PostgreSql.Services.Static;

/// <summary>
///     Uuidv7 generator that creates an optimal sequence of uuids, stored in PostgreSQL as 'uuid' data type.
/// </summary>
public static class UuidVersion7Generator
{
    /// <summary>
    ///     Generates Uuidv7 for PostgreSQL.
    /// </summary>
    /// <returns><see cref="Guid" /> containing Uuidv7 generated in a way to be optimally stored and used as a primary key in PostgreSQL.</returns>
    public static Guid Generate()
    {
        const ushort bits48To63ResetVersionMask = 0xFFF;
        const ushort bits48To63SetVersionMask = 0x7000;
        const byte bits64To71ResetVersionMask = 0x3F;
        const byte bits64To71SetVersionMask = 0x80;

        // https://github.com/npgsql/npgsql/blob/c36b1bc7e5c6d79bb526e5a89a0a68f150b283cb/src/Npgsql/Internal/Converters/Primitive/GuidUuidConverter.cs#L14-L43
        Span<Guid> guidBuffer = stackalloc Guid[1];
        guidBuffer[0] = Guid.NewGuid();
        var buffer = MemoryMarshal.AsBytes(guidBuffer);
        var temp48To63 = (ushort) ((ushort) (BinaryPrimitives.ReadUInt16LittleEndian(buffer[6..]) & bits48To63ResetVersionMask) | bits48To63SetVersionMask);
        buffer[8] = (byte) ((byte) (buffer[8] & bits64To71ResetVersionMask) | bits64To71SetVersionMask);
        var unixTimeMilliseconds = (ulong) DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        BinaryPrimitives.WriteUInt64BigEndian(buffer, (unixTimeMilliseconds << 16) | temp48To63);
        Span<byte> result = stackalloc byte[16];
        result[0] = buffer[3];
        result[1] = buffer[2];
        result[2] = buffer[1];
        result[3] = buffer[0];
        result[4] = buffer[5];
        result[5] = buffer[4];
        result[6] = buffer[7];
        result[7] = buffer[6];
        result[8] = buffer[8];
        result[9] = buffer[9];
        result[10] = buffer[10];
        result[11] = buffer[11];
        result[12] = buffer[12];
        result[13] = buffer[13];
        result[14] = buffer[14];
        result[15] = buffer[15];
        var guid = Unsafe.As<byte, Guid>(ref result.GetPinnableReference());
        return guid;
    }
}
