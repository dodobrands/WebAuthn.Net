using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace WebAuthn.Net.Storage.SqlServer.Services.Static;

public static class UuidVersion7Generator
{
    public static byte[] Generate()
    {
        const ushort bits48To63ResetVersionMask = 0xFFF;
        const ushort bits48To63SetVersionMask = 0x7000;
        const byte bits64To71ResetVersionMask = 0x3F;
        const byte bits64To71SetVersionMask = 0x80;

        Span<Guid> buffer = stackalloc Guid[1];
        buffer[0] = Guid.NewGuid();
        var result = MemoryMarshal.AsBytes(buffer);
        var temp48To63 = (ushort) ((ushort) (BinaryPrimitives.ReadUInt16LittleEndian(result[6..]) & bits48To63ResetVersionMask) | bits48To63SetVersionMask);
        result[8] = (byte) ((byte) (result[8] & bits64To71ResetVersionMask) | bits64To71SetVersionMask);
        var unixTimeMilliseconds = (ulong) (DateTime.UtcNow.Ticks / TimeSpan.TicksPerMillisecond);
        BinaryPrimitives.WriteUInt64BigEndian(result, (unixTimeMilliseconds << 16) | temp48To63);
        return result.ToArray();
    }
}
