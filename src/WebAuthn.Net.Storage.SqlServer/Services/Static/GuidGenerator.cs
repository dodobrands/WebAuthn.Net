using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace WebAuthn.Net.Storage.SqlServer.Services.Static;

/// <summary>
///     A Guid generator that generates sequential Guids, optimal for use as a primary key in Microsoft SQL Server for a column with the 'uniqueidentifier' data type.
/// </summary>
public static class GuidGenerator
{
    /// <summary>
    ///     Generates a sequential <see cref="Guid" /> for Microsoft SQL Server.
    /// </summary>
    /// <returns>A sequential <see cref="Guid" />, tied to the current time.</returns>
    public static Guid Generate()
    {
        // https://github.com/dotnet/runtime/blob/5535e31a712343a63f5d7d796cd874e563e5ac14/src/libraries/System.Data.Common/src/System/Data/SQLTypes/SQLGuid.cs#L116
        // https://web.archive.org/web/20120628234912/http://blogs.msdn.com/b/sqlprogrammability/archive/2006/11/06/how-are-guids-compared-in-sql-server-2005.aspx
        Span<Guid> guidBuffer = stackalloc Guid[1];
        guidBuffer[0] = Guid.NewGuid();
        var gBuffer = MemoryMarshal.AsBytes(guidBuffer);
        var unixTimeTicks = (ulong) (DateTimeOffset.UtcNow - DateTimeOffset.UnixEpoch).Ticks;
        Span<byte> tBuffer = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(tBuffer, unixTimeTicks);
        Span<byte> result = stackalloc byte[16];
        result[0] = gBuffer[12];
        result[1] = gBuffer[13];
        result[2] = gBuffer[14];
        result[3] = gBuffer[15];
        result[4] = gBuffer[2];
        result[5] = gBuffer[3];
        result[6] = gBuffer[0];
        result[7] = gBuffer[1];
        result[8] = tBuffer[6];
        result[9] = tBuffer[7];
        result[10] = tBuffer[0];
        result[11] = tBuffer[1];
        result[12] = tBuffer[2];
        result[13] = tBuffer[3];
        result[14] = tBuffer[4];
        result[15] = tBuffer[5];
        var guid = Unsafe.As<byte, Guid>(ref result.GetPinnableReference());
        return guid;
    }
}
