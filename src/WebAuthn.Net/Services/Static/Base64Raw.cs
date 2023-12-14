using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.Static;

/// <summary>
///     Static utilities for working with regular Base64 (NOT urlencoded).
/// </summary>
public static class Base64Raw
{
    /// <summary>
    ///     Decodes binary data from a base64 string
    /// </summary>
    /// <param name="input">Base64 string.</param>
    /// <param name="bytes">Output parameter. Contains binary data decoded from base64 if the method returns <see langword="true" />, otherwise - <see langword="null" />.</param>
    /// <returns><see langword="true" /> if it was possible to decode binary data from a base64 string, otherwise - <see langword="false" />.</returns>
    public static bool TryDecode(ReadOnlySpan<char> input, [NotNullWhen(true)] out byte[]? bytes)
    {
        const int dstBytesStackallocThreshold = 2048;

        if (input.IsEmpty)
        {
            bytes = Array.Empty<byte>();
            return true;
        }

        if (input.Length % 4 == 1)
        {
            bytes = null;
            return false;
        }

        if (input.Length > int.MaxValue - 2)
        {
            bytes = null;
            return false;
        }

        var dstBufferSize = FromBase64ComputeResultLength(input.Length);
        byte[]? dstArray = null;
        try
        {
            var dstBuffer = dstBufferSize <= dstBytesStackallocThreshold
                ? stackalloc byte[dstBufferSize]
                : dstArray = ArrayPool<byte>.Shared.Rent(dstBufferSize);
            dstBuffer = dstBuffer[..dstBufferSize];
            try
            {
                if (!Convert.TryFromBase64Chars(input, dstBuffer, out var dstWritten))
                {
                    bytes = null;
                    return false;
                }

                bytes = dstBuffer[..dstWritten].ToArray();
                return true;
            }
            finally
            {
                dstBuffer.Clear();
            }
        }
        finally
        {
            if (dstArray is not null)
            {
                ArrayPool<byte>.Shared.Return(dstArray, true);
            }
        }
    }

    private static int FromBase64ComputeResultLength(int inputLength)
    {
        return (inputLength / 4 * 3) + 2;
    }
}
