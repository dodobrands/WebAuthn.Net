using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.WebUtilities;

namespace WebAuthn.Net.Services.Static;

/// <summary>
///     Static utilities for working with Base64 in urlencoded format.
/// </summary>
public static class Base64Url
{
    /// <summary>
    ///     Encodes the specified bytes into a Base64Urlencoded string.
    /// </summary>
    /// <param name="input">Bytes to be encoded into a Base64Urlencoded string.</param>
    /// <returns>Base64Urlencoded string.</returns>
    public static string Encode(ReadOnlySpan<byte> input)
    {
        return WebEncoders.Base64UrlEncode(input);
    }

    /// <summary>
    ///     Decodes binary data from a base64urlencoded string.
    /// </summary>
    /// <param name="input">Base64Urlencoded string.</param>
    /// <param name="bytes">Output parameter. Contains binary data decoded from a base64urlencoded string if the method returns <see langword="true" />, otherwise - <see langword="null" />.</param>
    /// <returns><see langword="true" /> if it was possible to decode binary data from a base64urlencoded string, otherwise - <see langword="false" />.</returns>
    public static bool TryDecode(ReadOnlySpan<char> input, [NotNullWhen(true)] out byte[]? bytes)
    {
        const int dstBytesStackallocThreshold = 2048;
        const int srcCharsStackallocThreshold = 4096;


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

        if (!TryGetNumBase64PaddingCharsToAddForDecode(input.Length, out var padding))
        {
            bytes = null;
            return false;
        }

        var paddingCharsToAdd = padding.Value;
        var srcBufferSize = checked(input.Length + paddingCharsToAdd);
        var dstBufferSize = FromBase64ComputeResultLength(srcBufferSize);
        char[]? srcArray = null;
        byte[]? dstArray = null;
        try
        {
            var srcBuffer = srcBufferSize <= srcCharsStackallocThreshold
                ? stackalloc char[srcBufferSize]
                : srcArray = ArrayPool<char>.Shared.Rent(srcBufferSize);
            srcBuffer = srcBuffer[..srcBufferSize];

            try
            {
                var i = 0;
                for (; i < input.Length; i++)
                {
                    var ch = input[i];
                    if (!IsValidBase64UrlEncodedCharacter(ch))
                    {
                        bytes = null;
                        return false;
                    }

                    srcBuffer[i] = ch switch
                    {
                        '-' => '+',
                        '_' => '/',
                        _ => ch
                    };
                }

                for (; paddingCharsToAdd > 0; i++, paddingCharsToAdd--)
                {
                    srcBuffer[i] = '=';
                }

                var dstBuffer = dstBufferSize <= dstBytesStackallocThreshold
                    ? stackalloc byte[dstBufferSize]
                    : dstArray = ArrayPool<byte>.Shared.Rent(dstBufferSize);
                dstBuffer = dstBuffer[..dstBufferSize];
                try
                {
                    if (!Convert.TryFromBase64Chars(srcBuffer, dstBuffer, out var dstWritten))
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
                srcBuffer.Clear();
            }
        }
        finally
        {
            if (srcArray is not null)
            {
                ArrayPool<char>.Shared.Return(srcArray, true);
            }

            if (dstArray is not null)
            {
                ArrayPool<byte>.Shared.Return(dstArray, true);
            }
        }
    }

    private static bool IsValidBase64UrlEncodedCharacter(char ch)
    {
        return ch is >= '0' and <= '9' or >= 'A' and <= 'Z' or >= 'a' and <= 'z' or '-' or '_';
    }

    private static bool TryGetNumBase64PaddingCharsToAddForDecode(int inputLength, [NotNullWhen(true)] out int? padding)
    {
        switch (inputLength % 4)
        {
            case 0:
                {
                    padding = 0;
                    return true;
                }
            case 2:
                {
                    padding = 2;
                    return true;
                }
            case 3:
                {
                    padding = 1;
                    return true;
                }
            default:
                {
                    padding = null;
                    return false;
                }
        }
    }

    private static int FromBase64ComputeResultLength(int inputLength)
    {
        return (inputLength / 4 * 3) + 2;
    }
}
