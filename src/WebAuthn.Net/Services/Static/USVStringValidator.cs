using System;
using System.Runtime.CompilerServices;

namespace WebAuthn.Net.Services.Static;

/// <summary>
/// The USVString type corresponds to <a href="https://infra.spec.whatwg.org/#scalar-value-string">scalar value strings</a>. Depending on the context, these can be treated as sequences of either 16-bit unsigned integer <a href="https://infra.spec.whatwg.org/#code-unit">code units</a> or <a href="https://infra.spec.whatwg.org/#scalar-value">scalar values</a>.
/// </summary>
/// <remarks>
/// <a href="https://webidl.spec.whatwg.org/#idl-USVString">Web IDL. Living Standard — Last Updated 10 September 2023 § 2.13.19. USVString</a>.
/// </remarks>
// ReSharper disable once InconsistentNaming
public static class USVStringValidator
{
    private const char LeadingSurrogateStart = '\uD800';
    private const char LeadingSurrogateEnd = '\uDBFF';
    private const char TrailingSurrogateStart = '\uDC00';
    private const char TrailingSurrogateEnd = '\uDFFF';

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static bool IsValid(ReadOnlySpan<char> input)
    {
        foreach (var ch in input)
        {
            if (IsLeadingSurrogate(ch) || IsTrailingSurrogate(ch))
                return false;
        }

        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    private static bool IsLeadingSurrogate(char ch)
    {
        return ch is >= LeadingSurrogateStart and <= LeadingSurrogateEnd;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    private static bool IsTrailingSurrogate(char ch)
    {
        return ch is >= TrailingSurrogateStart and <= TrailingSurrogateEnd;
    }
}
