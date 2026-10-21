using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;

/// <summary>
///     Describes the members of an 'attStmt' map that are not defined by the syntax of its attestation statement format, so that they can be reported with a single log entry.
/// </summary>
/// <remarks>
///     The members are chosen by the client, their number is bounded only by the size of the request, and they are reported before any signature is verified.
///     Therefore the description contains their total number but lists at most <see cref="MaxListedMembers" /> keys, each of them neutralized and truncated,
///     so that the size of the log entry doesn't depend on the number of members.
/// </remarks>
internal static class AttestationStatementMembersOutsideSyntax
{
    /// <summary>
    ///     The maximum number of keys listed in the description. The members after them are only counted.
    /// </summary>
    public const int MaxListedMembers = 8;

    // a text key is truncated to this length (see LogValue.Sanitize)
    private const int MaxKeyLength = 64;

    /// <summary>
    ///     Describes the members of <paramref name="attStmt" /> whose keys are not among <paramref name="syntaxMembers" />.
    /// </summary>
    /// <param name="attStmt">The 'attStmt' map.</param>
    /// <param name="syntaxMembers">The keys of the members defined by the syntax of the attestation statement format.</param>
    /// <param name="count">Output parameter. The number of members outside the syntax.</param>
    /// <param name="description">
    ///     Output parameter. If the method returns <see langword="true" /> - the keys of the first (at most <see cref="MaxListedMembers" />) members outside the syntax, separated by commas:
    ///     a text key in quotes (truncated to 64 characters, with every control character replaced by '?'), a key of any other data type as its CBOR data type in angle brackets.
    ///     If there are more members, the list ends with ", ...". Otherwise - <see langword="null" />.
    /// </param>
    /// <returns><see langword="true" /> if <paramref name="attStmt" /> contains at least one member outside the syntax, otherwise - <see langword="false" />.</returns>
    public static bool TryDescribe(CborMap attStmt, string[] syntaxMembers, out int count, [NotNullWhen(true)] out string? description)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(syntaxMembers);
        var total = 0;
        StringBuilder? listed = null;
        foreach (var key in attStmt.RawValue.Keys)
        {
            if (key is CborTextString syntaxKey && Array.IndexOf(syntaxMembers, syntaxKey.RawValue) >= 0)
            {
                continue;
            }

            total++;
            if (total > MaxListedMembers)
            {
                continue;
            }

            listed ??= new();
            if (total > 1)
            {
                listed.Append(", ");
            }

            // the key is untrusted input: a text string is neutralized and truncated, a key of any other data type is described by its type only
            if (key is CborTextString textKey)
            {
                listed.Append('\'').Append(LogValue.Sanitize(textKey.RawValue, MaxKeyLength)).Append('\'');
            }
            else
            {
                listed.Append('<').Append(key.Type.ToString()).Append('>');
            }
        }

        if (listed is null)
        {
            count = 0;
            description = null;
            return false;
        }

        if (total > MaxListedMembers)
        {
            listed.Append(", ...");
        }

        count = total;
        description = listed.ToString();
        return true;
    }
}
