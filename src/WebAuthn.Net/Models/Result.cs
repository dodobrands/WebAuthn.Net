using System;
using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Models;

public class Result<TOk>
    where TOk : class
{
    public Result(string error)
    {
        ArgumentNullException.ThrowIfNull(error);
        HasError = true;
        Error = error;
    }

    public Result(TOk ok)
    {
        Ok = ok;
    }

    [MemberNotNullWhen(true, nameof(Error))]
    [MemberNotNullWhen(false, nameof(Ok))]
    public bool HasError { get; }

    public TOk? Ok { get; }

    public string? Error { get; }
}
