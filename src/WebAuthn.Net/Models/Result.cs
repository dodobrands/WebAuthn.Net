using System;
using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Models;

/// <summary>
///     Generic result of executing any operation.
/// </summary>
/// <typeparam name="TOk">The data type returned in case of a successful operation execution.</typeparam>
public class Result<TOk> where TOk : class
{
    private Result(string error)
    {
        ArgumentNullException.ThrowIfNull(error);
        HasError = true;
        Error = error;
    }

    private Result(TOk ok)
    {
        ArgumentNullException.ThrowIfNull(ok);
        Ok = ok;
        HasError = false;
    }

    /// <summary>
    ///     Flag indicating the presence of an error.
    ///     If it returns <see langword="false" />, then the <see cref="Ok" /> property contains the result of a successful operation.
    ///     If it returns <see langword="true" />, then the <see cref="Error" /> property contains a description of the encountered error.
    /// </summary>
    [MemberNotNullWhen(true, nameof(Error))]
    [MemberNotNullWhen(false, nameof(Ok))]
    public bool HasError { get; }

    /// <summary>
    ///     Result of a successful operation execution.
    /// </summary>
    public TOk? Ok { get; }

    /// <summary>
    ///     Description of the encountered error.
    /// </summary>
    public string? Error { get; }

#pragma warning disable CA1000

    /// <summary>
    /// Returns a result indicating the successful completion of the operation.
    /// </summary>
    /// <param name="result">The result of a successful operation completion.</param>
    /// <returns>The <see cref="Result{TOk}"/> corresponding to the successful execution of the operation.</returns>
    public static Result<TOk> Success(TOk result)
    {
        return new(result);
    }

    /// <summary>
    /// Returns a result indicating the unsuccessful execution of the operation.
    /// </summary>
    /// <param name="error">The error that occurred during the execution of the operation.</param>
    /// <returns>The <see cref="Result{TOk}"/> corresponding to the unsuccessful execution of the operation.</returns>
    public static Result<TOk> Failed(string error)
    {
        return new(error);
    }

#pragma warning restore CA1000
}
