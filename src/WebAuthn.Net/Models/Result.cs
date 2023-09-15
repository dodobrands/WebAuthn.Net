using System;
using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Models;

/// <summary>
///     Generic result of executing any operation.
/// </summary>
/// <typeparam name="TOk">The data type returned in case of a successful operation execution.</typeparam>
public class Result<TOk> where TOk : class
{
    /// <summary>
    ///     Constructs a <see cref="Result{TOk}" /> indicating a result that includes a description of the error that occurred during the execution of an operation.
    /// </summary>
    /// <param name="error">Description of the encountered error.</param>
    /// <exception cref="ArgumentNullException">If the parameter <paramref name="error" /> is <see langword="null" />.</exception>
    public Result(string error)
    {
        ArgumentNullException.ThrowIfNull(error);
        HasError = true;
        Error = error;
    }

    /// <summary>
    ///     Constructs a <see cref="Result{TOk}" /> indicating a result that includes the successful outcome of an operation.
    /// </summary>
    /// <param name="ok">Result of a successful operation execution.</param>
    /// <exception cref="ArgumentNullException">If the parameter <paramref name="ok" /> is <see langword="null" />.</exception>
    public Result(TOk ok)
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
}
