using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Models;

/// <summary>
///     Generic result of executing any operation.
/// </summary>
/// <typeparam name="TOk">The data type returned in case of a successful operation execution.</typeparam>
[SuppressMessage("Design", "CA1000:Do not declare static members on generic types")]
public class Result<TOk>
{
    private Result()
    {
        HasError = true;
    }

    private Result(TOk ok)
    {
        Ok = ok;
        HasError = false;
    }

    /// <summary>
    ///     Flag indicating the presence of an error.
    ///     If it returns <see langword="false" />, then the <see cref="Ok" /> property contains the result of a successful operation.
    /// </summary>
    [MemberNotNullWhen(false, nameof(Ok))]
    public bool HasError { get; }

    /// <summary>
    ///     Result of a successful operation execution.
    /// </summary>
    public TOk? Ok { get; }

    /// <summary>
    ///     Returns a result indicating the successful completion of the operation.
    /// </summary>
    /// <param name="result">The result of a successful operation completion.</param>
    /// <returns>The <see cref="Result{TOk}" /> corresponding to the successful execution of the operation.</returns>
    public static Result<TOk> Success(TOk result)
    {
        return new(result);
    }

    /// <summary>
    ///     Returns a result indicating the unsuccessful execution of the operation.
    /// </summary>
    /// <returns>The <see cref="Result{TOk}" /> corresponding to the unsuccessful execution of the operation.</returns>
    public static Result<TOk> Fail()
    {
        return new();
    }
}
