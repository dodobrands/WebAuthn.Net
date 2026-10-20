using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Threading;

namespace WebAuthn.Net.Services.Static;

/// <summary>
///     Static utilities for working with Ed25519.
/// </summary>
public static class Ed25519
{
    private const int Ed25519SignBytes = 64;
    private const int Ed25519PublicKeyBytes = 32;

    // https://doc.libsodium.org/usage
    // sodium_init() should be called before any other function provided by Sodium. It is safe to call sodium_init() multiple times, or from different threads; it will immediately return 1 without doing anything if the library had already been initialized.
    // After this function returns, all of the other functions provided by Sodium will be thread-safe.
    // It is called exactly once, before the first verification, and the outcome is kept: a native library that cannot be loaded or initialized does not become loadable later on, and the failure must not be rethrown on every verification.
    private static readonly Lazy<bool> Initialized = new(Initialize, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>
    ///     Indicates whether the native libsodium library has been loaded and initialized, so that Ed25519 signatures can be verified.
    ///     The first access loads and initializes the library. When it is <see langword="false" /> (there is no native asset for the current runtime identifier,
    ///     the application was published without runtime assets, or the system library has another ABI), <see cref="Verify" /> treats every signature as invalid.
    /// </summary>
    public static bool IsAvailable => Initialized.Value;

    /// <summary>
    ///     Verifies a digital signature created using a public key in the Ed25519 format.
    /// </summary>
    /// <param name="publicKey">Public key in the Ed25519 format</param>
    /// <param name="data">The data for which the digital signature needs to be verified.</param>
    /// <param name="signature">The digital signature that needs to be verified.</param>
    /// <returns><see langword="true" /> if the digital signature is valid, otherwise - <see langword="false" /> (also when the native libsodium library is unavailable, see <see cref="IsAvailable" />).</returns>
    public static unsafe bool Verify(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != Ed25519PublicKeyBytes || signature.Length != Ed25519SignBytes)
        {
            return false;
        }

        if (!Initialized.Value)
        {
            return false;
        }

        // The library was loaded by sodium_init(), so the P/Invoke below does not normally fail; the native load failures are still handled here so that they never leave the verification as an exception.
        try
        {
            fixed (byte* sig = signature)
            fixed (byte* m = data)
            fixed (byte* pk = publicKey)
            {
                return crypto_sign_ed25519_verify_detached(sig, m, (ulong) data.Length, pk) == 0;
            }
        }
        catch (DllNotFoundException)
        {
            return false;
        }
        catch (EntryPointNotFoundException)
        {
            return false;
        }
        catch (BadImageFormatException)
        {
            return false;
        }
    }

    private static bool Initialize()
    {
        try
        {
            // https://doc.libsodium.org/usage
            // sodium_init() returns 0 on success, -1 on failure, and 1 if the library had already been initialized.
            return sodium_init() >= 0;
        }
        // The native library cannot be loaded (no asset for the RID, a trimmed publish, a system library of another ABI) or does not export the entry point.
        catch (DllNotFoundException)
        {
            return false;
        }
        catch (EntryPointNotFoundException)
        {
            return false;
        }
        catch (BadImageFormatException)
        {
            return false;
        }
    }

    [DllImport("libsodium",
        EntryPoint = "sodium_init",
        ExactSpelling = true,
        CallingConvention = CallingConvention.Cdecl)]
    [SuppressMessage("Security", "CA5392:Use DefaultDllImportSearchPaths attribute for P/Invokes")]
    [SuppressMessage("ReSharper", "IdentifierTypo")]
    private static extern int sodium_init();

    [DllImport("libsodium",
        EntryPoint = "crypto_sign_ed25519_verify_detached",
        ExactSpelling = true,
        CallingConvention = CallingConvention.Cdecl)]
    [SuppressMessage("Security", "CA5392:Use DefaultDllImportSearchPaths attribute for P/Invokes")]
    [SuppressMessage("ReSharper", "IdentifierTypo")]
    private static extern unsafe int crypto_sign_ed25519_verify_detached(
        byte* sig,
        byte* m,
        ulong mlen,
        byte* pk);
}
