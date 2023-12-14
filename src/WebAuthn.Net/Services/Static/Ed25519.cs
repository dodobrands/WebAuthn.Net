using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace WebAuthn.Net.Services.Static;

/// <summary>
///     Static utilities for working with Ed25519.
/// </summary>
public static class Ed25519
{
    private const int Ed25519SignBytes = 64;
    private const int Ed25519PublicKeyBytes = 32;

    /// <summary>
    ///     Verifies a digital signature created using a public key in the Ed25519 format.
    /// </summary>
    /// <param name="publicKey">Public key in the Ed25519 format</param>
    /// <param name="data">The data for which the digital signature needs to be verified.</param>
    /// <param name="signature">The digital signature that needs to be verified.</param>
    /// <returns><see langword="true" /> if the digital signature is valid, otherwise - <see langword="false" />.</returns>
    public static unsafe bool Verify(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        if (publicKey.Length != Ed25519PublicKeyBytes || signature.Length != Ed25519SignBytes)
        {
            return false;
        }

        fixed (byte* sig = signature)
        fixed (byte* m = data)
        fixed (byte* pk = publicKey)
        {
            return crypto_sign_ed25519_verify_detached(sig, m, (ulong) data.Length, pk) == 0;
        }
    }

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
