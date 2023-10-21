using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;

/// <summary>
///     Authenticator Attachment Hint
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#transaction-confirmation-display-types">FIDO Registry of Predefined Values - §3.5 Transaction Confirmation Display Types</a>
///     </para>
/// </remarks>
[Flags]
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum TransactionConfirmationDisplayType : ushort
{
    /// <summary>
    ///     This flag must be set to indicate that a transaction confirmation display, of any type, is available on this authenticator. Other TRANSACTION_CONFIRMATION_DISPLAY flags may also be set if this flag is set. If the authenticator does not support a transaction confirmation
    ///     display, then the value of TRANSACTION_CONFIRMATION_DISPLAY must be set to 0.
    /// </summary>
    [EnumMember(Value = "any")]
    TRANSACTION_CONFIRMATION_DISPLAY_ANY = 0x0001,

    /// <summary>
    ///     <para>This flag must be set to indicate, that a software-based transaction confirmation display operating in a privileged context is available on this authenticator.</para>
    ///     <para>
    ///         A FIDO client that is capable of providing this capability may set this bit (in conjunction with <see cref="TRANSACTION_CONFIRMATION_DISPLAY_ANY" />) for all authenticators of type ATTACHMENT_HINT_INTERNAL, even if the authoritative metadata for the authenticator does
    ///         not indicate this capability.
    ///     </para>
    ///     <para>This flag is mutually exclusive with <see cref="TRANSACTION_CONFIRMATION_DISPLAY_TEE" /> and <see cref="TRANSACTION_CONFIRMATION_DISPLAY_HARDWARE" />.</para>
    /// </summary>
    /// <remarks>
    ///     Software based transaction confirmation displays might be implemented within the boundaries of the ASM rather than by the authenticator itself [UAFASM].
    /// </remarks>
    [EnumMember(Value = "privileged_software")]
    TRANSACTION_CONFIRMATION_DISPLAY_PRIVILEGED_SOFTWARE = 0x0002,

    /// <summary>
    ///     This flag should be set to indicate that the authenticator implements a transaction confirmation display in a Trusted Execution Environment ([TEE], [TEESecureDisplay]). This flag is mutually exclusive with <see cref="TRANSACTION_CONFIRMATION_DISPLAY_PRIVILEGED_SOFTWARE" />
    ///     and <see cref="TRANSACTION_CONFIRMATION_DISPLAY_HARDWARE" />.
    /// </summary>
    [EnumMember(Value = "tee")]
    TRANSACTION_CONFIRMATION_DISPLAY_TEE = 0x0004,

    /// <summary>
    ///     This flag should be set to indicate that a transaction confirmation display based on hardware assisted capabilities is available on this authenticator. This flag is mutually exclusive with <see cref="TRANSACTION_CONFIRMATION_DISPLAY_PRIVILEGED_SOFTWARE" /> and
    ///     <see cref="TRANSACTION_CONFIRMATION_DISPLAY_TEE" />.
    /// </summary>
    [EnumMember(Value = "hardware")]
    TRANSACTION_CONFIRMATION_DISPLAY_HARDWARE = 0x0008,

    /// <summary>
    ///     This flag should be set to indicate that the transaction confirmation display is provided on a distinct device from the FIDO User Device. This flag can be combined with any other flag.
    /// </summary>
    [EnumMember(Value = "remote")]
    TRANSACTION_CONFIRMATION_DISPLAY_REMOTE = 0x0010
}
