using System.Runtime.Serialization;

namespace WebAuthn.Net.Models.Protocol.Enums;

/// <summary>
///     <a href="https://www.w3.org/TR/credential-management-1/#mediation-requirements">Requirement</a> for <a href="https://www.w3.org/TR/credential-management-1/#user-mediated">user mediation</a>.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/credential-management-1/#enumdef-credentialmediationrequirement">Credential Management Level 1 - § 2.3.2. Mediation Requirements</a>
/// </remarks>
public enum CredentialMediationRequirement
{
    /// <summary>
    ///     <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialmediationrequirement-silent">Credential Management Level 1. § 2.3.2. Mediation Requirements</a>
    ///     <br />
    ///     User mediation is suppressed for the given operation. If the operation can be performed without user involvement, wonderful.
    ///     If user involvement is necessary, then the operation will return null rather than involving the user.
    /// </summary>
    /// <remarks>
    ///     The intended usage is to support "<a href="https://www.w3.org/TR/credential-management-1/#example-mediation-silent">Keep me signed-into this site</a>" scenarios, where a developer may wish to silently obtain credentials if a user should be automatically signed in, but
    ///     to delay bothering the user with a sign-in prompt until they actively choose to sign-in.
    /// </remarks>
    [EnumMember(Value = "silent")]
    Silent = 0,

    /// <summary>
    ///     <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialmediationrequirement-optional">Credential Management Level 1. § 2.3.2. Mediation Requirements</a>
    ///     <br />
    ///     If credentials can be handed over for a given operation without user mediation, they will be.
    ///     If <a href="https://www.w3.org/TR/credential-management-1/#origin-requires-user-mediation">user mediation</a> is required, then the user agent will involve the user in the decision.
    /// </summary>
    /// <remarks>
    ///     This is the default behavior for <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-get">get()</a>, and is intended to serve a case where a developer has reasonable confidence that a user expects to start a sign-in operation. If a user has
    ///     just clicked "sign-in" for example, then they won’t be surprised or confused to see a <a href="https://www.w3.org/TR/credential-management-1/#credential-chooser">credential chooser</a> if necessary.
    /// </remarks>
    [EnumMember(Value = "optional")]
    Optional = 1,

    /// <summary>
    ///     <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialmediationrequirement-optional">Credential Management Level 1. § 2.3.2. Mediation Requirements</a>
    ///     <br />
    ///     The user agent will not hand over credentials without <a href="https://www.w3.org/TR/credential-management-1/#user-mediated">user mediation</a>, even if the
    ///     <a href="https://www.w3.org/TR/credential-management-1/#origin-prevent-silent-access-flag">prevent silent access flag</a> is unset for an origin.
    /// </summary>
    /// <remarks>
    ///     Note: This requirement is intended to support <a href="https://www.w3.org/TR/credential-management-1/#example-mediation-require">reauthentication</a> or <a href="https://www.w3.org/TR/credential-management-1/#example-mediation-switch">user-switching</a> scenarios.
    ///     Further, the requirement is tied to a specific operation, and does not affect the <a href="https://www.w3.org/TR/credential-management-1/#origin-prevent-silent-access-flag">prevent silent access flag</a> for the origin. To set that flag, developers should call
    ///     <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-preventsilentaccess">preventSilentAccess()</a>.
    /// </remarks>
    [EnumMember(Value = "required")]
    Required = 2
}
