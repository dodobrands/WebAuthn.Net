using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using WebAuthn.Net.Serialization.Json;

namespace WebAuthn.Net.Models.Protocol.Enums;

/// <summary>
///     Mediation Requirements
/// </summary>
/// <remarks>
///     <a href="https://w3c.github.io/webappsec-credential-management/#mediation-requirements">Credential Management Level 1 - §2.3.2. Mediation Requirements</a>
/// </remarks>
[JsonConverter(typeof(EnumAsStringConverter<CredentialMediationRequirement>))]
public enum CredentialMediationRequirement
{
    /// <summary>
    ///     User mediation is suppressed for the given operation. If the operation can be performed without user involvement, wonderful. If user involvement is necessary, then the operation will return null rather than involving the user.
    /// </summary>
    /// <remarks>
    ///     The intended usage is to support <a href="https://w3c.github.io/webappsec-credential-management/#example-mediation-silent">"Keep me signed-into this site"</a> scenarios, where a developer may wish to silently obtain credentials if a user should be automatically signed in,
    ///     but to delay bothering the user with a sign-in prompt until they actively choose to sign-in.
    /// </remarks>
    [EnumMember(Value = "silent")]
    Silent = 0,

    /// <summary>
    ///     If credentials can be handed over for a given operation without user mediation, they will be. If <a href="https://w3c.github.io/webappsec-credential-management/#origin-requires-user-mediation">user mediation</a> is required, then the user agent will involve the user in the
    ///     decision.
    /// </summary>
    /// <remarks>
    ///     This is the default behavior for <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get">get()</a>, and is intended to serve a case where a developer has reasonable confidence that a user expects to start a sign-in operation. If a user
    ///     has just clicked "sign-in" for example, then they won’t be surprised or confused to see a <a href="https://w3c.github.io/webappsec-credential-management/#credential-chooser">credential chooser</a> if necessary.
    /// </remarks>
    [EnumMember(Value = "optional")]
    Optional = 1,

    /// <summary>
    ///     <para>
    ///         Discovered credentials are presented to the user in a non-modal dialog along with an indication of the <a href="https://html.spec.whatwg.org/multipage/browsers.html#concept-origin">origin</a> which is requesting credentials. If the user makes a gesture outside of the
    ///         dialog, the dialog closes without resolving or rejecting the <a href="https://webidl.spec.whatwg.org/#idl-promise">Promise</a> returned by the <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get">get()</a> method and without
    ///         causing a user-visible error condition. If the user makes a gesture that selects a credential, that credential is returned to the caller. The <a href="https://w3c.github.io/webappsec-credential-management/#origin-prevent-silent-access-flag">prevent silent access flag</a>
    ///         is treated as being true regardless of its actual value: the <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialmediationrequirement-conditional">conditional</a> behavior always involves
    ///         <a href="https://w3c.github.io/webappsec-credential-management/#user-mediated">user mediation</a> of some sort if applicable credentials are discovered.
    ///     </para>
    ///     <para>
    ///         If no credentials are discovered, the user agent MAY prompt the user to take action in a way that depends on the type of credential (e.g. to insert a device containing credentials). Either way, the get() method MUST NOT resolve immediately with null to avoid revealing
    ///         the lack of applicable credentials to the website.
    ///     </para>
    ///     <para>
    ///         Websites can only pass <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialmediationrequirement-conditional">conditional</a> into the <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get">get()</a> method
    ///         if all of the <a href="https://w3c.github.io/webappsec-credential-management/#credentialrequestoptions-relevant-credential-interface-objects">credential interfaces it refers to</a> have overridden
    ///         <a href="https://w3c.github.io/webappsec-credential-management/#dom-credential-isconditionalmediationavailable">isConditionalMediationAvailable()</a> to return a new <a href="https://webidl.spec.whatwg.org/#idl-promise">Promise</a> that
    ///         <a href="https://webidl.spec.whatwg.org/#resolve">resolves</a> with true.
    ///     </para>
    /// </summary>
    [EnumMember(Value = "conditional")]
    Conditional = 2,

    /// <summary>
    ///     The user agent will not hand over credentials without <a href="https://w3c.github.io/webappsec-credential-management/#user-mediated">user mediation</a>, even if the
    ///     <a href="https://w3c.github.io/webappsec-credential-management/#origin-prevent-silent-access-flag">prevent silent access flag</a> is unset for an origin.
    /// </summary>
    /// <remarks>
    ///     This requirement is intended to support <a href="https://w3c.github.io/webappsec-credential-management/#example-mediation-require">reauthentication</a> or <a href="https://w3c.github.io/webappsec-credential-management/#example-mediation-switch">user-switching</a> scenarios.
    ///     Further, the requirement is tied to a specific operation, and does not affect the <a href="https://w3c.github.io/webappsec-credential-management/#origin-prevent-silent-access-flag">prevent silent access flag</a> for the origin. To set that flag, developers should call
    ///     <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-preventsilentaccess">preventSilentAccess()</a>.
    /// </remarks>
    [EnumMember(Value = "required")]
    Required = 3
}
