namespace WebAuthn.Net.Models;

/// <summary>
/// PublicKeyCredentialCreationOptions. <see cref="https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions"/>
/// </summary>
public class PublicKeyCredentialCreationOptions
{
    // required PublicKeyCredentialRpEntity         rp;
    // required PublicKeyCredentialUserEntity       user;
    //
    // required BufferSource                             challenge;
    // required sequence<PublicKeyCredentialParameters>  pubKeyCredParams;
    //
    // unsigned long                                timeout;
    // sequence<PublicKeyCredentialDescriptor>      excludeCredentials = [];
    // AuthenticatorSelectionCriteria               authenticatorSelection;
    // DOMString                                    attestation = "none";
    // AuthenticationExtensionsClientInputs         extensions;
}
