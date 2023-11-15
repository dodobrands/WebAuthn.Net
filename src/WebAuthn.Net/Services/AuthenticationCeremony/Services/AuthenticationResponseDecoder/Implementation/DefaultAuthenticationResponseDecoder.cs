using Microsoft.AspNetCore.WebUtilities;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.AuthenticationCeremony.VerifyAssertion;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.VerifyAssertion;
using WebAuthn.Net.Services.Serialization.Json;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Services.AuthenticationResponseDecoder.Implementation;

public class DefaultAuthenticationResponseDecoder : IAuthenticationResponseDecoder
{
    protected static readonly EnumMemberAttributeMapper<AuthenticatorAttachment> AttachmentMapper = new();
    protected static readonly EnumMemberAttributeMapper<PublicKeyCredentialType> TypeMapper = new();

    public Result<AuthenticationResponse> Decode(AuthenticationResponseJSON authenticationResponse)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (authenticationResponse is null)
        {
            return Result<AuthenticationResponse>.Fail();
        }

        var id = WebEncoders.Base64UrlDecode(authenticationResponse.Id);
        var rawId = WebEncoders.Base64UrlDecode(authenticationResponse.RawId);
        var responseResult = DecodeAuthenticatorAssertionResponse(authenticationResponse.Response);
        if (responseResult.HasError)
        {
            return Result<AuthenticationResponse>.Fail();
        }

        var authenticatorAttachmentResult = DecodeAuthenticatorAttachment(authenticationResponse.AuthenticatorAttachment);
        if (authenticatorAttachmentResult.HasError)
        {
            return Result<AuthenticationResponse>.Fail();
        }

        var typeResult = DecodePublicKeyCredentialType(authenticationResponse.Type);
        if (typeResult.HasError)
        {
            return Result<AuthenticationResponse>.Fail();
        }

        var result = new AuthenticationResponse(
            id,
            rawId,
            responseResult.Ok,
            authenticatorAttachmentResult.Ok,
            authenticationResponse.ClientExtensionResults,
            typeResult.Ok);
        return Result<AuthenticationResponse>.Success(result);
    }

    protected virtual Result<AuthenticatorAssertionResponse> DecodeAuthenticatorAssertionResponse(AuthenticatorAssertionResponseJSON response)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (response is null)
        {
            return Result<AuthenticatorAssertionResponse>.Fail();
        }

        if (string.IsNullOrEmpty(response.ClientDataJson))
        {
            return Result<AuthenticatorAssertionResponse>.Fail();
        }

        var clientDataJson = WebEncoders.Base64UrlDecode(response.ClientDataJson);

        if (string.IsNullOrEmpty(response.AuthenticatorData))
        {
            return Result<AuthenticatorAssertionResponse>.Fail();
        }

        var authenticatorData = WebEncoders.Base64UrlDecode(response.AuthenticatorData);

        if (string.IsNullOrEmpty(response.Signature))
        {
            return Result<AuthenticatorAssertionResponse>.Fail();
        }

        var signature = WebEncoders.Base64UrlDecode(response.Signature);


        byte[]? userHandle = null;
        if (!string.IsNullOrEmpty(response.UserHandle))
        {
            userHandle = WebEncoders.Base64UrlDecode(response.UserHandle);
        }

        byte[]? attestationObject = null;
        if (!string.IsNullOrEmpty(response.AttestationObject))
        {
            attestationObject = WebEncoders.Base64UrlDecode(response.AttestationObject);
        }

        var result = new AuthenticatorAssertionResponse(
            clientDataJson,
            authenticatorData,
            signature,
            userHandle,
            attestationObject);
        return Result<AuthenticatorAssertionResponse>.Success(result);
    }

    protected virtual Result<AuthenticatorAttachment?> DecodeAuthenticatorAttachment(string? authenticatorAttachment)
    {
        if (authenticatorAttachment is null)
        {
            return Result<AuthenticatorAttachment?>.Success(null);
        }

        if (!AttachmentMapper.TryGetEnumFromString(authenticatorAttachment, out var attachment))
        {
            return Result<AuthenticatorAttachment?>.Fail();
        }

        return Result<AuthenticatorAttachment?>.Success(attachment.Value);
    }

    protected virtual Result<PublicKeyCredentialType> DecodePublicKeyCredentialType(string type)
    {
        if (string.IsNullOrEmpty(type))
        {
            return Result<PublicKeyCredentialType>.Fail();
        }

        if (!TypeMapper.TryGetEnumFromString(type, out var publicKeyCredentialType))
        {
            return Result<PublicKeyCredentialType>.Fail();
        }

        return Result<PublicKeyCredentialType>.Success(publicKeyCredentialType.Value);
    }
}
