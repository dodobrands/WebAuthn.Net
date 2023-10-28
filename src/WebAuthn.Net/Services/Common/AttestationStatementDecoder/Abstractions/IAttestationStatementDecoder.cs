﻿using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Abstractions;

public interface IAttestationStatementDecoder
{
    Result<AbstractAttestationStatement> Decode(CborMap attStmt, AttestationStatementFormat attestationStatementFormat);
}