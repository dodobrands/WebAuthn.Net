﻿namespace WebAuthn.Net.Configuration.Options;

public class WebAuthnOptions
{
    public AttestationStatementOptions AttestationStatements { get; set; } = new();
    public AttestationTypeOptions AttestationTypes { get; set; } = new();
}
