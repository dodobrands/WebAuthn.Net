namespace WebAuthn.Net.Configuration.Options.AttestationStatements;

public class AndroidKeyAttestationStatementOptions
{
    public bool AcceptKeysOnlyFromTrustedExecutionEnvironment { get; set; } = true;
}
