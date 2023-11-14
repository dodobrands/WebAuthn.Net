namespace WebAuthn.Net.DSL.Fakes;

public class FakeWebAuthnContextMetrics
{
    public int Commits { get; set; }

    public void Reset()
    {
        Commits = 0;
    }
}
