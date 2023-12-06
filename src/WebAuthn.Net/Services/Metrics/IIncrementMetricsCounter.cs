namespace WebAuthn.Net.Services.Metrics;

public interface IIncrementMetricsCounter<T>
{
    void Increment(T counter);
}
