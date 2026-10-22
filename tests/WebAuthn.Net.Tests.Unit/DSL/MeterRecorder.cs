using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.Linq;

namespace WebAuthn.Net.DSL;

// Records the measurements of the instruments of a single Meter instance, so that the tests running in parallel don't see each other's measurements.
public sealed class MeterRecorder : IDisposable
{
    private readonly MeterListener _listener = new();
    private readonly List<RecordedMeasurement> _measurements = new();

    public MeterRecorder(Meter meter)
    {
        ArgumentNullException.ThrowIfNull(meter);
        _listener.InstrumentPublished = (instrument, listener) =>
        {
            if (ReferenceEquals(instrument.Meter, meter))
            {
                listener.EnableMeasurementEvents(instrument);
            }
        };
        _listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, _) =>
        {
            var formattedTags = string.Join(
                ",",
                tags.ToArray()
                    .OrderBy(static x => x.Key, StringComparer.Ordinal)
                    .Select(static x => x.Key + "=" + Convert.ToString(x.Value, CultureInfo.InvariantCulture)));
            lock (_measurements)
            {
                _measurements.Add(new(instrument.Name, measurement, formattedTags));
            }
        });
        _listener.Start();
    }

    public IReadOnlyList<RecordedMeasurement> Measurements
    {
        get
        {
            lock (_measurements)
            {
                return _measurements.ToArray();
            }
        }
    }

    public void Dispose()
    {
        _listener.Dispose();
    }
}

// Tags are formatted as "key=value" pairs ordered by the key and separated by commas.
public sealed record RecordedMeasurement(string Instrument, long Value, string Tags);
