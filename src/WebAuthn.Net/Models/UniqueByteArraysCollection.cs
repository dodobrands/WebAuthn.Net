using System;
using System.Collections;
using System.Collections.Generic;

namespace WebAuthn.Net.Models;

public class UniqueByteArraysCollection : IReadOnlyCollection<byte[]>
{
    private readonly List<byte[]> _existingItems = new(128);

    public UniqueByteArraysCollection()
    {
    }

    public UniqueByteArraysCollection(IEnumerable<byte[]> initialItems)
    {
        AddRange(initialItems);
    }

    public IEnumerator<byte[]> GetEnumerator()
    {
        return _existingItems.GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }

    public int Count => _existingItems.Count;

    public void Add(byte[] newItem)
    {
        ArgumentNullException.ThrowIfNull(newItem);
        foreach (var existingItem in _existingItems)
        {
            if (existingItem.Length != newItem.Length)
            {
                continue;
            }

            if (existingItem.AsSpan().SequenceEqual(newItem.AsSpan()))
            {
                return;
            }
        }

        _existingItems.Add(newItem);
    }

    public void AddRange(IEnumerable<byte[]> newItems)
    {
        ArgumentNullException.ThrowIfNull(newItems);
        foreach (var newItem in newItems)
        {
            Add(newItem);
        }
    }

    public byte[][] ToArray()
    {
        return _existingItems.ToArray();
    }
}
