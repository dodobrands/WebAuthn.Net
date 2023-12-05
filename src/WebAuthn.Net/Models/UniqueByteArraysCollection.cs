using System;
using System.Collections;
using System.Collections.Generic;

namespace WebAuthn.Net.Models;

/// <summary>
///     A collection containing unique arrays of bytes.
/// </summary>
public class UniqueByteArraysCollection : IReadOnlyCollection<byte[]>
{
    private readonly List<byte[]> _existingItems = new(128);

    /// <summary>
    ///     Constructs <see cref="UniqueByteArraysCollection" />.
    /// </summary>
    public UniqueByteArraysCollection()
    {
    }

    /// <summary>
    ///     Constructs <see cref="UniqueByteArraysCollection" />.
    /// </summary>
    /// <param name="initialItems">Initial values. The enumeration, as well as its elements, should not be <see langword="null" />.</param>
    public UniqueByteArraysCollection(IEnumerable<byte[]> initialItems)
    {
        AddRange(initialItems);
    }

    /// <inheritdoc />
    public IEnumerator<byte[]> GetEnumerator()
    {
        return _existingItems.GetEnumerator();
    }

    /// <inheritdoc />
    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }

    /// <inheritdoc />
    public int Count => _existingItems.Count;

    /// <summary>
    ///     Adds an element to the collection. If it is found that an array similar in length and content already exists in the collection - such an array will not be added, and the method will complete without error.
    /// </summary>
    /// <param name="newItem">An array of bytes that needs to be added to the collection. Can't be <see langword="null" />.</param>
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

    /// <summary>
    ///     Adds all arrays of bytes from the specified enumeration to the collection only if arrays similar in length and content were not previously added to it. Otherwise, such arrays will not be added to the collection, but will be skipped and in such a situation the method will
    ///     finish without errors.
    /// </summary>
    /// <param name="newItems">An enumeration containing arrays of bytes that need to be added to the collection. The enumeration, as well as its elements, should not be <see langword="null" />.</param>
    public void AddRange(IEnumerable<byte[]> newItems)
    {
        ArgumentNullException.ThrowIfNull(newItems);
        foreach (var newItem in newItems)
        {
            Add(newItem);
        }
    }

    /// <summary>
    ///     Converts the collection into an array of byte arrays.
    /// </summary>
    /// <returns>An array of byte arrays.</returns>
    public byte[][] ToArray()
    {
        return _existingItems.ToArray();
    }
}
