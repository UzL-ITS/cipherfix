using System.Collections.Generic;

namespace StaticInstrumentation;

public static class EnumerableExtensions
{
    public static bool TryFirstOrDefault<T>(this IEnumerable<T> source, out T value)
    {
        value = default;
        using var iterator = source.GetEnumerator();

        if(!iterator.MoveNext())
            return false;

        value = iterator.Current;
        return true;
    }
}