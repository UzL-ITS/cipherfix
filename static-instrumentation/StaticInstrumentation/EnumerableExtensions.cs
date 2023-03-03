using System;
using System.Collections.Generic;
using System.Linq;
using Iced.Intel;

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

    /// <summary>
    /// Returns the first register from the given enumerable, while trying to avoid the given register.
    /// </summary>
    /// <param name="registers">Register list.</param>
    /// <param name="avoidReg">Register to avoid.</param>
    /// <returns></returns>
    public static Register FirstAvoidingRegister(this IEnumerable<Register> registers, Register avoidReg)
    {
        Register? reg = null;
        foreach(var r in registers)
        {
            if(r != avoidReg)
                return r;

            // Try to find another one
            reg = avoidReg;
        }

        if(reg == null)
            throw new InvalidOperationException("Sequence is empty.");

        return reg.Value;
    }
}