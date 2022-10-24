using System;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace StaticInstrumentation;

public static class GenericMemoryOperandFactory
{
    public static AssemblerMemoryOperandFactory GetVariableWidthMemoryOperandFactory(int width)
    {
        return width switch
        {
            0 => __,
            1 => __byte_ptr,
            2 => __word_ptr,
            4 => __dword_ptr,
            8 => __qword_ptr,
            16 => __xmmword_ptr,
            32 => __ymmword_ptr,
            _ => throw new NotSupportedException("Unsupported memory operand size.")
        };
    }
}