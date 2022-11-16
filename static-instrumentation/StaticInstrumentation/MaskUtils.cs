using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace StaticInstrumentation;

// ReSharper disable HeuristicUnreachableCode
// ReSharper disable RedundantIfElseBlock
#pragma warning disable CS0162

/// <summary>
/// Helper functions for generating, accessing and updating masks.
/// </summary>
public class MaskUtils
{
    public const int SecrecyBufferOffset = -0x2ffff000;
    public const int MaskBufferOffset = -0x3ffff000;

    public static bool DebugForceZeroMask = false; // Debug flag
    public static bool DebugForceConstantMask = false; // Debug flag

    public static bool UseSecrecyBuffer = false;
    public static bool AvoidSmallWrites = false;

    public static void GenerateMask(Assembler assembler, AssemblerRegister64 register)
    {
        if(DebugForceZeroMask)
            assembler.xor(register.GetSubRegister32(), register.GetSubRegister32());
        else if(DebugForceConstantMask)
            assembler.mov(register, 0xc0ffee11c0ffee11);
        else
        {
            assembler.AnonymousLabel();
            assembler.rdrand(register);

            if(UseSecrecyBuffer)
            {
                assembler.jnc(assembler.B);
            }
            else
            {
                assembler.test(register.GetSubRegister8L(), register.GetSubRegister8L());
                assembler.jz(assembler.B);
            }
        }
    }

    public static void StoreMask(Assembler assembler, AssemblerMemoryOperand dataMemoryOperand, AssemblerRegister64 mask)
    {
        assembler.DebugMarkSkippableSectionBegin();
        assembler.mov(__qword_ptr[dataMemoryOperand + MaskBufferOffset], mask);
        assembler.DebugMarkSkippableSectionEnd();
    }

    public static void StoreMask(Assembler assembler, AssemblerMemoryOperand dataMemoryOperand, AssemblerRegister32 mask)
    {
        assembler.DebugMarkSkippableSectionBegin();
        assembler.mov(__dword_ptr[dataMemoryOperand + MaskBufferOffset], mask);
        assembler.DebugMarkSkippableSectionEnd();
    }

    public static void StoreMask(Assembler assembler, AssemblerMemoryOperand dataMemoryOperand, AssemblerRegister16 mask)
    {
        assembler.DebugMarkSkippableSectionBegin();
        assembler.mov(__word_ptr[dataMemoryOperand + MaskBufferOffset], mask);
        assembler.DebugMarkSkippableSectionEnd();
    }

    public static void StoreMask(Assembler assembler, AssemblerMemoryOperand dataMemoryOperand, AssemblerRegister8 mask)
    {
        assembler.DebugMarkSkippableSectionBegin();
        assembler.mov(__byte_ptr[dataMemoryOperand + MaskBufferOffset], mask);
        assembler.DebugMarkSkippableSectionEnd();
    }

    public static void GenerateAndStoreMask(Assembler assembler, AssemblerMemoryOperand dataMemoryOperand, AssemblerRegister64 mask)
    {
        GenerateMask(assembler, mask);
        StoreMask(assembler, dataMemoryOperand, mask);
        if(UseSecrecyBuffer)
            assembler.and(mask, __qword_ptr[dataMemoryOperand + SecrecyBufferOffset]);
    }

    public static void GenerateAndStoreMask(Assembler assembler, AssemblerMemoryOperand dataMemoryOperand, AssemblerRegister32 mask)
    {
        GenerateMask(assembler, new AssemblerRegister64(mask.Value.GetFullRegister()));
        StoreMask(assembler, dataMemoryOperand, mask);
        if(UseSecrecyBuffer)
            assembler.and(mask, __dword_ptr[dataMemoryOperand + SecrecyBufferOffset]);
    }

    public static void GenerateAndStoreMask(Assembler assembler, AssemblerMemoryOperand dataMemoryOperand, AssemblerRegister16 mask)
    {
        GenerateMask(assembler, new AssemblerRegister64(mask.Value.GetFullRegister()));
        StoreMask(assembler, dataMemoryOperand, mask);
        if(UseSecrecyBuffer)
            assembler.and(mask, __word_ptr[dataMemoryOperand + SecrecyBufferOffset]);
    }

    public static void GenerateAndStoreMask(Assembler assembler, AssemblerMemoryOperand dataMemoryOperand, AssemblerRegister8 mask)
    {
        GenerateMask(assembler, new AssemblerRegister64(mask.Value.GetFullRegister()));
        StoreMask(assembler, dataMemoryOperand, mask);
        if(UseSecrecyBuffer)
            assembler.and(mask, __byte_ptr[dataMemoryOperand + SecrecyBufferOffset]);
    }
}