using System;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace StaticInstrumentation;

// ReSharper disable HeuristicUnreachableCode
// ReSharper disable RedundantIfElseBlock
#pragma warning disable CS0162

public static class AssemblerExtensions
{
    public static bool DebugInsertMarkersForMaskingCode = false; // Debug flag
    public static bool DebugInsertMarkersForMemtraceEvaluation = false; // Analysis flag

    /// <summary>
    /// Marks a certain section as skippable during debug tracing.
    /// </summary>
    public static void DebugMarkSkippableSectionBegin(this Assembler assembler)
    {
        if(!DebugInsertMarkersForMaskingCode)
            return;

        assembler.mov(r14, r14);
    }

    /// <summary>
    /// Marks a certain section as skippable during debug tracing.
    /// </summary>
    public static void DebugMarkSkippableSectionEnd(this Assembler assembler)
    {
        if(!DebugInsertMarkersForMaskingCode)
            return;

        assembler.mov(r15, r15);
    }

    /// <summary>
    /// Marks a certain section as contiguous during memtrace evaluation.
    /// </summary>
    public static void DebugMarkMemtraceSequenceSectionBegin(this Assembler assembler)
    {
        if(!DebugInsertMarkersForMemtraceEvaluation)
            return;

        assembler.mov(r12, r12);
    }

    /// <summary>
    /// Marks a certain section as to be ignored during memtrace evaluation.
    /// </summary>
    public static void DebugMarkMemtraceIgnoreSectionBegin(this Assembler assembler)
    {
        if(!DebugInsertMarkersForMemtraceEvaluation)
            return;

        assembler.mov(r11, r11);
    }

    /// <summary>
    /// Marks a certain section as contiguous during memtrace evaluation.
    /// </summary>
    public static void DebugMarkMemtraceSectionEnd(this Assembler assembler)
    {
        if(!DebugInsertMarkersForMemtraceEvaluation)
            return;

        assembler.mov(r13, r13);
    }

    public static void mov(this Assembler assembler, GenericAssemblerRegister register, AssemblerMemoryOperand memoryOperand)
    {
        if(register.PreferredWidth == 1)
            assembler.mov(register.Reg8, memoryOperand);
        else if(register.PreferredWidth == 2)
            assembler.mov(register.Reg16, memoryOperand);
        else if(register.PreferredWidth == 4)
            assembler.mov(register.Reg32, memoryOperand);
        else if(register.PreferredWidth == 8)
            assembler.mov(register.Reg64, memoryOperand);
        else
            throw new InvalidOperationException("Unsupported / invalid preferred register width.");
    }

    public static void mov(this Assembler assembler, AssemblerMemoryOperand memoryOperand, GenericAssemblerRegister register)
    {
        if(register.PreferredWidth == 1)
            assembler.mov(memoryOperand, register.Reg8);
        else if(register.PreferredWidth == 2)
            assembler.mov(memoryOperand, register.Reg16);
        else if(register.PreferredWidth == 4)
            assembler.mov(memoryOperand, register.Reg32);
        else if(register.PreferredWidth == 8)
            assembler.mov(memoryOperand, register.Reg64);
        else
            throw new InvalidOperationException("Unsupported / invalid preferred register width.");
    }

    public static void mov(this Assembler assembler, GenericAssemblerRegister register, ulong immediate)
    {
        if(register.PreferredWidth == 1)
            assembler.mov(register.Reg8, (byte)immediate);
        else if(register.PreferredWidth == 2)
            assembler.mov(register.Reg16, (ushort)immediate);
        else if(register.PreferredWidth == 4)
            assembler.mov(register.Reg32, (uint)immediate);
        else if(register.PreferredWidth == 8)
            assembler.mov(register.Reg64, immediate);
        else
            throw new InvalidOperationException("Unsupported / invalid preferred register width.");
    }

    public static void xor(this Assembler assembler, GenericAssemblerRegister register1, GenericAssemblerRegister register2)
    {
        if(register1.PreferredWidth == 1)
            assembler.xor(register1.Reg8, register2.Reg8);
        else if(register1.PreferredWidth == 2)
            assembler.xor(register1.Reg16, register2.Reg16);
        else if(register1.PreferredWidth == 4)
            assembler.xor(register1.Reg32, register2.Reg32);
        else if(register1.PreferredWidth == 8)
            assembler.xor(register1.Reg64, register2.Reg64);
        else
            throw new InvalidOperationException("Unsupported / invalid preferred register width.");
    }

    public static void xor(this Assembler assembler, GenericAssemblerRegister register, AssemblerMemoryOperand memoryOperand)
    {
        if(register.PreferredWidth == 1)
            assembler.xor(register.Reg8, memoryOperand);
        else if(register.PreferredWidth == 2)
            assembler.xor(register.Reg16, memoryOperand);
        else if(register.PreferredWidth == 4)
            assembler.xor(register.Reg32, memoryOperand);
        else if(register.PreferredWidth == 8)
            assembler.xor(register.Reg64, memoryOperand);
        else
            throw new InvalidOperationException("Unsupported / invalid preferred register width.");
    }

    public static void xor(this Assembler assembler, GenericAssemblerRegister register, ulong immediate)
    {
        if(register.PreferredWidth == 1)
            assembler.xor(register.Reg8, (byte)immediate);
        else if(register.PreferredWidth == 2)
            assembler.xor(register.Reg16, (ushort)immediate);
        else if(register.PreferredWidth == 4)
            assembler.xor(register.Reg32, (uint)immediate);
        else if(register.PreferredWidth == 8)
            assembler.xor(register.Reg64, (int)immediate); // ulong is not available and handled elsewhere
        else
            throw new InvalidOperationException("Unsupported / invalid preferred register width.");
    }

    public static void and(this Assembler assembler, GenericAssemblerRegister register, AssemblerMemoryOperand memoryOperand)
    {
        if(register.PreferredWidth == 1)
            assembler.and(register.Reg8, memoryOperand);
        else if(register.PreferredWidth == 2)
            assembler.and(register.Reg16, memoryOperand);
        else if(register.PreferredWidth == 4)
            assembler.and(register.Reg32, memoryOperand);
        else if(register.PreferredWidth == 8)
            assembler.and(register.Reg64, memoryOperand);
        else
            throw new InvalidOperationException("Unsupported / invalid preferred register width.");
    }

    public static void vpxor(this Assembler assembler, GenericAssemblerVectorRegister dst, GenericAssemblerVectorRegister src1, GenericAssemblerVectorRegister src2)
    {
        if(dst.PreferredWidth == 16)
            assembler.vpxor(dst.RegXMM, src1.RegXMM, src2.RegXMM);
        else if(dst.PreferredWidth == 32)
            assembler.vpxor(dst.RegYMM, src1.RegYMM, src2.RegYMM);
        else
            throw new InvalidOperationException("Unsupported / invalid preferred register width.");
    }
}