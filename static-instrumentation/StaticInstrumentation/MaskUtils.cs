using System;
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
    public static bool UseAesRng = false;
    public static bool UseGf61Rng = false;
    public static bool UseGf63Rng = false;
    public static bool UseXorShiftPlusRng = false;

    public static AssemblerRegisterXMM? FastRngState;
    public static AssemblerRegisterXMM? FastRngKey;
    public static AssemblerRegisterXMM? FastRngHelp;    

    public static void GenerateMask(Assembler assembler, AssemblerRegister64 register)
    {
        if(DebugForceZeroMask)
            assembler.xor(register.GetSubRegister32(), register.GetSubRegister32());
        else if(DebugForceConstantMask)
            assembler.mov(register, 0xc0ffee11c0ffee11);
        else if(UseAesRng)
        {
            if(FastRngState == null || FastRngKey == null)
                throw new Exception("Invalid RNG configuration");

            assembler.vmovq(register, FastRngState.Value);
            assembler.vaesenc(FastRngState.Value, FastRngState.Value, FastRngKey.Value);
        }
        else if(UseGf61Rng)
        {
            if(FastRngState == null || FastRngKey == null || FastRngHelp == null)
                throw new Exception("Invalid RNG configuration");

            assembler.vpclmulqdq(FastRngState.Value, FastRngState.Value, FastRngKey.Value, 0);
            assembler.vpshufd(FastRngHelp.Value, FastRngState.Value, 0x4e);
            assembler.vpsllq(FastRngHelp.Value, FastRngHelp.Value, 1);          
            assembler.vpxor(FastRngState.Value, FastRngState.Value, FastRngHelp.Value); // +1
            assembler.vpsllq(FastRngHelp.Value, FastRngHelp.Value, 1);
            assembler.vpxor(FastRngState.Value, FastRngState.Value, FastRngHelp.Value); // +x  
            assembler.vpsllq(FastRngHelp.Value, FastRngHelp.Value, 1);
            assembler.vpxor(FastRngState.Value, FastRngState.Value, FastRngHelp.Value); // +x^2 
            assembler.vpsllq(FastRngHelp.Value, FastRngHelp.Value, 3);
            assembler.vpxor(FastRngState.Value, FastRngState.Value, FastRngHelp.Value); // +x^5 
            
            assembler.vmovq(register, FastRngState.Value); 
        }
        else if(UseGf63Rng)
        {
            if(FastRngState == null || FastRngKey == null || FastRngHelp == null)
                throw new Exception("Invalid RNG configuration");

            assembler.vpclmulqdq(FastRngState.Value, FastRngState.Value, FastRngKey.Value, 0);
            assembler.vpshufd(FastRngHelp.Value, FastRngState.Value, 0x4e);
            assembler.vpsllq(FastRngHelp.Value, FastRngHelp.Value, 1);          
            assembler.vpxor(FastRngState.Value, FastRngState.Value, FastRngHelp.Value); // +1
            assembler.vpsllq(FastRngHelp.Value, FastRngHelp.Value, 1);
            assembler.vpxor(FastRngState.Value, FastRngState.Value, FastRngHelp.Value); // +x  

            assembler.vmovq(register, FastRngState.Value);
        }
        else if(UseXorShiftPlusRng)
        {
            if(FastRngState == null || FastRngKey == null || FastRngHelp == null)
                throw new Exception("Invalid RNG configuration");

            var s = FastRngState.Value;
            var t = FastRngKey.Value;
            var h = FastRngHelp.Value;

            assembler.vpsllq(h, t, 23); // h <- t << 23
            assembler.vpxor(t, t, h); // t <- t ^ h
            assembler.vpsrlq(h, t, 18); // h <- t >> 18
            assembler.vpxor(t, t, h); // t <- t ^ h
            assembler.vpsrlq(h, s, 5); // h <- s >> 5
            assembler.vpxor(t, t, h); // t <- t ^ h
            assembler.vpxor(t, t, s); // t <- t ^ s

            assembler.vmovdqa(h, s); // s <-> t
            assembler.vmovdqa(s, t);
            assembler.vmovdqa(t, h);

            assembler.vpaddq(h, s, t); // result <- s + t

            assembler.vmovq(register, h);
        }
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

    public static ToyRegister GenerateMask(Assembler assembler, GenericAssemblerVectorRegister register, ToyRegisterAllocator toyRegisterAllocator)
    {
        if(DebugForceZeroMask)
            assembler.vpxor(register, register, register);
        else if(DebugForceConstantMask)
        {
            var toy = toyRegisterAllocator.AllocateToyRegister(preferredWidth: 8);

            assembler.mov(toy.Reg64, 0xc0ffee11c0ffee11);

            // Copy into vector register
            assembler.vmovq(register.RegXMM, toy.Reg64);
            if(register.PreferredWidth == 16)
                assembler.vpinsrq(register.RegXMM, register.RegXMM, toy.Reg64, 1);
            else if(register.PreferredWidth == 32)
                assembler.vpbroadcastq(register.RegYMM, register.RegXMM);
            else
                throw new InvalidOperationException("Unsupported / invalid preferred register width.");

            return toy;
        }
        else if(UseAesRng)
        {
            if(FastRngState == null || FastRngKey == null)
                throw new Exception("Invalid RNG configuration");

            if(register.PreferredWidth == 16)
                assembler.vpbroadcastq(register.RegXMM, FastRngState.Value);
            else if(register.PreferredWidth == 32)
                assembler.vpbroadcastq(register.RegYMM, FastRngState.Value);
            else
                throw new InvalidOperationException("Unsupported / invalid preferred register width.");

            assembler.vaesenc(FastRngState.Value, FastRngState.Value, FastRngKey.Value);
        }
        else if(UseGf61Rng)
        {
            if(FastRngState == null || FastRngKey == null)
                throw new Exception("Invalid RNG configuration");

            assembler.vpclmulqdq(FastRngState.Value, FastRngState.Value, FastRngKey.Value, 0);
            assembler.vpshufd(register.RegXMM, FastRngState.Value, 0x4e);
            assembler.vpsllq(register.RegXMM, register.RegXMM, 1);
            assembler.vpxor(FastRngState.Value, FastRngState.Value, register.RegXMM); // +1
            assembler.vpsllq(register.RegXMM, register.RegXMM, 1);
            assembler.vpxor(FastRngState.Value, FastRngState.Value, register.RegXMM); // +x  
            assembler.vpsllq(register.RegXMM, register.RegXMM, 1);
            assembler.vpxor(FastRngState.Value, FastRngState.Value, register.RegXMM); // +x^2 
            assembler.vpsllq(register.RegXMM, register.RegXMM, 3);
            assembler.vpxor(FastRngState.Value, FastRngState.Value, register.RegXMM); // +x^5

            if(register.PreferredWidth == 16)
                assembler.vpbroadcastq(register.RegXMM, FastRngState.Value);
            else if(register.PreferredWidth == 32)
                assembler.vpbroadcastq(register.RegYMM, FastRngState.Value);
            else
                throw new InvalidOperationException("Unsupported / invalid preferred register width.");
        }
        else if(UseGf63Rng)
        {
            if(FastRngState == null || FastRngKey == null)
                throw new Exception("Invalid RNG configuration");

            assembler.vpclmulqdq(FastRngState.Value, FastRngState.Value, FastRngKey.Value, 0);
            assembler.vpshufd(register.RegXMM, FastRngState.Value, 0x4e);
            assembler.vpsllq(register.RegXMM, register.RegXMM, 1);
            assembler.vpxor(FastRngState.Value, FastRngState.Value, register.RegXMM); // +1
            assembler.vpsllq(register.RegXMM, register.RegXMM, 1);
            assembler.vpxor(FastRngState.Value, FastRngState.Value, register.RegXMM); // +x  

            if(register.PreferredWidth == 16)
                assembler.vpbroadcastq(register.RegXMM, FastRngState.Value);
            else if(register.PreferredWidth == 32)
                assembler.vpbroadcastq(register.RegYMM, FastRngState.Value);
            else
                throw new InvalidOperationException("Unsupported / invalid preferred register width.");
        }
        else if(UseXorShiftPlusRng)
        {
            if(FastRngState == null || FastRngKey == null || FastRngHelp == null)
                throw new Exception("Invalid RNG configuration");

            var s = FastRngState.Value;
            var t = FastRngKey.Value;
            var h = FastRngHelp.Value;

            assembler.vpsllq(h, t, 23); // h <- t << 23
            assembler.vpxor(t, t, h); // t <- t ^ h
            assembler.vpsrlq(h, t, 18); // h <- t >> 18
            assembler.vpxor(t, t, h); // t <- t ^ h
            assembler.vpsrlq(h, s, 5); // h <- s >> 5
            assembler.vpxor(t, t, h); // t <- t ^ h
            assembler.vpxor(t, t, s); // t <- t ^ s

            assembler.vmovdqa(h, s); // s <-> t
            assembler.vmovdqa(s, t);
            assembler.vmovdqa(t, h);

            assembler.vpaddq(h, s, t); // result <- s + t

            if(register.PreferredWidth == 16)
                assembler.vmovdqa(register.RegXMM, h);
            else if(register.PreferredWidth == 32)
                assembler.vpbroadcastq(register.RegYMM, h);
            else
                throw new InvalidOperationException("Unsupported / invalid preferred register width.");
        }
        else
        {
            var toy = toyRegisterAllocator.AllocateToyRegister(preferredWidth: 8);

            assembler.AnonymousLabel();
            assembler.rdrand(toy.Reg64);

            if(UseSecrecyBuffer)
            {
                assembler.jnc(assembler.B);
            }
            else
            {
                assembler.test(toy.Reg8, toy.Reg8);
                assembler.jz(assembler.B);
            }

            // Copy into vector register
            assembler.vmovq(register.RegXMM, toy.Reg64);
            if(register.PreferredWidth == 16)
                assembler.vpinsrq(register.RegXMM, register.RegXMM, toy.Reg64, 1);
            else if(register.PreferredWidth == 32)
                assembler.vpbroadcastq(register.RegYMM, register.RegXMM);
            else
                throw new InvalidOperationException("Unsupported / invalid preferred register width.");

            return toy;
        }

        return null;
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