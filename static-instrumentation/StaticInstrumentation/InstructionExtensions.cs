using System;
using System.IO;
using Iced.Intel;

namespace StaticInstrumentation;

public static class InstructionExtensions
{
    /// <summary>
    /// Adjusts the IP displacement operand of the given instruction to point to the given target address, and returns the adjusted instruction.
    /// The instruction length is never changed.
    /// </summary>
    /// <param name="instruction">Instruction.</param>
    /// <param name="newOperandTargetAddress">New target address.</param>
    /// <returns>The adjusted instruction.</returns>
    public static Instruction WithAdjustedIpDisplacement(this Instruction instruction, ulong newOperandTargetAddress)
    {
        // Sanity checks
        if(!instruction.IsIPRelativeMemoryOperand)
            throw new ArgumentException("The instruction is not IP-relative.", nameof(instruction));

        // Such operands always encode as [RIP/EIP + disp32], so no length change is needed

        // For some reason, we cannot change the displacement, but only the IP-dependent absolute address
        // We ignore kernel-mode addresses, so casting to long is safe
        long displacement = (long)newOperandTargetAddress - ((long)instruction.IP + instruction.Length);
        if(displacement < int.MinValue || displacement > int.MaxValue)
            throw new Exception($"Can not set the displacement to {displacement:x}: Out of range");

        instruction.MemoryDisplacement64 = newOperandTargetAddress;

        return instruction;
    }

    /// <summary>
    /// Adjusts the IP displacement of the given branch instruction to point to the given target address, and returns the adjusted instruction.
    /// The instruction length may change.
    /// </summary>
    /// <param name="instruction">Instruction.</param>
    /// <param name="newOperandTargetAddress">New target address.</param>
    /// <returns>The adjusted instruction.</returns>
    public static Instruction WithAdjustedBranchDisplacement(this Instruction instruction, ulong newOperandTargetAddress)
    {
        // Check whether resulting displacement is in range
        long displacement = (long)newOperandTargetAddress - ((long)instruction.IP + instruction.Length);
        if(displacement < int.MinValue || displacement > int.MaxValue)
            throw new Exception($"Can not set the displacement to {displacement:x}: Out of range");

        // Decide based on instruction type
        var modifiedInstruction = instruction;
        if(instruction.Code == Code.Jrcxz_rel8_64)
        {
            // JRCXZ with 8-bit displacement

            modifiedInstruction.NearBranch64 = newOperandTargetAddress;
        }
        else if(instruction.IsJccShort)
        {
            // Jcc with 8-bit displacement

            // Extend to 32-bit displacement
            var newCode = instruction.Code switch
            {
                Code.Jo_rel8_64 => Code.Jo_rel32_64,
                Code.Jno_rel8_64 => Code.Jno_rel32_64,
                Code.Jb_rel8_64 => Code.Jb_rel32_64,
                Code.Jae_rel8_64 => Code.Jae_rel32_64,
                Code.Je_rel8_64 => Code.Je_rel32_64,
                Code.Jne_rel8_64 => Code.Jne_rel32_64,
                Code.Jbe_rel8_64 => Code.Jbe_rel32_64,
                Code.Ja_rel8_64 => Code.Ja_rel32_64,
                Code.Js_rel8_64 => Code.Js_rel32_64,
                Code.Jns_rel8_64 => Code.Jns_rel32_64,
                Code.Jp_rel8_64 => Code.Jp_rel32_64,
                Code.Jnp_rel8_64 => Code.Jnp_rel32_64,
                Code.Jl_rel8_64 => Code.Jl_rel32_64,
                Code.Jge_rel8_64 => Code.Jge_rel32_64,
                Code.Jle_rel8_64 => Code.Jle_rel32_64,
                Code.Jg_rel8_64 => Code.Jg_rel32_64,
                _ => throw new Exception($"Unknown Jcc instruction: {instruction}")
            };

            modifiedInstruction = Instruction.CreateBranch(newCode, newOperandTargetAddress);
            modifiedInstruction.Length = 2 + 4; // All Jcc rel32 opcodes have the same length
            modifiedInstruction.IP = instruction.IP;
        }
        else if(instruction.IsJccNear)
        {
            // Jcc with 32-bit displacement

            // No operand size extension needed, just apply the new target
            modifiedInstruction.NearBranch64 = newOperandTargetAddress;
        }
        else if(instruction.IsJmpShort)
        {
            // JMP with 8-bit displacement

            // Extend to 32-bit displacement
            modifiedInstruction = Instruction.CreateBranch(Code.Jmp_rel32_64, newOperandTargetAddress);
            modifiedInstruction.Length = 1 + 4;
            modifiedInstruction.IP = instruction.IP;
        }
        else if(instruction.IsJmpNear)
        {
            // JMP with 32-bit displacement

            // No operand size extension needed, just apply the new target
            modifiedInstruction.NearBranch64 = newOperandTargetAddress;
        }
        else if(instruction.IsCallNear)
        {
            // CALL with 32-bit displacement

            // No operand size extension needed, just apply the new target
            modifiedInstruction.NearBranch64 = newOperandTargetAddress;
        }

        return modifiedInstruction;
    }

    public static bool IsMemoryAccess(this Instruction instruction)
    {
        for(int i = 0; i < instruction.OpCount; ++i)
        {
            switch(instruction.GetOpKind(i))
            {
                case OpKind.Memory:
                case OpKind.MemorySegDI:
                case OpKind.MemorySegSI:
                case OpKind.MemorySegEDI:
                case OpKind.MemorySegESI:
                case OpKind.MemorySegRDI:
                case OpKind.MemorySegRSI:
                case OpKind.MemoryESDI:
                case OpKind.MemoryESEDI:
                case OpKind.MemoryESRDI:
                {
                    return instruction.Mnemonic != Mnemonic.Lea;
                }
            }
        }

        return (instruction.MemoryBase != Register.None
                || instruction.MemoryIndex != Register.None
                || instruction.IsIPRelativeMemoryOperand
                || instruction.IsStackInstruction
                || instruction.IsStringInstruction)
               && instruction.Mnemonic != Mnemonic.Lea;
    }

    public static bool IsCmov(this Instruction instruction)
    {
        return instruction.Mnemonic
                is Mnemonic.Cmova or Mnemonic.Cmovae
                or Mnemonic.Cmovb or Mnemonic.Cmovbe
                or Mnemonic.Cmove or Mnemonic.Cmovne
                or Mnemonic.Cmovl or Mnemonic.Cmovle
                or Mnemonic.Cmovg or Mnemonic.Cmovge
                or Mnemonic.Cmovo or Mnemonic.Cmovno
                or Mnemonic.Cmovp or Mnemonic.Cmovnp
                or Mnemonic.Cmovs or Mnemonic.Cmovns
            ;
    }

    private static readonly Assembler _assembler = new(64);

    public static int GetActualLength(this Instruction instruction, ulong rip)
    {
        using var target = new MemoryStream();
        var writer = new StreamCodeWriter(target);

        _assembler.Reset();
        _assembler.AddInstruction(instruction);

        _assembler.Assemble(writer, rip, BlockEncoderOptions.DontFixBranches);

        return (int)target.Length;
    }
}