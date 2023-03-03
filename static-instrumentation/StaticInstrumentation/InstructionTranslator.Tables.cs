using System.Collections.Generic;
using System.Linq;
using Iced.Intel;

// ReSharper disable InconsistentNaming

namespace StaticInstrumentation;

public partial class InstructionTranslator
{
    private Dictionary<Mnemonic, UnaryArithmeticDescriptor> _unaryArithmeticDescriptors = new();
    private Dictionary<Mnemonic, BinaryArithmeticDescriptor> _binaryArithmeticDescriptors = new();
    private Dictionary<Mnemonic, VectorArithmeticDescriptor> _vectorArithmeticDescriptors = new();
    private Dictionary<Mnemonic, ShiftDescriptor> _shiftDescriptors = new();
    private Dictionary<Mnemonic, CmovDescriptor> _cmovDescriptors = new();
    private Dictionary<Mnemonic, SetccDescriptor> _setccDescriptors = new();

    private HashSet<Mnemonic> _vectorArithmeticMnemonics;
    private HashSet<Mnemonic> _setccMnemonics = new();

    private void InitTables()
    {
        _unaryArithmeticDescriptors = new Dictionary<Mnemonic, UnaryArithmeticDescriptor>
        {
            [Mnemonic.Neg] = new()
            {
                Op64R = _assembler.neg,
                Op32R = _assembler.neg,
                Op16R = _assembler.neg,
                Op8R = _assembler.neg,
            },
            [Mnemonic.Not] = new()
            {
                Op64R = _assembler.not,
                Op32R = _assembler.not,
                Op16R = _assembler.not,
                Op8R = _assembler.not,
            }
        };

        _binaryArithmeticDescriptors = new Dictionary<Mnemonic, BinaryArithmeticDescriptor>
        {
            [Mnemonic.Add] = new()
            {
                Op64RI = _assembler.add,
                Op64RR = _assembler.add,
                Op32RI = _assembler.add,
                Op32RR = _assembler.add,
                Op16RI = _assembler.add,
                Op16RR = _assembler.add,
                Op8RI = _assembler.add,
                Op8RR = _assembler.add,
            },
            [Mnemonic.Adc] = new()
            {
                Op64RI = _assembler.adc,
                Op64RR = _assembler.adc,
                Op32RI = _assembler.adc,
                Op32RR = _assembler.adc,
                Op16RI = _assembler.adc,
                Op16RR = _assembler.adc,
                Op8RI = _assembler.adc,
                Op8RR = _assembler.adc,
            },
            [Mnemonic.Sub] = new()
            {
                Op64RI = _assembler.sub,
                Op64RR = _assembler.sub,
                Op32RI = _assembler.sub,
                Op32RR = _assembler.sub,
                Op16RI = _assembler.sub,
                Op16RR = _assembler.sub,
                Op8RI = _assembler.sub,
                Op8RR = _assembler.sub,
            },
            [Mnemonic.Sbb] = new()
            {
                Op64RI = _assembler.sbb,
                Op64RR = _assembler.sbb,
                Op32RI = _assembler.sbb,
                Op32RR = _assembler.sbb,
                Op16RI = _assembler.sbb,
                Op16RR = _assembler.sbb,
                Op8RI = _assembler.sbb,
                Op8RR = _assembler.sbb,
            },
            [Mnemonic.Cmp] = new()
            {
                Op64RI = _assembler.cmp,
                Op64RR = _assembler.cmp,
                Op32RI = _assembler.cmp,
                Op32RR = _assembler.cmp,
                Op16RI = _assembler.cmp,
                Op16RR = _assembler.cmp,
                Op8RI = _assembler.cmp,
                Op8RR = _assembler.cmp,
            },
            [Mnemonic.And] = new()
            {
                Op64RI = _assembler.and,
                Op64RR = _assembler.and,
                Op32RI = _assembler.and,
                Op32RR = _assembler.and,
                Op16RI = _assembler.and,
                Op16RR = _assembler.and,
                Op8RI = _assembler.and,
                Op8RR = _assembler.and,
            },
            [Mnemonic.Test] = new()
            {
                Op64RI = _assembler.test,
                Op64RR = _assembler.test,
                Op32RI = _assembler.test,
                Op32RR = _assembler.test,
                Op16RI = _assembler.test,
                Op16RR = _assembler.test,
                Op8RI = _assembler.test,
                Op8RR = _assembler.test,
            },
            [Mnemonic.Or] = new()
            {
                Op64RI = _assembler.or,
                Op64RR = _assembler.or,
                Op32RI = _assembler.or,
                Op32RR = _assembler.or,
                Op16RI = _assembler.or,
                Op16RR = _assembler.or,
                Op8RI = _assembler.or,
                Op8RR = _assembler.or,
            },
            [Mnemonic.Xor] = new()
            {
                Op64RI = _assembler.xor,
                Op64RR = _assembler.xor,
                Op32RI = _assembler.xor,
                Op32RR = _assembler.xor,
                Op16RI = _assembler.xor,
                Op16RR = _assembler.xor,
                Op8RI = _assembler.xor,
                Op8RR = _assembler.xor,
            }
        };

        _vectorArithmeticDescriptors = new Dictionary<Mnemonic, VectorArithmeticDescriptor>
        {
            [Mnemonic.Paddb] = new() { Op128RR = _assembler.paddb },
            [Mnemonic.Paddw] = new() { Op128RR = _assembler.paddw },
            [Mnemonic.Paddd] = new() { Op128RR = _assembler.paddd },
            [Mnemonic.Paddq] = new() { Op128RR = _assembler.paddq },
            [Mnemonic.Vpaddb] = new() { Op128RRR = _assembler.vpaddb, Op256RRR = _assembler.vpaddb },
            [Mnemonic.Vpaddw] = new() { Op128RRR = _assembler.vpaddw, Op256RRR = _assembler.vpaddw },
            [Mnemonic.Vpaddd] = new() { Op128RRR = _assembler.vpaddd, Op256RRR = _assembler.vpaddd },
            [Mnemonic.Vpaddq] = new() { Op128RRR = _assembler.vpaddq, Op256RRR = _assembler.vpaddq },
            [Mnemonic.Psubb] = new() { Op128RR = _assembler.psubb },
            [Mnemonic.Psubw] = new() { Op128RR = _assembler.psubw },
            [Mnemonic.Psubd] = new() { Op128RR = _assembler.psubd },
            [Mnemonic.Psubq] = new() { Op128RR = _assembler.psubq },
            [Mnemonic.Vpsubb] = new() { Op128RRR = _assembler.vpsubb, Op256RRR = _assembler.vpsubb },
            [Mnemonic.Vpsubw] = new() { Op128RRR = _assembler.vpsubw, Op256RRR = _assembler.vpsubw },
            [Mnemonic.Vpsubd] = new() { Op128RRR = _assembler.vpsubd, Op256RRR = _assembler.vpsubd },
            [Mnemonic.Vpsubq] = new() { Op128RRR = _assembler.vpsubq, Op256RRR = _assembler.vpsubq },
            [Mnemonic.Pand] = new() { Op128RR = _assembler.pand },
            [Mnemonic.Pxor] = new() { Op128RR = _assembler.pxor }
        };
        _vectorArithmeticMnemonics = _vectorArithmeticDescriptors.Keys.ToHashSet();

        _shiftDescriptors = new Dictionary<Mnemonic, ShiftDescriptor>
        {
            [Mnemonic.Shl] = new()
            {
                Op64RI = _assembler.shl,
                Op32RI = _assembler.shl,
                Op16RI = _assembler.shl,
                Op8RI = _assembler.shl,
                Op64RCL = _assembler.shl,
                Op32RCL = _assembler.shl,
                Op16RCL = _assembler.shl,
                Op8RCL = _assembler.shl,
            },
            [Mnemonic.Shr] = new()
            {
                Op64RI = _assembler.shr,
                Op32RI = _assembler.shr,
                Op16RI = _assembler.shr,
                Op8RI = _assembler.shr,
                Op64RCL = _assembler.shr,
                Op32RCL = _assembler.shr,
                Op16RCL = _assembler.shr,
                Op8RCL = _assembler.shr,
            },
            [Mnemonic.Sal] = new()
            {
                Op64RI = _assembler.sal,
                Op32RI = _assembler.sal,
                Op16RI = _assembler.sal,
                Op8RI = _assembler.sal,
                Op64RCL = _assembler.sal,
                Op32RCL = _assembler.sal,
                Op16RCL = _assembler.sal,
                Op8RCL = _assembler.sal,
            },
            [Mnemonic.Sar] = new()
            {
                Op64RI = _assembler.sar,
                Op32RI = _assembler.sar,
                Op16RI = _assembler.sar,
                Op8RI = _assembler.sar,
                Op64RCL = _assembler.sar,
                Op32RCL = _assembler.sar,
                Op16RCL = _assembler.sar,
                Op8RCL = _assembler.sar,
            }
        };

        _cmovDescriptors = new Dictionary<Mnemonic, CmovDescriptor>
        {
            [Mnemonic.Cmove] = new()
            {
                Op64RR = _assembler.cmove,
                Op32RR = _assembler.cmove,
                Op16RR = _assembler.cmove
            },
            [Mnemonic.Cmovne] = new()
            {
                Op64RR = _assembler.cmovne,
                Op32RR = _assembler.cmovne,
                Op16RR = _assembler.cmovne
            },
            [Mnemonic.Cmovb] = new()
            {
                Op64RR = _assembler.cmovb,
                Op32RR = _assembler.cmovb,
                Op16RR = _assembler.cmovb
            },
            [Mnemonic.Cmovbe] = new()
            {
                Op64RR = _assembler.cmovbe,
                Op32RR = _assembler.cmovbe,
                Op16RR = _assembler.cmovbe
            },
            [Mnemonic.Cmova] = new()
            {
                Op64RR = _assembler.cmova,
                Op32RR = _assembler.cmova,
                Op16RR = _assembler.cmova
            },
            [Mnemonic.Cmovae] = new()
            {
                Op64RR = _assembler.cmovae,
                Op32RR = _assembler.cmovae,
                Op16RR = _assembler.cmovae
            },
            [Mnemonic.Cmovl] = new()
            {
                Op64RR = _assembler.cmovl,
                Op32RR = _assembler.cmovl,
                Op16RR = _assembler.cmovl
            },
            [Mnemonic.Cmovle] = new()
            {
                Op64RR = _assembler.cmovle,
                Op32RR = _assembler.cmovle,
                Op16RR = _assembler.cmovle
            },
            [Mnemonic.Cmovg] = new()
            {
                Op64RR = _assembler.cmovg,
                Op32RR = _assembler.cmovg,
                Op16RR = _assembler.cmovg
            },
            [Mnemonic.Cmovge] = new()
            {
                Op64RR = _assembler.cmovge,
                Op32RR = _assembler.cmovge,
                Op16RR = _assembler.cmovge
            },
            [Mnemonic.Cmovs] = new()
            {
                Op64RR = _assembler.cmovs,
                Op32RR = _assembler.cmovs,
                Op16RR = _assembler.cmovs
            },
            [Mnemonic.Cmovns] = new()
            {
                Op64RR = _assembler.cmovns,
                Op32RR = _assembler.cmovns,
                Op16RR = _assembler.cmovns
            }
        };

        _setccDescriptors = new Dictionary<Mnemonic, SetccDescriptor>
        {
            [Mnemonic.Setne] = new() { OpRL8 = _assembler.setne }
        };
        _setccMnemonics = _setccDescriptors.Keys.ToHashSet();
    }

    /// <summary>
    /// Type for generic unary arithmetic instructions.
    /// </summary>
    private class UnaryArithmeticDescriptor
    {
        public delegate void ArithmeticOpR64(AssemblerRegister64 register);

        public delegate void ArithmeticOpR32(AssemblerRegister32 register);

        public delegate void ArithmeticOpR16(AssemblerRegister16 register);

        public delegate void ArithmeticOpR8(AssemblerRegister8 register);

        public ArithmeticOpR64 Op64R { get; init; } = null!;
        public ArithmeticOpR32 Op32R { get; init; } = null!;
        public ArithmeticOpR16 Op16R { get; init; } = null!;
        public ArithmeticOpR8 Op8R { get; init; } = null!;
    }

    /// <summary>
    /// Type for generic binary arithmetic instructions.
    /// </summary>
    private class BinaryArithmeticDescriptor
    {
        public delegate void ArithmeticOpRI64(AssemblerRegister64 register, int immediate);

        public delegate void ArithmeticOpRI32(AssemblerRegister32 register, uint immediate);

        public delegate void ArithmeticOpRI16(AssemblerRegister16 register, ushort immediate);

        public delegate void ArithmeticOpRI8(AssemblerRegister8 register, byte immediate);

        public delegate void ArithmeticOpRR64(AssemblerRegister64 destinationRegister, AssemblerRegister64 sourceRegister);

        public delegate void ArithmeticOpRR32(AssemblerRegister32 destinationRegister, AssemblerRegister32 sourceRegister);

        public delegate void ArithmeticOpRR16(AssemblerRegister16 destinationRegister, AssemblerRegister16 sourceRegister);

        public delegate void ArithmeticOpRR8(AssemblerRegister8 destinationRegister, AssemblerRegister8 sourceRegister);

        public ArithmeticOpRI64 Op64RI { get; init; } = null!;
        public ArithmeticOpRI32 Op32RI { get; init; } = null!;
        public ArithmeticOpRI16 Op16RI { get; init; } = null!;
        public ArithmeticOpRI8 Op8RI { get; init; } = null!;
        public ArithmeticOpRR64 Op64RR { get; init; } = null!;
        public ArithmeticOpRR32 Op32RR { get; init; } = null!;
        public ArithmeticOpRR16 Op16RR { get; init; } = null!;
        public ArithmeticOpRR8 Op8RR { get; init; } = null!;
    }

    /// <summary>
    /// Type for vector arithmetic instructions.
    /// </summary>
    private class VectorArithmeticDescriptor
    {
        public delegate void ArithmeticOpRR128(AssemblerRegisterXMM destinationRegister, AssemblerRegisterXMM sourceRegister);

        public delegate void ArithmeticOpRRR128(AssemblerRegisterXMM destinationRegister, AssemblerRegisterXMM sourceRegister1, AssemblerRegisterXMM sourceRegister2);

        public delegate void ArithmeticOpRRR256(AssemblerRegisterYMM destinationRegister, AssemblerRegisterYMM sourceRegister1, AssemblerRegisterYMM sourceRegister2);

        public ArithmeticOpRR128 Op128RR { get; init; }
        public ArithmeticOpRRR128 Op128RRR { get; init; }
        public ArithmeticOpRRR256 Op256RRR { get; init; }
    }

    private class ShiftDescriptor
    {
        public delegate void ShiftOpRI64(AssemblerRegister64 register, byte immediate);

        public delegate void ShiftOpRI32(AssemblerRegister32 register, byte immediate);

        public delegate void ShiftOpRI16(AssemblerRegister16 register, byte immediate);

        public delegate void ShiftOpRI8(AssemblerRegister8 register, byte immediate);

        public delegate void ShiftOpRCL64(AssemblerRegister64 register, AssemblerRegister8 cl);

        public delegate void ShiftOpRCL32(AssemblerRegister32 register, AssemblerRegister8 cl);

        public delegate void ShiftOpRCL16(AssemblerRegister16 register, AssemblerRegister8 cl);

        public delegate void ShiftOpRCL8(AssemblerRegister8 register, AssemblerRegister8 cl);

        public ShiftOpRI64 Op64RI { get; init; } = null!;
        public ShiftOpRI32 Op32RI { get; init; } = null!;
        public ShiftOpRI16 Op16RI { get; init; } = null!;
        public ShiftOpRI8 Op8RI { get; init; } = null!;
        public ShiftOpRCL64 Op64RCL { get; init; } = null!;
        public ShiftOpRCL32 Op32RCL { get; init; } = null!;
        public ShiftOpRCL16 Op16RCL { get; init; } = null!;
        public ShiftOpRCL8 Op8RCL { get; init; } = null!;
    }

    private class CmovDescriptor
    {
        public delegate void CmovOpRR64(AssemblerRegister64 destinationRegister, AssemblerRegister64 sourceRegister);

        public delegate void CmovOpRR32(AssemblerRegister32 destinationRegister, AssemblerRegister32 sourceRegister);

        public delegate void CmovOpRR16(AssemblerRegister16 destinationRegister, AssemblerRegister16 sourceRegister);

        public CmovOpRR64 Op64RR { get; init; } = null!;
        public CmovOpRR32 Op32RR { get; init; } = null!;
        public CmovOpRR16 Op16RR { get; init; } = null!;
    }

    private class SetccDescriptor
    {
        public delegate void SetccOpRL8(AssemblerRegister8 register);

        public SetccOpRL8 OpRL8 { get; init; } = null!;
    }
}